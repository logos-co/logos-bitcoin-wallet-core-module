//! Fee rates from every enabled fee source, and the coins too small to spend at them.

use serde::Serialize;
use serde_json::Value;

use crate::network::Family;

/// Core's default minimum relay fee, the floor when no source names one.
pub const DEFAULT_MINIMUM: f64 = 1.0;

/// Confirmation targets, in blocks, behind fast, normal and slow.
pub const TARGETS: [u16; 3] = [2, 6, 24];

/// The mempool, in vB from the top, each target's rate must outbid on a fee histogram: half its
/// blocks, leaving the rest to what arrives paying more.
pub const DEPTHS: [u64; 3] = [1_000_000, 3_000_000, 12_000_000];

/// Where a source's rates come from.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Basis {
    /// The node's own estimate: estimatefee, `/fee-estimates` or estimatesmartfee.
    Estimate,
    /// Read off the server's mempool fee histogram, above its relay fee.
    Mempool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SourceEstimate {
    pub source: String,
    /// sat/vB per target in `TARGETS`; `None` where the source had no estimate.
    pub rates: [Option<f64>; 3],
    /// The source's minimum relay fee, sat/vB.
    pub minimum: Option<f64>,
    /// `Mempool` when any of the rates came from the server's mempool.
    pub basis: Basis,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FeeRates {
    pub fast: f64,
    pub normal: f64,
    pub slow: f64,
    pub minimum: f64,
    /// The sources whose estimates these are; a source that stated only its minimum is not one.
    pub sources: Vec<String>,
    /// Every level has an estimate from some source. Otherwise the levels are only the floor.
    pub estimated: bool,
    /// `Mempool` when every source in `sources` read its rates off its mempool.
    pub basis: Basis,
}

pub fn median(mut v: Vec<f64>) -> Option<f64> {
    v.retain(|x| x.is_finite() && *x > 0.0);
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let n = v.len();
    Some(if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 })
}

/// The median of each target across sources, never below the highest minimum any source states.
pub fn combine(estimates: &[SourceEstimate]) -> FeeRates {
    let minimum = estimates.iter().filter_map(|e| e.minimum).filter(|m| m.is_finite() && *m > 0.0).fold(DEFAULT_MINIMUM, f64::max);
    let medians: Vec<Option<f64>> = (0..3).map(|i| median(estimates.iter().filter_map(|e| e.rates[i]).collect())).collect();
    let at = |i: usize| medians[i].unwrap_or(minimum).max(minimum);
    let (fast, normal, slow) = (at(0), at(1), at(2));
    // A slower target never costs more than a faster one.
    let normal = normal.min(fast);
    let slow = slow.min(normal);
    let gave = |e: &SourceEstimate| e.rates.iter().flatten().any(|r| r.is_finite() && *r > 0.0);
    let estimating: Vec<&SourceEstimate> = estimates.iter().filter(|e| gave(e)).collect();
    let mempool = !estimating.is_empty() && estimating.iter().all(|e| e.basis == Basis::Mempool);
    FeeRates {
        fast: round(fast),
        normal: round(normal),
        slow: round(slow),
        minimum: round(minimum),
        sources: estimating.iter().map(|e| e.source.clone()).collect(),
        estimated: medians.iter().all(Option::is_some),
        basis: if mempool { Basis::Mempool } else { Basis::Estimate },
    }
}

fn round(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// An Electrum server's rates: estimatefee's, and where it has none, its fee histogram's.
pub fn from_electrum(source: &str, rates: [Option<f64>; 3], histogram: Option<&Value>, minimum: Option<f64>) -> SourceEstimate {
    let bins = histogram.and_then(parse_histogram);
    let mut e = SourceEstimate { source: source.into(), rates, minimum, basis: Basis::Estimate };
    for (rate, depth) in e.rates.iter_mut().zip(DEPTHS) {
        if rate.is_none() {
            *rate = bins.as_deref().and_then(|b| mempool_rate(b, depth, minimum));
            if rate.is_some() {
                e.basis = Basis::Mempool;
            }
        }
    }
    e
}

/// `mempool.get_fee_histogram`'s `[[sat/vB, vB], ...]`; `None` if any pair is not one.
pub fn parse_histogram(v: &Value) -> Option<Vec<(f64, u64)>> {
    v.as_array()?
        .iter()
        .map(|p| {
            let (rate, vsize) = (p.get(0)?.as_f64()?, p.get(1)?.as_f64()?);
            (rate.is_finite() && rate >= 0.0 && vsize.is_finite() && vsize >= 0.0).then_some((rate, vsize as u64))
        })
        .collect()
}

/// What outbids `depth` vB of the mempool, as Electrum reads a histogram: walking down from the
/// highest rate, the rate where the vsize passes the depth; the floor when all of it fits.
pub fn mempool_rate(bins: &[(f64, u64)], depth: u64, floor: Option<f64>) -> Option<f64> {
    let mut bins = bins.to_vec();
    bins.sort_by(|a, b| b.0.total_cmp(&a.0));
    let mut above = 0u64;
    let at = bins.iter().find(|(_, vsize)| {
        above = above.saturating_add(*vsize);
        above > depth
    });
    let floor = floor.filter(|f| f.is_finite() && *f > 0.0);
    match (at.map(|(rate, _)| *rate), floor) {
        (Some(r), Some(f)) => Some(r.max(f)),
        (Some(r), None) => (r > 0.0).then_some(r),
        (None, f) => f,
    }
}

/// What spending one coin of this family costs at `rate` sat/vB.
pub fn cost_to_spend(rate: f64, family: Family) -> u64 {
    (rate * family.input_vbytes() as f64).ceil() as u64
}

/// A coin worth less than it costs to spend. It stays in the total; coin selection leaves it out.
pub fn too_small(value: u64, rate: f64, family: Family) -> bool {
    value < cost_to_spend(rate, family)
}

/// Electrum's estimates are BTC per kB; -1 means none.
pub fn from_btc_per_kb(v: f64) -> Option<f64> {
    (v.is_finite() && v > 0.0).then(|| v * 100_000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn est(source: &str, rates: [Option<f64>; 3], minimum: Option<f64>) -> SourceEstimate {
        SourceEstimate { source: source.into(), rates, minimum, basis: Basis::Estimate }
    }

    #[test]
    fn medians() {
        assert_eq!(median(vec![]), None);
        assert_eq!(median(vec![3.0]), Some(3.0));
        assert_eq!(median(vec![5.0, 1.0, 3.0]), Some(3.0));
        assert_eq!(median(vec![4.0, 1.0, 3.0, 10.0]), Some(3.5));
        assert_eq!(median(vec![-1.0, f64::NAN, 2.0]), Some(2.0));
    }

    #[test]
    fn rates_are_the_median_and_never_below_the_minimum() {
        let r = combine(&[
            est("a", [Some(20.0), Some(10.0), Some(2.0)], Some(1.0)),
            est("b", [Some(30.0), Some(12.0), Some(0.5)], Some(1.5)),
            est("c", [Some(25.0), None, None], None),
        ]);
        assert_eq!((r.fast, r.normal, r.slow, r.minimum), (25.0, 11.0, 1.5, 1.5));
        assert_eq!((r.sources.clone(), r.estimated), (vec!["a".to_string(), "b".into(), "c".into()], true));
        // No estimates anywhere, as on regtest (Electrum's -1) or from Kyoto's floor: the minimum
        // everywhere, and no estimate.
        let r = combine(&[est("regtest", [None, None, None], None), est("kyoto", [None; 3], Some(1.0))]);
        assert_eq!((r.fast, r.normal, r.slow, r.estimated), (1.0, 1.0, 1.0, false));
        assert!(r.sources.is_empty(), "{r:?}");
        assert!(!combine(&[]).estimated);
        // A level no source estimates is no estimate either.
        assert!(!combine(&[est("a", [Some(5.0), Some(3.0), None], None)]).estimated);
        // A quiet network: every level the same, from a real estimate.
        let r = combine(&[est("a", [Some(1.0), Some(1.0), Some(1.0)], Some(1.0)), est("kyoto", [None; 3], Some(1.0))]);
        assert_eq!((r.fast, r.normal, r.slow, r.estimated, r.sources.clone()), (1.0, 1.0, 1.0, true, vec!["a".to_string()]));
        // A slower target is never dearer than a faster one.
        let r = combine(&[est("a", [Some(5.0), Some(9.0), Some(12.0)], None)]);
        assert_eq!((r.fast, r.normal, r.slow), (5.0, 5.0, 5.0));
    }

    #[test]
    fn coins_too_small_to_spend() {
        // 68 vB for a native segwit input, 58 vB for taproot.
        assert_eq!(cost_to_spend(10.0, Family::Bitcoin), 680);
        assert!(too_small(679, 10.0, Family::Bitcoin));
        assert!(!too_small(680, 10.0, Family::Bitcoin));
        assert_eq!(cost_to_spend(10.0, Family::BitcoinTaproot), 580);
        assert!(!too_small(600, 10.0, Family::BitcoinTaproot));
        assert!(too_small(600, 10.0, Family::Bitcoin));
        assert_eq!(cost_to_spend(1.5, Family::Bitcoin), 102);
        assert_eq!(from_btc_per_kb(0.0001), Some(10.0));
        assert_eq!(from_btc_per_kb(-1.0), None);
    }

    #[test]
    fn relay_fees_in_sat_per_vb() {
        // blockchain.relayfee is BTC/kvB: ElectrumX on testnet4 says 1e-05, Core 31's default 1e-06.
        assert_eq!(from_btc_per_kb(1e-05), Some(1.0));
        assert_eq!(from_btc_per_kb(1e-06).map(round), Some(0.1));
        assert_eq!(from_btc_per_kb(0.0), None);
        assert_eq!(from_btc_per_kb(f64::NAN), None);
    }

    #[test]
    fn histograms_parse_or_are_none() {
        // ElectrumX's tenths, electrs's integer bands (`2^k - 1`, then every band below).
        assert_eq!(parse_histogram(&json!([[1.1, 25751], [1.0, 98398]])), Some(vec![(1.1, 25751), (1.0, 98398)]));
        assert_eq!(parse_histogram(&json!([[31, 95141], [15, 0], [0, 0]])), Some(vec![(31.0, 95141), (15.0, 0), (0.0, 0)]));
        assert_eq!(parse_histogram(&json!([])), Some(vec![]));
        for bad in [json!(null), json!({"code": -32601}), json!([[1.0]]), json!([["1", 10]]), json!([[-1.0, 10]]), json!([[2.0, -5]])] {
            assert_eq!(parse_histogram(&bad), None, "{bad}");
        }
    }

    #[test]
    fn mempool_rates_from_a_histogram() {
        // Empty, or all of it within the depth: the floor, and nothing without one.
        assert_eq!(mempool_rate(&[], DEPTHS[0], Some(1.0)), Some(1.0));
        assert_eq!(mempool_rate(&[], DEPTHS[0], None), None);
        assert_eq!(mempool_rate(&[(5.0, 400_000)], DEPTHS[0], Some(1.0)), Some(1.0));
        assert_eq!(mempool_rate(&[(5.0, 1_000_000)], DEPTHS[0], Some(1.0)), Some(1.0), "exactly a block's worth fits");
        // One bin past the depth: its rate.
        assert_eq!(mempool_rate(&[(5.0, 1_000_001)], DEPTHS[0], Some(1.0)), Some(5.0));
        assert_eq!(mempool_rate(&[(5.0, 1_000_001)], DEPTHS[0], None), Some(5.0));
        // A deep mempool: each depth lands in its own bin, in any order the server sends them.
        let deep = [(1.0, 5_000_000), (50.0, 400_000), (20.0, 700_000), (8.0, 2_500_000), (3.0, 9_000_000)];
        let at: Vec<Option<f64>> = DEPTHS.iter().map(|d| mempool_rate(&deep, *d, Some(1.0))).collect();
        assert_eq!(at, vec![Some(20.0), Some(8.0), Some(3.0)]);
        // Never below the floor; electrs's band under 1 sat/vB is 0.
        assert_eq!(mempool_rate(&[(3.0, 900_000), (0.0, 400_000)], DEPTHS[0], Some(1.5)), Some(1.5));
        assert_eq!(mempool_rate(&[(3.0, 900_000), (0.0, 400_000)], DEPTHS[0], None), None);
        assert_eq!(mempool_rate(&[(9.0, u64::MAX), (1.0, u64::MAX)], DEPTHS[2], None), Some(9.0));
    }

    #[test]
    fn electrum_without_estimates_reads_its_mempool() {
        // stagemole.eu on testnet4: estimatefee -1 everywhere, 124k vB waiting, relay fee 1 sat/vB.
        let h = json!([[1.1, 25751], [1.0, 98398]]);
        let e = from_electrum("stagemole", [None; 3], Some(&h), from_btc_per_kb(1e-05));
        assert_eq!((e.rates, e.basis), ([Some(1.0); 3], Basis::Mempool));
        let r = combine(&[e, est("kyoto", [None; 3], Some(1.0))]);
        assert_eq!((r.fast, r.normal, r.slow, r.estimated), (1.0, 1.0, 1.0, true));
        assert_eq!((r.sources, r.basis), (vec!["stagemole".to_string()], Basis::Mempool));
        // Its own estimates first; the histogram fills only what it lacks.
        let e = from_electrum("a", [Some(12.0), Some(6.0), Some(2.0)], Some(&h), Some(1.0));
        assert_eq!((e.rates, e.basis), ([Some(12.0), Some(6.0), Some(2.0)], Basis::Estimate));
        let deep = json!([[25.0, 1_200_000], [4.0, 3_000_000]]);
        let e = from_electrum("b", [Some(30.0), None, None], Some(&deep), Some(1.0));
        assert_eq!((e.rates, e.basis), ([Some(30.0), Some(4.0), Some(1.0)], Basis::Mempool));
        // No histogram, a refused one, or no floor for a mempool that fits: no estimate, no source.
        for (h, min) in [(None, Some(1.0)), (Some(json!({"code": -32601})), Some(1.0)), (Some(json!([])), None)] {
            let e = from_electrum("c", [None; 3], h.as_ref(), min);
            assert_eq!(e.rates, [None; 3], "{h:?}");
            let r = combine(&[e]);
            assert!(!r.estimated && r.sources.is_empty() && r.basis == Basis::Estimate, "{r:?}");
        }
        // Beside a node's estimate the median mixes both, and the levels are not the mempool's alone.
        let r = combine(&[from_electrum("m", [None; 3], Some(&deep), Some(1.0)), est("n", [Some(20.0), Some(8.0), Some(3.0)], None)]);
        assert_eq!((r.fast, r.normal, r.slow, r.basis), (22.5, 6.0, 2.0, Basis::Estimate));
        assert_eq!(serde_json::to_value(&r).unwrap()["basis"], "estimate");
        assert_eq!(serde_json::to_value(Basis::Mempool).unwrap(), "mempool");
    }
}
