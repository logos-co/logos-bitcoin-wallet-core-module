//! Fee rates from every enabled fee source, and the coins too small to spend at them.

use serde::Serialize;

use crate::network::Family;

/// Core's default minimum relay fee, the floor when no source names one.
pub const DEFAULT_MINIMUM: f64 = 1.0;

/// Confirmation targets, in blocks, behind fast, normal and slow.
pub const TARGETS: [u16; 3] = [2, 6, 24];

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SourceEstimate {
    pub source: String,
    /// sat/vB per target in `TARGETS`; `None` where the source had no estimate.
    pub rates: [Option<f64>; 3],
    /// The source's minimum relay fee, sat/vB.
    pub minimum: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FeeRates {
    pub fast: f64,
    pub normal: f64,
    pub slow: f64,
    pub minimum: f64,
    pub sources: Vec<String>,
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
    let at = |i: usize| median(estimates.iter().filter_map(|e| e.rates[i]).collect()).unwrap_or(minimum).max(minimum);
    let (fast, normal, slow) = (at(0), at(1), at(2));
    // A slower target never costs more than a faster one.
    let normal = normal.min(fast);
    let slow = slow.min(normal);
    FeeRates { fast: round(fast), normal: round(normal), slow: round(slow), minimum: round(minimum), sources: estimates.iter().map(|e| e.source.clone()).collect() }
}

fn round(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
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

    fn est(source: &str, rates: [Option<f64>; 3], minimum: Option<f64>) -> SourceEstimate {
        SourceEstimate { source: source.into(), rates, minimum }
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
        assert_eq!(r.sources, vec!["a", "b", "c"]);
        // No estimates anywhere, as on regtest: the minimum everywhere.
        let r = combine(&[est("regtest", [None, None, None], None)]);
        assert_eq!((r.fast, r.normal, r.slow), (1.0, 1.0, 1.0));
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
}
