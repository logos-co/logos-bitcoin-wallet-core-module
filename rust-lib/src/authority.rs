//! The chain authority, the only source that moves the wallet's chain: here the most-work valid
//! header chain among the enabled Electrum servers; Kyoto and the local node come behind [`Authority`].

use std::collections::{BTreeMap, BTreeSet};

use bdk_electrum::electrum_client;
use bitcoin::block::Header;
use bitcoin::BlockHash;
use electrum_client::ElectrumApi;
use serde::Serialize;

use crate::checks::ChainView;
use crate::headers::{HeaderChain, HeaderError};
use crate::network::BNetwork;

/// Electrum serves at most this many headers per `blockchain.block.headers`.
pub const HEADERS_PER_CALL: u32 = 2016;
/// Calls per source per refresh; a first sync continues on the next refresh.
const MAX_CALLS_PER_REFRESH: u32 = 25;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub kind: &'static str,
    pub height: Option<u32>,
    pub hash: Option<String>,
    pub tip_age_secs: Option<u64>,
    /// Sources whose tip is on the authority's chain.
    pub peers: u32,
}

/// What one refresh changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Change {
    pub tip_moved: bool,
    /// The lowest height whose header changed, for storing and for BDK's chain.
    pub changed_from: Option<u32>,
    pub reorg_depth: u32,
    /// Sources that served invalid headers, or a chain without the checkpoint.
    pub suspects: Vec<(String, String)>,
    /// Sources that couldn't be asked.
    pub failures: Vec<(String, String)>,
    pub agreeing: Vec<String>,
}

/// One source the authority may ask for headers.
pub trait HeaderSource {
    fn id(&self) -> &str;
    fn tip(&self) -> Result<(u32, Header), String>;
    /// Up to `count` headers from `start`.
    fn headers(&self, start: u32, count: u32) -> Result<Vec<Header>, String>;
}

/// An Electrum server as a header source.
pub struct ElectrumHeaders<'a, E> {
    pub id: &'a str,
    pub client: &'a E,
}

impl<E: ElectrumApi> HeaderSource for ElectrumHeaders<'_, E> {
    fn id(&self) -> &str {
        self.id
    }
    fn tip(&self) -> Result<(u32, Header), String> {
        let n = self.client.block_headers_subscribe().map_err(|e| e.to_string())?;
        Ok((n.height as u32, n.header))
    }
    fn headers(&self, start: u32, count: u32) -> Result<Vec<Header>, String> {
        Ok(self.client.block_headers(start as usize, count as usize).map_err(|e| e.to_string())?.headers)
    }
}

pub trait Authority: ChainView + Send {
    fn kind(&self) -> &'static str;
    /// Asks the sources for their chains and keeps the most-work valid one.
    fn refresh(&mut self, sources: &[&dyn HeaderSource], now: u32) -> Change;
    /// Proves heights below the checkpoint by linking a source's headers up to a known hash.
    fn prove_below(&mut self, heights: &[u32], source: &dyn HeaderSource) -> Result<Vec<(u32, BlockHash)>, String>;
    fn summary(&self, now: u64) -> Summary;
    fn chain(&self) -> &HeaderChain;
}

/// Blocks a reorg replaced, remembered so a server that lags it isn't taken for a liar.
const REPLACED_KEPT: usize = 512;

pub struct ServerAuthority {
    chain: HeaderChain,
    old: BTreeMap<u32, BlockHash>,
    progressed: bool,
    agreeing: BTreeSet<String>,
    replaced: std::collections::VecDeque<(u32, BlockHash)>,
}

impl ServerAuthority {
    pub fn new(net: BNetwork) -> Self {
        Self::on(HeaderChain::new(net))
    }

    pub fn on(chain: HeaderChain) -> Self {
        Self { chain, old: BTreeMap::new(), progressed: false, agreeing: BTreeSet::new(), replaced: Default::default() }
    }

    /// From stored headers and proofs; a stored chain counts as progress, and its age shows.
    pub fn restore(net: BNetwork, headers: Vec<(u32, Header)>, old: Vec<(u32, BlockHash)>, now: u32) -> Self {
        let chain = HeaderChain::restore(net, headers, now);
        let progressed = chain.tip_height() > chain.base();
        Self { chain, old: old.into_iter().collect(), progressed, agreeing: BTreeSet::new(), replaced: Default::default() }
    }

    /// The highest height where `src` and the chain agree, searching down from `from`.
    fn fork_point(&self, src: &dyn HeaderSource, from: u32) -> Result<Option<u32>, String> {
        let base = self.chain.base();
        let mut top = from.min(self.chain.tip_height());
        loop {
            let start = top.saturating_sub(HEADERS_PER_CALL - 1).max(base);
            let theirs = src.headers(start, top - start + 1)?;
            for (i, h) in theirs.iter().enumerate().rev() {
                let height = start + i as u32;
                if self.chain.hash_at(height) == Some(h.block_hash()) {
                    return Ok(Some(height));
                }
            }
            if start == base {
                return Ok(None);
            }
            top = start - 1;
        }
    }

    /// Fetches and tries `src`'s chain; returns its tip for the agreement count.
    fn refresh_one(&mut self, src: &dyn HeaderSource, now: u32, change: &mut Change) -> Result<(u32, BlockHash), String> {
        let (their_tip, their_header) = src.tip()?;
        let tip = (their_tip, their_header.block_hash());
        if their_tip < self.chain.base() {
            return Err(format!("its tip {their_tip} is below the checkpoint"));
        }
        if self.chain.hash_at(their_tip) == Some(tip.1) {
            return Ok(tip);
        }
        let Some(fork) = self.fork_point(src, their_tip)? else {
            change.suspects.push((src.id().into(), "its chain does not contain the checkpoint".into()));
            return Ok(tip);
        };
        let mut start = fork + 1;
        let mut branch: Vec<Header> = vec![];
        let mut calls = 0;
        while start <= their_tip && calls < MAX_CALLS_PER_REFRESH {
            let got = src.headers(start, (their_tip - start + 1).min(HEADERS_PER_CALL))?;
            if got.is_empty() {
                break;
            }
            start += got.len() as u32;
            branch.extend(got);
            calls += 1;
        }
        let r = self.chain.try_extend(fork, &branch, now);
        if let Some(e) = &r.error {
            // A header that fails the checks is a lie, not a lag; one from the future may be a clock.
            if !matches!(e, HeaderError::TimeTooNew(_)) {
                change.suspects.push((src.id().into(), e.to_string()));
            }
        }
        if r.adopted {
            for x in r.replaced {
                if self.replaced.len() == REPLACED_KEPT {
                    self.replaced.pop_front();
                }
                self.replaced.push_back(x);
            }
            change.reorg_depth = change.reorg_depth.max(r.reorg_depth);
            change.changed_from = match (change.changed_from, r.changed_from) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        Ok(tip)
    }
}

impl ChainView for ServerAuthority {
    fn tip_height(&self) -> Option<u32> {
        self.progressed.then(|| self.chain.tip_height())
    }
    fn base_height(&self) -> u32 {
        self.chain.base()
    }
    fn hash_at(&self, height: u32) -> Option<BlockHash> {
        if height >= self.chain.base() {
            self.chain.hash_at(height)
        } else if height == 0 {
            // BDK's chain always starts at genesis, which every chain shares.
            Some(bitcoin::constants::genesis_block(self.chain.network().bitcoin()).block_hash())
        } else {
            self.old.get(&height).copied()
        }
    }
    fn header_at(&self, height: u32) -> Option<Header> {
        self.chain.header_at(height).copied()
    }
    fn replaced(&self, height: u32, hash: BlockHash) -> bool {
        self.replaced.contains(&(height, hash))
    }
}

impl Authority for ServerAuthority {
    fn kind(&self) -> &'static str {
        "electrum_headers"
    }

    fn refresh(&mut self, sources: &[&dyn HeaderSource], now: u32) -> Change {
        let mut change = Change::default();
        let before = self.chain.tip_hash();
        let mut tips = vec![];
        for src in sources {
            match self.refresh_one(*src, now, &mut change) {
                Ok(tip) => {
                    self.progressed = true;
                    tips.push((src.id().to_string(), tip));
                }
                Err(e) => change.failures.push((src.id().into(), e)),
            }
        }
        // Agreement against the chain kept after every source had its say.
        self.agreeing = tips
            .into_iter()
            .filter(|(id, (h, hash))| self.chain.hash_at(*h) == Some(*hash) && !change.suspects.iter().any(|(s, _)| s == id))
            .map(|(id, _)| id)
            .collect();
        change.tip_moved = self.chain.tip_hash() != before;
        change.agreeing = self.agreeing.iter().cloned().collect();
        change
    }

    fn prove_below(&mut self, heights: &[u32], src: &dyn HeaderSource) -> Result<Vec<(u32, BlockHash)>, String> {
        let base = self.chain.base();
        let mut wanted: Vec<u32> = heights.iter().copied().filter(|h| *h < base && !self.old.contains_key(h)).collect();
        wanted.sort_unstable();
        wanted.dedup();
        let mut proved = vec![];
        // Highest first, each linking up to the nearest known hash above it.
        for h in wanted.into_iter().rev() {
            let (above, known) = match self.old.range(h + 1..).next() {
                Some((k, v)) => (*k, *v),
                None => (base, self.chain.hash_at(base).expect("the checkpoint")),
            };
            let (mut top, mut expect) = (above, known);
            loop {
                let start = top.saturating_sub(HEADERS_PER_CALL - 1).max(h);
                let got = src.headers(start, top - start + 1)?;
                if got.len() as u32 != top - start + 1 {
                    return Err(format!("headers {start}..={top} came back short"));
                }
                for (i, hd) in got.iter().enumerate().rev() {
                    if hd.block_hash() != expect {
                        return Err(format!("header {} does not link up to the checkpoint", start + i as u32));
                    }
                    expect = hd.prev_blockhash;
                }
                if start == h {
                    let hash = got[0].block_hash();
                    self.old.insert(h, hash);
                    proved.push((h, hash));
                    break;
                }
                top = start - 1;
            }
        }
        Ok(proved)
    }

    fn summary(&self, now: u64) -> Summary {
        Summary {
            kind: self.kind(),
            height: self.tip_height(),
            hash: self.progressed.then(|| self.chain.tip_hash().to_string()),
            tip_age_secs: self.progressed.then(|| now.saturating_sub(u64::from(self.chain.tip().time))),
            peers: self.agreeing.len() as u32,
        }
    }

    fn chain(&self) -> &HeaderChain {
        &self.chain
    }
}

/// BDK's heights down to the first that agrees, restated, plus `wanted` and the tip; `None` while
/// BDK holds a block above the authority's tip, which only a longer authority chain can replace.
pub fn chain_update(view: &dyn ChainView, bdk: &[(u32, BlockHash)], wanted: &BTreeSet<u32>) -> Option<Vec<(u32, BlockHash)>> {
    let tip = view.tip_height()?;
    let mut heights: BTreeMap<u32, BlockHash> = BTreeMap::new();
    for (h, hash) in bdk.iter().rev() {
        if *h > tip {
            return None;
        }
        let ours = view.hash_at(*h)?;
        heights.insert(*h, ours);
        if ours == *hash {
            break;
        }
    }
    for h in wanted.iter().filter(|h| **h <= tip) {
        if let Some(hash) = view.hash_at(*h) {
            heights.insert(*h, hash);
        }
    }
    heights.insert(tip, view.hash_at(tip)?);
    Some(heights.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::tests::regtest_branch;
    use bitcoin::hashes::Hash;

    const NOW: u32 = 2_000_000_000;

    /// A source serving a fixed chain from genesis.
    struct Fake {
        id: String,
        chain: Vec<Header>,
    }

    impl HeaderSource for Fake {
        fn id(&self) -> &str {
            &self.id
        }
        fn tip(&self) -> Result<(u32, Header), String> {
            Ok((self.chain.len() as u32 - 1, *self.chain.last().unwrap()))
        }
        fn headers(&self, start: u32, count: u32) -> Result<Vec<Header>, String> {
            Ok(self.chain.iter().skip(start as usize).take(count as usize).copied().collect())
        }
    }

    fn fake(id: &str, chain: Vec<Header>) -> Fake {
        Fake { id: id.into(), chain }
    }

    fn genesis() -> Header {
        BNetwork::Regtest.checkpoint().header
    }

    fn chain_of(n: usize, salt: u32) -> Vec<Header> {
        let mut c = vec![genesis()];
        c.extend(regtest_branch(&genesis(), n, genesis().time, salt));
        c
    }

    #[test]
    fn no_progress_means_no_tip() {
        let a = ServerAuthority::new(BNetwork::Regtest);
        assert_eq!(a.tip_height(), None);
        assert_eq!(a.summary(0).height, None);
    }

    #[test]
    fn the_most_work_chain_among_servers_wins() {
        let mut a = ServerAuthority::new(BNetwork::Regtest);
        let honest = chain_of(30, 1);
        // A server hiding the last 5 blocks loses to one that doesn't.
        let hiding = fake("hiding", honest[..26].to_vec());
        let full = fake("full", honest.clone());
        let c = a.refresh(&[&hiding, &full], NOW);
        assert!(c.tip_moved && c.suspects.is_empty(), "{c:?}");
        assert_eq!(a.tip_height(), Some(30));
        assert_eq!(c.agreeing, vec!["full".to_string(), "hiding".to_string()]);
        assert_eq!(a.summary(u64::from(NOW)).peers, 2);
        // A heavier fork from height 20 replaces it: a reorg of 10.
        let mut fork = honest[..21].to_vec();
        fork.extend(regtest_branch(&honest[20], 12, honest[20].time + 1, 2));
        let c = a.refresh(&[&fake("fork", fork.clone()), &full], NOW);
        assert_eq!((c.reorg_depth, c.changed_from), (10, Some(21)));
        assert_eq!(a.hash_at(32), Some(fork[32].block_hash()));
        assert_eq!(c.agreeing, vec!["fork".to_string()]);
        assert!(a.replaced(25, honest[25].block_hash()) && !a.replaced(25, fork[25].block_hash()));
    }

    #[test]
    fn invalid_headers_mark_the_source() {
        let mut a = ServerAuthority::new(BNetwork::Regtest);
        let honest = chain_of(10, 3);
        a.refresh(&[&fake("h", honest.clone())], NOW);
        let mut bad = honest.clone();
        bad.extend(regtest_branch(&honest[10], 3, honest[10].time, 3));
        bad[12].prev_blockhash = BlockHash::all_zeros();
        let c = a.refresh(&[&fake("liar", bad)], NOW);
        assert_eq!(c.suspects.len(), 1);
        assert!(c.agreeing.is_empty());
        assert_eq!(a.tip_height(), Some(11), "the valid prefix still counts");
        // A lighter chain is ignored without blame.
        let c = a.refresh(&[&fake("other", chain_of(5, 9))], NOW);
        assert!(c.suspects.is_empty() && !c.tip_moved, "{c:?}");
    }

    #[test]
    fn bdk_chain_updates_connect() {
        let mut a = ServerAuthority::new(BNetwork::Regtest);
        let honest = chain_of(30, 4);
        a.refresh(&[&fake("h", honest.clone())], NOW);
        let bdk = vec![(0, honest[0].block_hash()), (12, honest[12].block_hash())];
        let u = chain_update(&a, &bdk, &BTreeSet::from([20])).unwrap();
        assert_eq!(u.iter().map(|(h, _)| *h).collect::<Vec<_>>(), vec![12, 20, 30]);
        // After a reorg from 21, BDK's 25 is restated with the new hash, down to agreement.
        let bdk = vec![(0, honest[0].block_hash()), (12, honest[12].block_hash()), (25, honest[25].block_hash())];
        let mut fork = honest[..21].to_vec();
        fork.extend(regtest_branch(&honest[20], 12, honest[20].time + 1, 5));
        a.refresh(&[&fake("f", fork.clone())], NOW);
        let u = chain_update(&a, &bdk, &BTreeSet::new()).unwrap();
        assert_eq!(u, vec![(12, honest[12].block_hash()), (25, fork[25].block_hash()), (32, fork[32].block_hash())]);
        // BDK holding a block above the authority's tip waits.
        let ahead = vec![(0, honest[0].block_hash()), (40, honest[0].block_hash())];
        assert_eq!(chain_update(&a, &ahead, &BTreeSet::new()), None);
        assert_eq!(chain_update(&ServerAuthority::new(BNetwork::Regtest), &bdk, &BTreeSet::new()), None, "no progress, no update");
    }

    #[test]
    fn a_checkpointed_chain_restates_bdks_genesis() {
        // Signet's authority starts at its checkpoint; BDK's chain starts at genesis.
        let cp = BNetwork::Signet.checkpoint();
        let mut a = ServerAuthority::on(HeaderChain::from_checkpoint(BNetwork::Signet, cp.height, cp.header));
        a.progressed = true;
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Signet).block_hash();
        let u = chain_update(&a, &[(0, genesis)], &BTreeSet::new()).expect("an update, not a stall");
        assert_eq!(u, vec![(0, genesis), (cp.height, cp.header.block_hash())]);
    }

    #[test]
    fn heights_below_the_checkpoint_are_proved_by_linkage() {
        let full = chain_of(20, 6);
        // Trust height 10 as if it were the checkpoint.
        let mut a = ServerAuthority::on(HeaderChain::from_checkpoint(BNetwork::Regtest, 10, full[10]));
        let honest = fake("h", full.clone());
        let proved = a.prove_below(&[7, 3, 12], &honest).unwrap();
        assert_eq!(proved, vec![(7, full[7].block_hash()), (3, full[3].block_hash())]);
        assert_eq!(a.hash_at(3), Some(full[3].block_hash()));
        // A server whose old header doesn't hash into the chain above is refused.
        let mut lie = full.clone();
        lie[5].nonce ^= 1;
        let mut b = ServerAuthority::on(HeaderChain::from_checkpoint(BNetwork::Regtest, 10, full[10]));
        let e = b.prove_below(&[2], &fake("liar", lie)).unwrap_err();
        assert!(e.contains("does not link"), "{e}");
        assert_eq!(b.hash_at(2), None);
    }
}
