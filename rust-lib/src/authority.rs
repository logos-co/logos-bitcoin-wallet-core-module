//! The chain authority, the only source that moves the wallet's chain: one validated header chain,
//! fed by the local node, by Kyoto, or else by the most-work chain among the enabled Electrum servers.

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
/// Headers a fork search asks for first, below the lower tip: most forks are a block or two deep.
const FORK_WINDOW: u32 = 16;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub kind: &'static str,
    pub height: Option<u32>,
    pub hash: Option<String>,
    pub tip_age_secs: Option<u64>,
    /// Sources whose tip is on the authority's chain.
    pub peers: u32,
    /// A round of asking the chain's sources has finished since the open or a change of feeder;
    /// until then `peers` is 0 and `height` is the chain stored last time.
    pub asked: bool,
    /// The checkpoint the chain starts from: every anchor at or above it is checked against it.
    pub base: u32,
    /// While headers are being taken in: the chain's tip and the tip its source announced.
    pub headers: Option<HeaderProgress>,
}

/// A header download: `have` the height reached, `target` the tip the source announced, unknown
/// for Kyoto, whose peers' tips aren't known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HeaderProgress {
    pub have: u32,
    pub target: Option<u32>,
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
    /// Proves heights below the checkpoint by linking a source's headers up to a known hash: the
    /// headers at those heights, or an error for headers that don't link.
    fn prove_below(&mut self, heights: &[u32], source: &dyn HeaderSource) -> Result<Walked, String>;
    fn summary(&self, now: u64) -> Summary;
    fn chain(&self) -> &HeaderChain;
}

/// What a walk below the chain's start proved: the headers at the heights asked for, and where
/// it stopped short of the lowest, if the budget ran out or a fetch failed first.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Walked {
    pub proved: Vec<(u32, Header)>,
    pub stopped_at: Option<(u32, BlockHash)>,
    /// Why a fetch failed, which stopped the walk.
    pub error: Option<String>,
}

/// Blocks a reorg replaced, remembered so a server that lags it isn't taken for a liar.
const REPLACED_KEPT: usize = 512;

pub const ELECTRUM_HEADERS: &str = "electrum_headers";
pub const KYOTO: &str = "kyoto";
pub const LOCAL_NODE: &str = "local_node";
pub const RPC_NODE: &str = "rpc_node";

/// The wallet's header chain and who feeds it: `refresh` for Electrum servers, `adopt` for Kyoto
/// and the local node, whose headers pass the same checks.
pub struct ChainAuthority {
    kind: &'static str,
    chain: HeaderChain,
    old: BTreeMap<u32, BlockHash>,
    progressed: bool,
    agreeing: BTreeSet<String>,
    peers: u32,
    asked: bool,
    replaced: std::collections::VecDeque<(u32, BlockHash)>,
    /// The highest tip a source on the chain announced above it: what a download is heading to.
    target: Option<u32>,
    /// This round's sources and the last of their headers taken, so one ahead still agrees.
    delivered: BTreeMap<String, (u32, BlockHash)>,
    /// The first height the shared header store gave that this wallet hadn't checked itself and
    /// no source has vouched for yet.
    seed: Option<u32>,
}

impl ChainAuthority {
    pub fn new(net: BNetwork) -> Self {
        Self::on(HeaderChain::new(net))
    }

    pub fn on(chain: HeaderChain) -> Self {
        Self { kind: ELECTRUM_HEADERS, chain, old: BTreeMap::new(), progressed: false, agreeing: BTreeSet::new(), peers: 0, asked: false, replaced: Default::default(), target: None, delivered: BTreeMap::new(), seed: None }
    }

    /// From stored headers and proofs on `cp`; a stored chain counts as progress, and its age shows.
    pub fn restore(net: BNetwork, cp: crate::network::Checkpoint, headers: Vec<(u32, Header)>, old: Vec<(u32, BlockHash)>, now: u32) -> Self {
        let chain = HeaderChain::restore_from(net, cp, headers, now);
        let progressed = chain.tip_height() > chain.base();
        Self { kind: ELECTRUM_HEADERS, chain, old: old.into_iter().collect(), progressed, agreeing: BTreeSet::new(), peers: 0, asked: false, replaced: Default::default(), target: None, delivered: BTreeMap::new(), seed: None }
    }

    /// Starts the chain again from `cp`, a lower checkpoint, keeping who feeds it and the hashes
    /// below proved so far: a birthday moved below the chain's start.
    pub fn rebase(&mut self, cp: crate::network::Checkpoint) {
        self.chain = HeaderChain::from_checkpoint(self.chain.network(), cp.height, cp.header);
        self.old.retain(|h, _| *h < cp.height);
        (self.progressed, self.replaced, self.asked, self.target, self.seed) = (false, Default::default(), false, None, None);
        self.agreeing.clear();
    }

    /// Takes the network's shared headers above the wallet's checkpoint when they hold more work
    /// than its own chain, as a source's branch would be taken. What the wallet's own chain or its
    /// last tip (`anchor`) covers it checked before; the rest waits for a source to vouch for it.
    pub fn seed(&mut self, shared: &HeaderChain, anchor: Option<(u32, BlockHash)>, now: u32) -> bool {
        let base = self.chain.base();
        if shared.network() != self.chain.network() || shared.hash_at(base) != self.chain.hash_at(base) {
            return false;
        }
        let own = self.chain.tip_height();
        let checked = if own == base {
            // Nothing of its own: the store's chain from here, checked as it was loaded.
            match shared.suffix(base).filter(|c| c.tip_height() > base) {
                Some(c) => self.chain = c,
                None => return false,
            }
            base
        } else {
            let branch: Vec<Header> = shared.headers_from(base + 1).map(|(_, h)| *h).collect();
            let r = self.chain.try_extend(base, &branch, now);
            if !r.adopted {
                return false;
            }
            r.changed_from.map_or(own, |h| h - 1)
        };
        let anchored = anchor.filter(|(h, hash)| self.chain.hash_at(*h) == Some(*hash)).map_or(base, |(h, _)| h);
        self.progressed = true;
        self.seed = Some(checked.max(anchored) + 1).filter(|h| *h <= self.chain.tip_height());
        true
    }

    /// The first seeded height no source has vouched for yet.
    pub fn seed_from(&self) -> Option<u32> {
        self.seed
    }

    /// A source holds the same block there: the seeded chain below links to the wallet's own.
    pub fn vouch(&mut self) {
        self.seed = None;
    }

    /// Sources hold another block there: the seeded headers go, from `seed_from` up, and are read
    /// from the sources instead. Returns the height they went from and the hash dropped there.
    pub fn disown(&mut self) -> Option<(u32, BlockHash)> {
        let from = self.seed.take()?;
        let hash = self.chain.hash_at(from)?;
        self.chain.truncate(from - 1);
        self.progressed = self.chain.tip_height() > self.chain.base();
        Some((from, hash))
    }

    /// Who feeds the chain now; the chain itself carries over.
    pub fn set_kind(&mut self, kind: &'static str) {
        if self.kind != kind {
            self.kind = kind;
            self.agreeing.clear();
            (self.peers, self.asked, self.target) = (0, false, None);
        }
    }

    /// The node's tip while its headers are taken in; none once the chain reaches it.
    pub fn set_target(&mut self, target: Option<u32>) {
        self.target = target;
    }

    /// Kyoto's connected peers, or 1 for a reachable node.
    pub fn set_peers(&mut self, n: u32) {
        self.peers = n;
    }

    /// Kyoto or the node answered, or failed to, for the first time since the feeder took over.
    pub fn set_asked(&mut self) {
        self.asked = true;
    }

    /// A branch from Kyoto or the node, continuing the chain at `fork`: validated like a server's,
    /// adopted on more work. An empty branch that agrees at the tip confirms the chain as it is.
    pub fn adopt(&mut self, fork: u32, branch: &[Header], now: u32) -> Change {
        let mut change = Change::default();
        let before = self.chain.tip_hash();
        let r = self.chain.try_extend(fork, branch, now);
        if let Some(e) = &r.error {
            change.suspects.push((self.kind.to_string(), e.to_string()));
        }
        if r.adopted {
            self.remember(r.replaced);
            change.reorg_depth = r.reorg_depth;
            change.changed_from = r.changed_from;
        }
        if r.error.is_none() && fork + branch.len() as u32 >= self.chain.tip_height() {
            self.progressed = true;
        }
        change.tip_moved = self.chain.tip_hash() != before;
        change
    }

    /// Proves blocks below the chain's start, walking down from the nearest known hash above them
    /// a header at a time (`header_of`, by hash, as Esplora serves them), each checked to hash as
    /// its child names it; at most `budget` a call, the next going on from where it stopped. A
    /// header that hashes otherwise is an error; a failed fetch only stops the walk.
    pub fn prove_below_by_hash(&mut self, heights: &[u32], header_of: &mut dyn FnMut(BlockHash) -> Result<Header, String>, budget: u32) -> Result<Walked, String> {
        let base = self.chain.base();
        let wanted: BTreeSet<u32> = heights.iter().copied().filter(|h| *h < base && !self.old.contains_key(h)).collect();
        let (Some(&lowest), Some(&highest)) = (wanted.first(), wanted.last()) else { return Ok(Walked::default()) };
        // A proven hash at `at`; its header, held at the chain's start, else fetched, names the next.
        let (mut at, mut hash) = match self.old.range(highest + 1..).next() {
            Some((h, hash)) => (*h, *hash),
            None => (base, self.chain.hash_at(base).expect("the checkpoint")),
        };
        let (mut walked, mut spent) = (Walked::default(), 0u32);
        loop {
            let header = match self.chain.header_at(at).filter(|_| at == base) {
                Some(h) => *h,
                None if spent == budget => {
                    self.old.insert(at, hash);
                    walked.stopped_at = Some((at, hash));
                    break;
                }
                None => match header_of(hash) {
                    Ok(h) if h.block_hash() == hash => {
                        spent += 1;
                        h
                    }
                    Ok(h) => return Err(format!("the header for {hash} at {at} hashes to {}", h.block_hash())),
                    Err(e) => {
                        self.old.insert(at, hash);
                        (walked.stopped_at, walked.error) = (Some((at, hash)), Some(e));
                        break;
                    }
                },
            };
            if wanted.contains(&at) {
                self.old.insert(at, hash);
                walked.proved.push((at, header));
            }
            if at == lowest {
                break;
            }
            (at, hash) = (at - 1, header.prev_blockhash);
            if self.old.get(&at).is_some_and(|known| *known != hash) {
                return Err(format!("the chain below {at} doesn't link to the one proved before"));
            }
        }
        Ok(walked)
    }

    /// A height below the checkpoint, named by Kyoto from its own start or proved by linkage.
    pub fn note_old(&mut self, height: u32, hash: BlockHash) {
        if height < self.chain.base() {
            self.old.insert(height, hash);
        }
    }

    fn remember(&mut self, replaced: Vec<(u32, BlockHash)>) {
        for x in replaced {
            if self.replaced.len() == REPLACED_KEPT {
                self.replaced.pop_front();
            }
            self.replaced.push_back(x);
        }
    }

    /// The highest height where `src` and the chain agree, searching down from `from`: a few
    /// headers first, then whole answers.
    fn fork_point(&self, src: &dyn HeaderSource, from: u32) -> Result<Option<u32>, String> {
        let base = self.chain.base();
        let (mut top, mut span) = (from.min(self.chain.tip_height()), FORK_WINDOW);
        loop {
            let start = top.saturating_sub(span - 1).max(base);
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
            (top, span) = (start - 1, HEADERS_PER_CALL);
        }
    }

    /// The fork and the branch's first headers, where no search is needed: the tip's parent is on
    /// the chain (a new block, or one beside ours), or the answer from above our tip names it.
    fn quick_fork(&self, src: &dyn HeaderSource, their_tip: u32, their_header: &Header) -> Result<Option<(u32, Vec<Header>)>, String> {
        if their_tip.checked_sub(1).and_then(|h| self.chain.hash_at(h)) == Some(their_header.prev_blockhash) {
            return Ok(Some((their_tip - 1, vec![*their_header])));
        }
        let ours = self.chain.tip_height();
        if their_tip <= ours + 1 {
            return Ok(None);
        }
        let got = src.headers(ours + 1, (their_tip - ours).min(HEADERS_PER_CALL))?;
        Ok(got.first().is_some_and(|h| h.prev_blockhash == self.chain.tip_hash()).then_some((ours, got)))
    }

    /// Fetches and tries `src`'s chain; returns its tip for the agreement count. Each answer is
    /// checked and taken as it comes, and `on_chunk` hears of it, so a long download shows.
    fn refresh_one(&mut self, src: &dyn HeaderSource, now: u32, change: &mut Change, on_chunk: &mut dyn FnMut(&ChainAuthority)) -> Result<(u32, BlockHash), String> {
        let (their_tip, their_header) = src.tip()?;
        let tip = (their_tip, their_header.block_hash());
        if their_tip < self.chain.base() {
            return Err(format!("its tip {their_tip} is below the checkpoint"));
        }
        if self.chain.hash_at(their_tip) == Some(tip.1) {
            return Ok(tip);
        }
        let (found, mut first) = match self.quick_fork(src, their_tip, &their_header)? {
            Some((at, got)) => (Some(at), Some(got)),
            None => (self.fork_point(src, their_tip)?, None),
        };
        let Some(mut fork) = found else {
            change.suspects.push((src.id().into(), "its chain does not contain the checkpoint".into()));
            return Ok(tip);
        };
        let mut start = fork + 1;
        let mut branch: Vec<Header> = vec![];
        let mut calls = 0;
        while start <= their_tip && calls < MAX_CALLS_PER_REFRESH {
            let got = match first.take() {
                Some(got) => got,
                None => src.headers(start, (their_tip - start + 1).min(HEADERS_PER_CALL))?,
            };
            if got.is_empty() {
                break;
            }
            start += got.len() as u32;
            branch.extend(got);
            calls += 1;
            // A branch lighter than ours so far (a deep reorg) waits for more of it.
            let r = self.chain.try_extend(fork, &branch, now);
            if let Some(e) = &r.error {
                // A header that fails the checks is a lie, not a lag; one from the future may be a clock.
                if !matches!(e, HeaderError::TimeTooNew(_)) {
                    change.suspects.push((src.id().into(), e.to_string()));
                }
            }
            if r.adopted {
                self.remember(r.replaced);
                change.reorg_depth = change.reorg_depth.max(r.reorg_depth);
                change.changed_from = match (change.changed_from, r.changed_from) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
            }
            if r.error.is_some() {
                break;
            }
            if branch.last().is_some_and(|h| self.chain.tip_hash() == h.block_hash()) {
                // Taken whole: the source is on the chain, ahead of it, and has answered.
                (fork, self.asked, self.progressed) = (self.chain.tip_height(), true, true);
                branch.clear();
                self.delivered.insert(src.id().to_string(), (fork, self.chain.tip_hash()));
                self.agreeing.insert(src.id().to_string());
                if their_tip > fork {
                    self.target = Some(self.target.map_or(their_tip, |t| t.max(their_tip)));
                }
                on_chunk(self);
            }
        }
        Ok(tip)
    }

    /// `refresh`, with `on_chunk` called as each answer is taken during a long download.
    pub fn refresh_with(&mut self, sources: &[&dyn HeaderSource], now: u32, on_chunk: &mut dyn FnMut(&ChainAuthority)) -> Change {
        let mut change = Change::default();
        let before = self.chain.tip_hash();
        self.delivered.clear();
        let mut tips = vec![];
        for src in sources {
            match self.refresh_one(*src, now, &mut change, on_chunk) {
                Ok(tip) => {
                    self.progressed = true;
                    tips.push((src.id().to_string(), tip));
                }
                Err(e) => change.failures.push((src.id().into(), e)),
            }
        }
        // Agreement against the chain kept after every source had its say: a source whose tip is
        // on it, or one ahead whose headers it took this round.
        let on_chain = |id: &str, (h, hash): (u32, BlockHash)| {
            self.chain.hash_at(h) == Some(hash) || self.delivered.get(id).is_some_and(|(dh, dhash)| self.chain.hash_at(*dh) == Some(*dhash))
        };
        let agreeing: Vec<(String, u32)> = tips
            .into_iter()
            .filter(|(id, tip)| on_chain(id, *tip) && !change.suspects.iter().any(|(s, _)| s == id))
            .map(|(id, (h, _))| (id, h))
            .collect();
        let tip = self.chain.tip_height();
        self.target = agreeing.iter().map(|(_, h)| *h).filter(|h| *h > tip).max();
        self.agreeing = agreeing.into_iter().map(|(id, _)| id).collect();
        change.tip_moved = self.chain.tip_hash() != before;
        change.agreeing = self.agreeing.iter().cloned().collect();
        self.asked = true;
        change
    }
}

impl ChainView for ChainAuthority {
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

impl Authority for ChainAuthority {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn refresh(&mut self, sources: &[&dyn HeaderSource], now: u32) -> Change {
        self.refresh_with(sources, now, &mut |_| {})
    }

    fn prove_below(&mut self, heights: &[u32], src: &dyn HeaderSource) -> Result<Walked, String> {
        let base = self.chain.base();
        let mut wanted: Vec<u32> = heights.iter().copied().filter(|h| *h < base && !self.old.contains_key(h)).collect();
        wanted.sort_unstable();
        wanted.dedup();
        let mut walked = Walked::default();
        // Highest first, each linking up to the nearest known hash above it; a failed or short
        // answer stops there, a header that doesn't link is a lie.
        for h in wanted.into_iter().rev() {
            let (above, known) = match self.old.range(h + 1..).next() {
                Some((k, v)) => (*k, *v),
                None => (base, self.chain.hash_at(base).expect("the checkpoint")),
            };
            let (mut top, mut expect) = (above, known);
            loop {
                let start = top.saturating_sub(HEADERS_PER_CALL - 1).max(h);
                let got = match src.headers(start, top - start + 1) {
                    Ok(got) if got.len() as u32 == top - start + 1 => got,
                    Ok(_) => return Ok(Walked { error: Some(format!("headers {start}..={top} came back short")), ..walked }),
                    Err(e) => return Ok(Walked { error: Some(e), ..walked }),
                };
                for (i, hd) in got.iter().enumerate().rev() {
                    if hd.block_hash() != expect {
                        return Err(format!("header {} does not link up to the checkpoint", start + i as u32));
                    }
                    expect = hd.prev_blockhash;
                }
                if start == h {
                    self.old.insert(h, got[0].block_hash());
                    walked.proved.push((h, got[0]));
                    break;
                }
                top = start - 1;
            }
        }
        Ok(walked)
    }

    fn summary(&self, now: u64) -> Summary {
        let tip = self.chain.tip_height();
        Summary {
            kind: self.kind(),
            height: self.tip_height(),
            hash: self.progressed.then(|| self.chain.tip_hash().to_string()),
            tip_age_secs: self.progressed.then(|| now.saturating_sub(u64::from(self.chain.tip().time))),
            peers: if self.kind == ELECTRUM_HEADERS { self.agreeing.len() as u32 } else { self.peers },
            asked: self.asked,
            base: self.chain.base(),
            headers: self.target.filter(|t| *t > tip).map(|t| HeaderProgress { have: tip, target: Some(t) }),
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

    /// A source serving a fixed chain from genesis, counting the headers it sends.
    struct Fake {
        id: String,
        chain: Vec<Header>,
        served: std::cell::Cell<u32>,
    }

    impl HeaderSource for Fake {
        fn id(&self) -> &str {
            &self.id
        }
        fn tip(&self) -> Result<(u32, Header), String> {
            Ok((self.chain.len() as u32 - 1, *self.chain.last().unwrap()))
        }
        fn headers(&self, start: u32, count: u32) -> Result<Vec<Header>, String> {
            let got: Vec<Header> = self.chain.iter().skip(start as usize).take(count as usize).copied().collect();
            self.served.set(self.served.get() + got.len() as u32);
            Ok(got)
        }
    }

    fn fake(id: &str, chain: Vec<Header>) -> Fake {
        Fake { id: id.into(), chain, served: Default::default() }
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
    fn a_chain_restored_on_a_checkpoint_and_rebased_lower() {
        let honest = chain_of(30, 1);
        let at = |h: usize| crate::network::Checkpoint { height: h as u32, header: honest[h] };
        // Stored headers above a checkpoint at 10: kept from there, and nothing below is known.
        let stored: Vec<(u32, Header)> = (11..=30).map(|h| (h as u32, honest[h])).collect();
        let mut a = ChainAuthority::restore(BNetwork::Regtest, at(10), stored, vec![(4, honest[4].block_hash())], NOW);
        assert_eq!((a.base_height(), a.tip_height()), (10, Some(30)));
        assert_eq!(a.summary(0).base, 10);
        assert_eq!(crate::checks::judge_anchor(&a, 7, honest[7].block_hash()), crate::checks::AnchorVerdict::NeedsLinkage);
        // A birthday below 10: the chain starts again at genesis, and every height is judged by it.
        a.rebase(at(0));
        assert_eq!((a.base_height(), a.tip_height()), (0, None), "no progress until it is fed again");
        let full = fake("full", honest.clone());
        a.refresh(&[&full], NOW);
        assert_eq!(crate::checks::judge_anchor(&a, 7, honest[7].block_hash()), crate::checks::AnchorVerdict::Keep);
        assert_eq!(crate::checks::judge_anchor(&a, 7, honest[8].block_hash()), crate::checks::AnchorVerdict::Drop);
    }

    #[test]
    fn old_blocks_link_to_the_chain_header_by_header_within_a_budget() {
        let honest = chain_of(40, 1);
        let by_hash: std::collections::HashMap<BlockHash, Header> = honest.iter().map(|h| (h.block_hash(), *h)).collect();
        let at = |h: usize| crate::network::Checkpoint { height: h as u32, header: honest[h] };
        let mut a = ChainAuthority::restore(BNetwork::Regtest, at(30), (31..=40).map(|h| (h as u32, honest[h])).collect(), vec![], NOW);
        let mut asked = 0;
        let mut serve = |hash: BlockHash| {
            asked += 1;
            by_hash.get(&hash).copied().ok_or_else(|| "404".to_string())
        };
        // Five headers a call: 29 to 25, then 24 to 20, then the rest down to 10.
        let w = a.prove_below_by_hash(&[10, 20], &mut serve, 5).unwrap();
        assert_eq!((w.proved.len(), w.stopped_at), (0, Some((24, honest[24].block_hash()))));
        let w = a.prove_below_by_hash(&[10, 20], &mut serve, 5).unwrap();
        assert_eq!(w.proved, vec![(20, honest[20])]);
        let w = a.prove_below_by_hash(&[10, 20], &mut serve, 20).unwrap();
        assert_eq!((w.proved, w.stopped_at), (vec![(10, honest[10])], None));
        assert_eq!(asked, 20, "each header fetched once");
        assert_eq!(crate::checks::judge_anchor(&a, 10, honest[10].block_hash()), crate::checks::AnchorVerdict::Keep);
        assert_eq!(crate::checks::judge_anchor(&a, 10, honest[11].block_hash()), crate::checks::AnchorVerdict::Drop);
        // A server that answers with another block's header is caught; one that fails only stops.
        let mut lying = |_: BlockHash| Ok(honest[3]);
        assert!(a.prove_below_by_hash(&[5], &mut lying, 10).is_err());
        let mut failing = |_: BlockHash| Err("timed out".to_string());
        let w = a.prove_below_by_hash(&[5], &mut failing, 10).unwrap();
        assert_eq!((w.proved.len(), w.error.as_deref()), (0, Some("timed out")));
        assert_eq!(crate::checks::judge_anchor(&a, 5, honest[5].block_hash()), crate::checks::AnchorVerdict::NeedsLinkage, "unchecked");
    }

    #[test]
    fn no_progress_means_no_tip() {
        let a = ChainAuthority::new(BNetwork::Regtest);
        assert_eq!(a.tip_height(), None);
        assert_eq!(a.summary(0).height, None);
    }

    #[test]
    fn a_stored_chain_is_not_asked_until_a_round_ends() {
        let honest = chain_of(10, 11);
        let stored: Vec<(u32, Header)> = honest.iter().enumerate().skip(1).map(|(h, x)| (h as u32, *x)).collect();
        let cp = crate::network::Checkpoint { height: 0, header: honest[0] };
        let mut a = ChainAuthority::restore(BNetwork::Regtest, cp, stored, vec![], NOW);
        let s = a.summary(u64::from(NOW));
        assert_eq!((s.height, s.peers, s.asked), (Some(10), 0, false), "last session's chain, nobody asked yet");
        // A round where every server failed has still asked them.
        struct Down;
        impl HeaderSource for Down {
            fn id(&self) -> &str {
                "down"
            }
            fn tip(&self) -> Result<(u32, Header), String> {
                Err("connection refused".into())
            }
            fn headers(&self, _: u32, _: u32) -> Result<Vec<Header>, String> {
                Err("connection refused".into())
            }
        }
        let c = a.refresh(&[&Down], NOW);
        assert_eq!(c.failures.len(), 1);
        assert_eq!((a.summary(0).peers, a.summary(0).asked), (0, true));
        // A new feeder starts unasked; Kyoto or the node say when they answered.
        a.set_kind(KYOTO);
        assert!(!a.summary(0).asked);
        a.set_asked();
        assert!(a.summary(0).asked);
        a.set_kind(KYOTO);
        assert!(a.summary(0).asked, "the same feeder keeps it");
    }

    #[test]
    fn the_most_work_chain_among_servers_wins() {
        let mut a = ChainAuthority::new(BNetwork::Regtest);
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

    /// A source serving a fixed chain, whose header calls fail from the `fail_from`th on.
    struct Failing {
        chain: Vec<Header>,
        calls: std::cell::Cell<u32>,
        fail_from: u32,
    }

    impl HeaderSource for Failing {
        fn id(&self) -> &str {
            "failing"
        }
        fn tip(&self) -> Result<(u32, Header), String> {
            Ok((self.chain.len() as u32 - 1, *self.chain.last().unwrap()))
        }
        fn headers(&self, start: u32, count: u32) -> Result<Vec<Header>, String> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() >= self.fail_from {
                return Err("connection reset".into());
            }
            Ok(self.chain.iter().skip(start as usize).take(count as usize).copied().collect())
        }
    }

    #[test]
    fn a_long_download_is_taken_and_shown_chunk_by_chunk() {
        let honest = chain_of(5_000, 21);
        let mut a = ChainAuthority::new(BNetwork::Regtest);
        let mut seen = vec![];
        let c = a.refresh_with(&[&fake("far", honest.clone())], NOW, &mut |a| {
            let s = a.summary(u64::from(NOW));
            seen.push((s.height, s.headers, s.peers, s.asked));
        });
        let at = |have: u32| Some(HeaderProgress { have, target: Some(5_000) });
        assert_eq!(seen, vec![(Some(2_016), at(2_016), 1, true), (Some(4_032), at(4_032), 1, true), (Some(5_000), None, 1, true)]);
        assert_eq!((c.changed_from, c.agreeing.clone()), (Some(1), vec!["far".to_string()]));
        assert_eq!(a.summary(0).headers, None, "at the source's tip nothing is left to read");
    }

    #[test]
    fn a_download_longer_than_a_round_shows_its_target_between_rounds() {
        let honest = chain_of(60_000, 22);
        let mut a = ChainAuthority::new(BNetwork::Regtest);
        let far = fake("far", honest);
        a.refresh(&[&far], NOW);
        let s = a.summary(u64::from(NOW));
        let have = HEADERS_PER_CALL * MAX_CALLS_PER_REFRESH;
        assert_eq!((s.height, s.headers, s.peers, s.asked), (Some(have), Some(HeaderProgress { have, target: Some(60_000) }), 1, true),
                   "a source still sending its chain agrees with it, and has answered");
        a.refresh(&[&far], NOW);
        let s = a.summary(u64::from(NOW));
        assert_eq!((s.height, s.headers, s.peers), (Some(60_000), None, 1));
    }

    #[test]
    fn what_was_taken_before_a_source_failed_stays() {
        let honest = chain_of(5_000, 23);
        let mut a = ChainAuthority::new(BNetwork::Regtest);
        // Two chunks, then the third call fails.
        let c = a.refresh(&[&Failing { chain: honest.clone(), calls: Default::default(), fail_from: 3 }], NOW);
        assert_eq!((a.tip_height(), c.changed_from, c.failures.len()), (Some(4_032), Some(1), 1));
        assert_eq!(a.hash_at(4_032), Some(honest[4_032].block_hash()));
        let s = a.summary(u64::from(NOW));
        assert_eq!((s.peers, s.headers), (0, None), "a source that failed agrees with nothing this round");
    }

    #[test]
    fn a_reorg_longer_than_one_answer_waits_for_enough_work() {
        let ours = chain_of(3_000, 24);
        let mut a = ChainAuthority::new(BNetwork::Regtest);
        a.refresh(&[&fake("ours", ours.clone())], NOW);
        // A heavier fork from 100: its first 2,016 headers weigh less than our 2,900 above it.
        let mut theirs = ours[..101].to_vec();
        theirs.extend(regtest_branch(&ours[100], 3_100, ours[100].time + 1, 25));
        let c = a.refresh(&[&fake("theirs", theirs.clone())], NOW);
        assert_eq!((c.reorg_depth, c.changed_from, a.tip_height()), (2_900, Some(101), Some(3_200)));
        assert_eq!(a.hash_at(3_200), Some(theirs[3_200].block_hash()));
    }

    #[test]
    fn new_blocks_cost_their_own_headers_and_a_shallow_fork_a_few() {
        let mut honest = chain_of(3_000, 26);
        let mut a = ChainAuthority::new(BNetwork::Regtest);
        let first = fake("s", honest.clone());
        a.refresh(&[&first], NOW);
        assert_eq!(first.served.get(), 3_000, "a first sync reads each header once");
        // One new block comes with the tip, its parent ours; three are read from just above ours.
        for (n, cost) in [(1, 0), (1, 0), (3, 3)] {
            let last = *honest.last().unwrap();
            honest.extend(regtest_branch(&last, n, last.time, 26));
            let s = fake("s", honest.clone());
            let c = a.refresh(&[&s], NOW);
            assert_eq!((c.changed_from, c.reorg_depth, c.agreeing.len(), s.served.get()), (Some(honest.len() as u32 - n as u32), 0, 1, cost));
        }
        // The tip replaced by two blocks: their parent isn't ours, and a window finds the fork.
        let at = honest.len() - 1;
        let mut fork = honest[..at].to_vec();
        fork.extend(regtest_branch(&honest[at - 1], 2, honest[at - 1].time + 1, 27));
        let s = fake("s", fork.clone());
        let c = a.refresh(&[&s], NOW);
        assert_eq!((c.reorg_depth, c.changed_from, a.hash_at(at as u32 + 1)), (1, Some(at as u32), Some(fork[at + 1].block_hash())));
        assert_eq!(s.served.get(), FORK_WINDOW + 2);
        // A server left on the replaced block: its tip's parent is ours, so nothing is read, and
        // it isn't blamed.
        let behind = fake("behind", honest.clone());
        let c = a.refresh(&[&behind], NOW);
        assert!(c.suspects.is_empty() && !c.tip_moved && c.agreeing.is_empty(), "{c:?}");
        assert_eq!(behind.served.get(), 0);
        // One deeper than the window: the search reads on, whole answers below it.
        let deep = honest.len() - 20;
        let mut longer = honest[..deep].to_vec();
        longer.extend(regtest_branch(&honest[deep - 1], 30, honest[deep - 1].time + 1, 28));
        let s = fake("s", longer.clone());
        let c = a.refresh(&[&s], NOW);
        assert_eq!((c.reorg_depth, c.changed_from), (fork.len() as u32 - deep as u32, Some(deep as u32)));
        assert_eq!(a.hash_at(longer.len() as u32 - 1), Some(longer.last().unwrap().block_hash()));
    }

    #[test]
    fn shared_headers_seed_the_chain_and_wait_for_a_source_past_what_the_wallet_checked() {
        let honest = chain_of(40, 31);
        let shared = HeaderChain::restore(BNetwork::Regtest, honest.iter().enumerate().skip(1).map(|(h, x)| (h as u32, *x)), NOW);
        // A new wallet: everything above the checkpoint waits for a source.
        let mut a = ChainAuthority::new(BNetwork::Regtest);
        assert!(a.seed(&shared, None, NOW));
        assert_eq!((a.tip_height(), a.seed_from()), (Some(40), Some(1)));
        a.vouch();
        assert_eq!(a.seed_from(), None);
        // A wallet whose last tip was 25 checked up to there itself.
        let mut b = ChainAuthority::new(BNetwork::Regtest);
        b.seed(&shared, Some((25, honest[25].block_hash())), NOW);
        assert_eq!(b.seed_from(), Some(26));
        let mut c = ChainAuthority::new(BNetwork::Regtest);
        c.seed(&shared, Some((40, honest[40].block_hash())), NOW);
        assert_eq!(c.seed_from(), None, "its whole chain");
        // A tip the store doesn't hold: none of it was checked here.
        let mut d = ChainAuthority::new(BNetwork::Regtest);
        d.seed(&shared, Some((25, honest[3].block_hash())), NOW);
        assert_eq!(d.seed_from(), Some(1));
        // Its own stored chain, 0 to 30: only more work is taken, past what it held.
        let own: Vec<(u32, Header)> = (1..=30).map(|h| (h as u32, honest[h])).collect();
        let mut e = ChainAuthority::restore(BNetwork::Regtest, BNetwork::Regtest.checkpoint(), own.clone(), vec![], NOW);
        assert!(e.seed(&shared, None, NOW));
        assert_eq!((e.tip_height(), e.seed_from()), (Some(40), Some(31)));
        let lighter = HeaderChain::restore(BNetwork::Regtest, own[..20].to_vec(), NOW);
        let mut f = ChainAuthority::restore(BNetwork::Regtest, BNetwork::Regtest.checkpoint(), own, vec![], NOW);
        assert!(!f.seed(&lighter, None, NOW));
        assert_eq!((f.tip_height(), f.seed_from()), (Some(30), None));
        // Disowned by the sources: back to what the wallet had, and the hash dropped named.
        let mut g = ChainAuthority::new(BNetwork::Regtest);
        g.seed(&shared, Some((25, honest[25].block_hash())), NOW);
        assert_eq!(g.disown(), Some((26, honest[26].block_hash())));
        assert_eq!((g.tip_height(), g.seed_from()), (Some(25), None));
        let mut n = ChainAuthority::new(BNetwork::Regtest);
        n.seed(&shared, None, NOW);
        n.disown();
        assert_eq!(n.tip_height(), None, "no progress until a source feeds it");
        // Another checkpoint's store, or another network's, seeds nothing.
        let mut h = ChainAuthority::on(HeaderChain::from_checkpoint(BNetwork::Regtest, 10, chain_of(40, 32)[10]));
        assert!(!h.seed(&shared, None, NOW));
    }

    #[test]
    fn invalid_headers_mark_the_source() {
        let mut a = ChainAuthority::new(BNetwork::Regtest);
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
        let mut a = ChainAuthority::new(BNetwork::Regtest);
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
        assert_eq!(chain_update(&ChainAuthority::new(BNetwork::Regtest), &bdk, &BTreeSet::new()), None, "no progress, no update");
    }

    #[test]
    fn a_checkpointed_chain_restates_bdks_genesis() {
        // Signet's authority starts at its checkpoint; BDK's chain starts at genesis.
        let cp = BNetwork::Signet.checkpoint();
        let mut a = ChainAuthority::on(HeaderChain::from_checkpoint(BNetwork::Signet, cp.height, cp.header));
        a.progressed = true;
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Signet).block_hash();
        let u = chain_update(&a, &[(0, genesis)], &BTreeSet::new()).expect("an update, not a stall");
        assert_eq!(u, vec![(0, genesis), (cp.height, cp.header.block_hash())]);
    }

    #[test]
    fn kyoto_and_the_node_feed_the_same_checks() {
        let mut a = ChainAuthority::new(BNetwork::Regtest);
        a.set_kind(KYOTO);
        let honest = chain_of(20, 7);
        let c = a.adopt(0, &honest[1..], NOW);
        assert!(c.tip_moved && c.suspects.is_empty(), "{c:?}");
        assert_eq!((a.tip_height(), a.kind()), (Some(20), KYOTO));
        // A heavier branch from 15 reorganizes; an empty branch at the tip only confirms it.
        let mut fork = honest[..16].to_vec();
        fork.extend(regtest_branch(&honest[15], 7, honest[15].time + 1, 8));
        let c = a.adopt(15, &fork[16..], NOW);
        assert_eq!((c.reorg_depth, c.changed_from), (5, Some(16)));
        assert!(a.replaced(18, honest[18].block_hash()));
        assert!(!a.adopt(22, &[], NOW).tip_moved);
        // A header that fails the checks is the feeder's fault, named by kind.
        let mut bad = regtest_branch(&fork[22], 2, fork[22].time, 9);
        bad[1].prev_blockhash = BlockHash::all_zeros();
        let c = a.adopt(22, &bad, NOW);
        assert_eq!(c.suspects.len(), 1);
        assert_eq!(c.suspects[0].0, KYOTO);
        assert_eq!(a.tip_height(), Some(23), "the valid prefix still counts");
        a.set_peers(3);
        assert_eq!(a.summary(u64::from(NOW)).peers, 3);
        a.note_old(3, honest[3].block_hash());
        assert_eq!(a.hash_at(3), Some(honest[3].block_hash()), "above the checkpoint the chain answers");
    }

    #[test]
    fn heights_below_the_checkpoint_are_proved_by_linkage() {
        let full = chain_of(20, 6);
        // Trust height 10 as if it were the checkpoint.
        let mut a = ChainAuthority::on(HeaderChain::from_checkpoint(BNetwork::Regtest, 10, full[10]));
        let honest = fake("h", full.clone());
        let w = a.prove_below(&[7, 3, 12], &honest).unwrap();
        assert_eq!((w.proved, w.error), (vec![(7, full[7]), (3, full[3])], None));
        assert_eq!(a.hash_at(3), Some(full[3].block_hash()));
        // A server short of the headers only stops the walk.
        let mut c = ChainAuthority::on(HeaderChain::from_checkpoint(BNetwork::Regtest, 10, full[10]));
        let w = c.prove_below(&[2], &fake("short", full[..6].to_vec())).unwrap();
        assert!(w.proved.is_empty() && w.error.as_deref().is_some_and(|e| e.contains("short")), "{w:?}");
        assert_eq!(c.hash_at(2), None);
        // A server whose old header doesn't hash into the chain above is refused.
        let mut lie = full.clone();
        lie[5].nonce ^= 1;
        let mut b = ChainAuthority::on(HeaderChain::from_checkpoint(BNetwork::Regtest, 10, full[10]));
        let e = b.prove_below(&[2], &fake("liar", lie)).unwrap_err();
        assert!(e.contains("does not link"), "{e}");
        assert_eq!(b.hash_at(2), None);
    }
}
