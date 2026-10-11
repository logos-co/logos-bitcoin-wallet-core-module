//! The header chain behind the server-only chain authority: linkage, proof of work against each
//! header's own target, mainnet retargets, median time past, and the most-work rule.

use bitcoin::block::Header;
use bitcoin::pow::{CompactTarget, Work};
use bitcoin::BlockHash;

use crate::network::BNetwork;

/// Headers further than this ahead of the local clock are refused, as Core does.
const MAX_FUTURE_SECS: u32 = 2 * 60 * 60;
const RETARGET_INTERVAL: u32 = 2016;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("header {0} does not link to the one below it")]
    Linkage(u32),
    #[error("header {0} lacks the proof of work its target asks")]
    Pow(u32),
    #[error("header {0} claims a target easier than the network allows")]
    TargetAboveLimit(u32),
    #[error("header {0} changes the difficulty between retargets")]
    BitsChanged(u32),
    #[error("header {0} has the wrong retarget")]
    Retarget(u32),
    #[error("header {0} is not later than the median of the 11 before it")]
    TimeTooOld(u32),
    #[error("header {0} is more than two hours ahead")]
    TimeTooNew(u32),
    #[error("header {0} is below the checkpoint")]
    BelowCheckpoint(u32),
}

/// The bits a retarget boundary must carry: `prev` ends the period that `first` starts.
pub fn expected_bits(net: BNetwork, prev: &Header, first: &Header) -> CompactTarget {
    let timespan = (i64::from(prev.time) - i64::from(first.time)).max(0) as u64;
    CompactTarget::from_next_work_required(prev.bits, timespan, net.params())
}

/// Checks `next` at `height` against the headers below it, which `below` returns by height.
pub fn validate(net: BNetwork, height: u32, prev: &Header, next: &Header, below: &dyn Fn(u32) -> Option<Header>, now: u32) -> Result<(), HeaderError> {
    if next.prev_blockhash != prev.block_hash() {
        return Err(HeaderError::Linkage(height));
    }
    let target = next.target();
    if target > net.params().max_attainable_target {
        return Err(HeaderError::TargetAboveLimit(height));
    }
    if next.validate_pow(target).is_err() {
        return Err(HeaderError::Pow(height));
    }
    if net.checks_retargets() {
        if height % RETARGET_INTERVAL != 0 {
            if next.bits != prev.bits {
                return Err(HeaderError::BitsChanged(height));
            }
        } else if let Some(first) = below(height - RETARGET_INTERVAL) {
            if next.bits != expected_bits(net, prev, &first) {
                return Err(HeaderError::Retarget(height));
            }
        }
    }
    // Median time past needs the 11 headers below; near the checkpoint there are fewer.
    let mut times: Vec<u32> = (1..=11).filter_map(|back| height.checked_sub(back).and_then(below)).map(|h| h.time).collect();
    if times.len() == 11 {
        times.sort_unstable();
        if next.time <= times[5] {
            return Err(HeaderError::TimeTooOld(height));
        }
    }
    if next.time > now.saturating_add(MAX_FUTURE_SECS) {
        return Err(HeaderError::TimeTooNew(height));
    }
    Ok(())
}

/// What a candidate branch did to the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extended {
    pub adopted: bool,
    /// Blocks of the old chain replaced, 0 for a plain extension.
    pub reorg_depth: u32,
    /// The first height whose header changed, when adopted.
    pub changed_from: Option<u32>,
    /// Why the branch stopped early, if a header failed.
    pub error: Option<HeaderError>,
    /// The blocks a reorg took off the chain, by height.
    pub replaced: Vec<(u32, BlockHash)>,
}

/// The validated chain from the checkpoint up: `headers[i]` is at `base + i`.
#[derive(Clone)]
pub struct HeaderChain {
    net: BNetwork,
    base: u32,
    headers: Vec<Header>,
    hashes: Vec<BlockHash>,
    /// Work of `headers[..=i]`, the checkpoint's own included.
    work: Vec<Work>,
}

impl HeaderChain {
    pub fn new(net: BNetwork) -> Self {
        let cp = net.checkpoint();
        Self::from_checkpoint(net, cp.height, cp.header)
    }

    /// A chain trusting `header` at `height`; `new` uses the network's own checkpoint.
    pub fn from_checkpoint(net: BNetwork, height: u32, header: Header) -> Self {
        Self { net, base: height, hashes: vec![header.block_hash()], work: vec![header.work()], headers: vec![header] }
    }

    /// Rebuilds a stored chain, keeping only the valid prefix from the checkpoint.
    pub fn restore(net: BNetwork, stored: impl IntoIterator<Item = (u32, Header)>, now: u32) -> Self {
        let mut chain = Self::new(net);
        let mut branch = vec![];
        for (h, header) in stored {
            if h <= chain.base {
                continue;
            }
            if h != chain.base + 1 + branch.len() as u32 {
                break;
            }
            branch.push(header);
        }
        let _ = chain.try_extend(chain.base, &branch, now);
        chain
    }

    pub fn network(&self) -> BNetwork {
        self.net
    }

    pub fn base(&self) -> u32 {
        self.base
    }

    pub fn tip_height(&self) -> u32 {
        self.base + self.headers.len() as u32 - 1
    }

    pub fn tip(&self) -> &Header {
        self.headers.last().expect("never empty")
    }

    pub fn tip_hash(&self) -> BlockHash {
        *self.hashes.last().expect("never empty")
    }

    pub fn header_at(&self, height: u32) -> Option<&Header> {
        height.checked_sub(self.base).and_then(|i| self.headers.get(i as usize))
    }

    pub fn hash_at(&self, height: u32) -> Option<BlockHash> {
        height.checked_sub(self.base).and_then(|i| self.hashes.get(i as usize)).copied()
    }

    pub fn total_work(&self) -> Work {
        *self.work.last().expect("never empty")
    }

    /// Headers above `height`, for storing.
    pub fn headers_from(&self, height: u32) -> impl Iterator<Item = (u32, &Header)> {
        let start = height.saturating_sub(self.base) as usize;
        self.headers.iter().enumerate().skip(start).map(move |(i, h)| (self.base + i as u32, h))
    }

    /// Validates `branch`, which continues the chain's header at `fork`, and adopts its valid
    /// prefix when that holds more work than the chain above `fork`. Ties keep the chain.
    pub fn try_extend(&mut self, fork: u32, branch: &[Header], now: u32) -> Extended {
        let mut out = Extended { adopted: false, reorg_depth: 0, changed_from: None, error: None, replaced: vec![] };
        if fork < self.base || fork > self.tip_height() {
            out.error = Some(HeaderError::BelowCheckpoint(fork));
            return out;
        }
        let keep = (fork - self.base + 1) as usize;
        let mut valid: Vec<Header> = Vec::with_capacity(branch.len());
        for (i, next) in branch.iter().enumerate() {
            let height = fork + 1 + i as u32;
            let prev = if i == 0 { self.headers[keep - 1] } else { valid[i - 1] };
            let below = |h: u32| -> Option<Header> {
                if h > fork {
                    valid.get((h - fork - 1) as usize).copied()
                } else {
                    self.header_at(h).copied()
                }
            };
            if let Err(e) = validate(self.net, height, &prev, next, &below, now) {
                out.error = Some(e);
                break;
            }
            valid.push(*next);
        }
        let ours = self.work_above(keep);
        let theirs = valid.iter().fold(Work::from_be_bytes([0; 32]), |acc, h| acc + h.work());
        if valid.is_empty() || theirs <= ours {
            return out;
        }
        // Replaced headers that the branch repeats are not a reorg.
        let same = valid.iter().zip(&self.hashes[keep..]).take_while(|(h, ours)| h.block_hash() == **ours).count();
        let old_tip = self.tip_height();
        out.replaced = self.hashes[keep + same..].iter().enumerate().map(|(i, h)| (fork + 1 + (same + i) as u32, *h)).collect();
        self.headers.truncate(keep);
        self.hashes.truncate(keep);
        self.work.truncate(keep);
        for h in valid {
            let w = *self.work.last().expect("never empty") + h.work();
            self.hashes.push(h.block_hash());
            self.work.push(w);
            self.headers.push(h);
        }
        out.adopted = true;
        out.reorg_depth = old_tip.saturating_sub(fork + same as u32);
        out.changed_from = Some(fork + 1 + same as u32).filter(|h| *h <= self.tip_height());
        if out.changed_from.is_none() {
            out.adopted = false;
        }
        out
    }

    fn work_above(&self, keep: usize) -> Work {
        let total = self.total_work();
        let below = self.work[keep - 1];
        total - below
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{block, TxMerkleNode};

    /// A regtest header on `prev`, mined until its own trivial target is met.
    pub(crate) fn mine(prev: &Header, time: u32, salt: u32) -> Header {
        let mut h = Header {
            version: block::Version::from_consensus(0x2000_0000),
            prev_blockhash: prev.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array([salt as u8; 32]),
            time,
            bits: prev.bits,
            nonce: 0,
        };
        while h.validate_pow(h.target()).is_err() {
            h.nonce += 1;
        }
        h
    }

    pub(crate) fn regtest_branch(from: &Header, n: usize, t0: u32, salt: u32) -> Vec<Header> {
        let mut out: Vec<Header> = vec![];
        for i in 0..n {
            let prev = out.last().copied().unwrap_or(*from);
            out.push(mine(&prev, t0 + 600 * (i as u32 + 1), salt));
        }
        out
    }

    const NOW: u32 = 2_000_000_000;

    fn genesis() -> Header {
        BNetwork::Regtest.checkpoint().header
    }

    #[test]
    fn extends_and_links() {
        let mut c = HeaderChain::new(BNetwork::Regtest);
        let b = regtest_branch(&genesis(), 20, genesis().time, 1);
        let r = c.try_extend(0, &b, NOW);
        assert!(r.adopted && r.error.is_none() && r.reorg_depth == 0, "{r:?}");
        assert_eq!(c.tip_height(), 20);
        assert_eq!(c.hash_at(20), Some(b[19].block_hash()));
        // A header that names another parent stops the branch there.
        let mut more = regtest_branch(c.tip(), 3, c.tip().time, 1);
        more[1].prev_blockhash = BlockHash::all_zeros();
        let r = c.try_extend(20, &more, NOW);
        assert_eq!(r.error, Some(HeaderError::Linkage(22)));
        assert!(r.adopted, "the valid prefix still adds work");
        assert_eq!(c.tip_height(), 21);
    }

    #[test]
    fn refuses_missing_work_and_easy_targets() {
        let mut c = HeaderChain::new(BNetwork::Regtest);
        let mut b = regtest_branch(&genesis(), 2, genesis().time, 2);
        // A target that asks for real work, without the work.
        b[1].bits = CompactTarget::from_consensus(0x1d00_ffff);
        assert_eq!(c.try_extend(0, &b, NOW).error, Some(HeaderError::Pow(2)));
        let mut c = HeaderChain::new(BNetwork::Signet);
        let cp = BNetwork::Signet.checkpoint();
        let mut h = cp.header;
        h.prev_blockhash = cp.header.block_hash();
        h.time += 600;
        h.bits = CompactTarget::from_consensus(0x207f_ffff);
        assert_eq!(c.try_extend(cp.height, &[h], NOW).error, Some(HeaderError::TargetAboveLimit(cp.height + 1)));
    }

    #[test]
    fn the_most_work_chain_wins_and_ties_keep_ours() {
        let mut c = HeaderChain::new(BNetwork::Regtest);
        let main = regtest_branch(&genesis(), 10, genesis().time, 4);
        c.try_extend(0, &main, NOW);
        // Same length from height 7: equal work, no reorg.
        let fork = *c.header_at(7).unwrap();
        let tie = regtest_branch(&fork, 3, fork.time + 1, 5);
        assert!(!c.try_extend(7, &tie, NOW).adopted);
        assert_eq!(c.tip_hash(), main[9].block_hash());
        // One more block on the fork: it wins and replaces 8..10.
        let longer = regtest_branch(&fork, 4, fork.time + 1, 5);
        let r = c.try_extend(7, &longer, NOW);
        assert!(r.adopted);
        assert_eq!((r.reorg_depth, r.changed_from), (3, Some(8)));
        assert_eq!(r.replaced, vec![(8, main[7].block_hash()), (9, main[8].block_hash()), (10, main[9].block_hash())]);
        assert_eq!(c.tip_height(), 11);
        // A shorter chain can still win on work alone; regtest's equal targets make length decide.
        assert!(c.total_work() > Work::from_be_bytes([0; 32]));
    }

    #[test]
    fn a_branch_repeating_our_headers_is_no_reorg() {
        let mut c = HeaderChain::new(BNetwork::Regtest);
        let main = regtest_branch(&genesis(), 5, genesis().time, 6);
        c.try_extend(0, &main, NOW);
        let mut again = main[2..].to_vec();
        again.extend(regtest_branch(&main[4], 2, main[4].time, 6));
        let r = c.try_extend(2, &again, NOW);
        assert!(r.adopted);
        assert_eq!((r.reorg_depth, r.changed_from), (0, Some(6)));
    }

    #[test]
    fn median_time_past_and_future() {
        let mut c = HeaderChain::new(BNetwork::Regtest);
        let b = regtest_branch(&genesis(), 12, genesis().time, 7);
        c.try_extend(0, &b, NOW);
        let old = mine(c.tip(), c.header_at(7).unwrap().time, 7);
        assert_eq!(c.try_extend(12, &[old], NOW).error, Some(HeaderError::TimeTooOld(13)));
        let ahead = mine(c.tip(), NOW + MAX_FUTURE_SECS + 1, 7);
        assert_eq!(c.try_extend(12, &[ahead], NOW).error, Some(HeaderError::TimeTooNew(13)));
    }

    fn hdr(hex: &str) -> Header {
        bitcoin::consensus::encode::deserialize_hex(hex).unwrap()
    }

    #[test]
    fn mainnet_retargets_match_real_blocks() {
        // Heights 933,408 and 935,423 bound the period before the 935,424 retarget; 937,439 ends the next.
        let first = hdr("000010203678ebdbb5a6225d119f80d2c9112bc943fbb8377ffd0000000000000000000074e7a9b6da8edcb223b5927bc4e2b0cab66a4ea1b168bf415d49ed34ce9679220a7b7269a1fc01172e0df72d");
        let last = hdr("00601224fc9e74a767a73b762e2cea86c58004c27c510de5ed2f000000000000000000001e0914218dbf56d16c70396e0c813a2329b82b9fbd8b29d03e83e23fead9ff7457418769a1fc0117eaddfb48");
        let boundary = BNetwork::Mainnet.checkpoint().header;
        assert_eq!(expected_bits(BNetwork::Mainnet, &last, &first), boundary.bits);
        let next_last = hdr("00000020926a02c2442027e190252099af5b65ac1dd903e7746f00000000000000000000f5d88c0aad3639b04486711c4f0e0ef32eba078acda18a3fb00858f4342d25ef285b97697e3c02173e0707b8");
        let next_boundary = hdr("00a0d42ac4847b40eba6bca8f090aa8d4114054e727890daccd701000000000000000000d76cf2d8af47f7f993095f0f5fc61bcfa0dbf5918dc511d99f8f1031df7ab1d06b5c976903f30117aaa8b7fd");
        assert_eq!(expected_bits(BNetwork::Mainnet, &next_last, &boundary), next_boundary.bits);
        assert_ne!(boundary.bits, next_boundary.bits);
        // The real boundary passes the whole check; a header keeping the old bits does not.
        let below = |h: u32| (h == 933_408).then_some(first);
        assert_eq!(validate(BNetwork::Mainnet, 935_424, &last, &boundary, &below, NOW), Ok(()));
        let mut stale = boundary;
        stale.bits = last.bits;
        assert!(matches!(validate(BNetwork::Mainnet, 935_424, &last, &stale, &below, NOW), Err(HeaderError::Pow(_) | HeaderError::Retarget(_))));
        // Between retargets the bits must not move.
        let between = |_h: u32| None;
        assert_eq!(validate(BNetwork::Mainnet, 937_440, &next_last, &next_boundary, &between, NOW), Ok(()));
        assert_eq!(validate(BNetwork::Mainnet, 937_441, &next_last, &next_boundary, &between, NOW), Err(HeaderError::BitsChanged(937_441)));
    }

    #[test]
    fn restore_keeps_the_valid_prefix() {
        let b = regtest_branch(&genesis(), 6, genesis().time, 8);
        let mut stored: Vec<(u32, Header)> = b.iter().enumerate().map(|(i, h)| (i as u32 + 1, *h)).collect();
        stored[3].1.prev_blockhash = BlockHash::all_zeros();
        let c = HeaderChain::restore(BNetwork::Regtest, stored, NOW);
        assert_eq!(c.tip_height(), 3);
    }
}
