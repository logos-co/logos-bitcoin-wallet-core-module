//! The header chain behind the server-only chain authority: linkage, proof of work against each
//! header's own target, mainnet retargets, testnet4's (BIP94), median time past, and the most-work
//! rule. Signet is held to each header's own target only.

use bitcoin::block::Header;
use bitcoin::pow::{CompactTarget, Work};
use bitcoin::BlockHash;

use crate::network::BNetwork;

/// Headers further than this ahead of the local clock are refused, as Core does.
const MAX_FUTURE_SECS: u32 = 2 * 60 * 60;
const RETARGET_INTERVAL: u32 = 2016;
/// BIP94: a retarget block may not be earlier than the block before it by more than this.
const MAX_TIMEWARP: i64 = 600;
/// Testnet: a block more than twice this after the one before may be at the minimum difficulty.
const TARGET_SPACING: u32 = 600;

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
    #[error("header {0} does not carry the difficulty testnet4 requires")]
    Difficulty(u32),
    #[error("header {0} is a retarget earlier than the block before it by more than 10 minutes")]
    Timewarp(u32),
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

/// Testnet4's difficulty (BIP94) for `next` at `height`: past 20 minutes without a block, the
/// minimum; else the last bits not set by that exception, walking back no further than a retarget.
/// A retarget scales the bits of its period's first block, which the exception never touches.
/// `None` when the headers it needs are below the checkpoint.
pub fn testnet4_bits(height: u32, prev: &Header, next: &Header, below: &dyn Fn(u32) -> Option<Header>) -> Option<CompactTarget> {
    let params = BNetwork::Testnet4.params();
    if height % RETARGET_INTERVAL != 0 {
        let limit = params.max_attainable_target.to_compact_lossy();
        if next.time > prev.time.saturating_add(2 * TARGET_SPACING) {
            return Some(limit);
        }
        let (mut at, mut h) = (height - 1, *prev);
        while at % RETARGET_INTERVAL != 0 && h.bits == limit {
            at -= 1;
            h = below(at)?;
        }
        return Some(h.bits);
    }
    let first = below(height - RETARGET_INTERVAL)?;
    let timespan = (i64::from(prev.time) - i64::from(first.time)).max(0) as u64;
    Some(CompactTarget::from_next_work_required(first.bits, timespan, params))
}

/// BIP94's timewarp rule: a retarget block no more than 10 minutes before the block below it.
pub fn timewarp_ok(height: u32, prev: &Header, next: &Header) -> bool {
    height % RETARGET_INTERVAL != 0 || i64::from(next.time) >= i64::from(prev.time) - MAX_TIMEWARP
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
    } else if net == BNetwork::Testnet4 {
        if testnet4_bits(height, prev, next, below).is_some_and(|bits| bits != next.bits) {
            return Err(if height % RETARGET_INTERVAL == 0 { HeaderError::Retarget(height) } else { HeaderError::Difficulty(height) });
        }
        if !timewarp_ok(height, prev, next) {
            return Err(HeaderError::Timewarp(height));
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

    /// Rebuilds a stored chain, keeping only the valid prefix from the network's checkpoint.
    pub fn restore(net: BNetwork, stored: impl IntoIterator<Item = (u32, Header)>, now: u32) -> Self {
        Self::restore_from(net, net.checkpoint(), stored, now)
    }

    /// Rebuilds a stored chain from `cp`, keeping only the valid prefix.
    pub fn restore_from(net: BNetwork, cp: crate::network::Checkpoint, stored: impl IntoIterator<Item = (u32, Header)>, now: u32) -> Self {
        let mut chain = Self::from_checkpoint(net, cp.height, cp.header);
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

    /// Testnet4 headers 118,944, 120,959 to 120,979 and 122,975 to 122,977, from mempool.space over Tor.
    fn testnet4(height: u32) -> Header {
        let hex = match height {
            118_944 => "00a0c6254a08224d7389194f2f2bd58fb3c39c197833a44611a9fb0a57dee902000000000baf15703be9f11fbbf8f9991a411e97052ddee259580ad6cdf29525d76cd73cb5c56b692b5402196463a255",
            120_959 => "0000002013ddb4d2a359edd286f4101223d7b0b822ea7c11cd567cb8b248960600000000b9c8d651c5bb8a077d7ae11b2d54da93e6b0dcc0ea6d1a21e58c0acff6729f5fd8717e69ffff001d81ca5a00",
            120_960 => "0040072b448834989d56b70d72388871849609144c9fb50d5ed9790f3059130d00000000e4f0f4dc786d90874f0725a2dbaab85497c7d138ec6596f3e8f9ceb9f43120ba806f7e691f5b0219651c56da",
            120_961 => "00002a2207f681669e8d3a782c8982a277173df960e7eecccc26e49301000000000000004628063c28ee255597ed550620d9e7e254537ebc65f7953cee22fc0779b72f7831747e69ffff001d94014edd",
            120_962 => "00e0ff3f94203b079ac970d6bffd79940da0af1e3b9912424abf19562207e00c0000000012b616154cc917208ac8c64442d7a0d55892306cfcd287ba6e20c4edb5cfde0fe2787e69ffff001d1cc5ca96",
            120_963 => "00e00020e9692510cbcdbc6dccdcfeb495f2da88acf1386c944da9f15357490f000000003cce56bceb7d857c1c94f16e912d812cc3f0bfe35b990bada06b8b476c04757b937d7e69ffff001dd3c7a8bc",
            120_964 => "00000020e536bf2e66df57bc0aa2ac66a16c230adc443a55645f380fcc715b05000000001dd7513876c059637cecbf6115fc5e02fc1091f3f907959d50e63ef70404cdf844827e69ffff001db94a312b",
            120_965 => "00e000200db4df7f668bd3d4b9ab93fd166463c0b2268f02d01b83c820c4810d0000000098c51a0dda33631fe0f4cfced283b382c9dac0ba2f303921b0554b7e1a200320f5867e69ffff001d428bba6b",
            120_966 => "0000b125f8d7001d4c57d1988fe599ad430dc11770d1da0662a04fa7886f290500000000dd9a35fcd16ffafaa4ed6928ac4adfc8d681dc86e2b133c004d401cb714c080e59797e691f5b0219442f84a1",
            120_967 => "00a0a4209978121333f77e77849e6d5a6c424710656f7cd74077370d0000000000000000d159fef2f4016a937f545c763772c39e7f64af96b42ad9e3f5c4f24bd0cc7ecf0a7e7e69ffff001dd20246d3",
            120_968 => "00006b208a045905e6f711bc1979732579d237b6191ed5a5de76c977c79c350300000000c7b5a8cc6081c60fd9585d0353a51324db6522e2602c1a30ef818439b2432042bb827e69ffff001da40196a3",
            120_969 => "002034217519f2ac39e82923c258b0a2c2258d45f2a7874d8c00014c99eb64010000000082f9b604998af25934a031adaa286d6ed95ebdd38292ba54119c772df22a15876c877e69ffff001d4202bf03",
            120_970 => "00000020cd21b5cdb40bf39db25422ad45ac643c1eff5418f24275a6168b59070000000007b12184f010ca90c84f5c6d5cddc0c1b3fa20a65413ef76be54b9fd4970c4881d8c7e69ffff001d48cb3d6a",
            120_971 => "0020a3204226beaf677a6e041804ad2a21287935631dbf9ded55040703c21b09000000005e0fb8c1d193f646601364e505cb3e6db251c724f00bb34a7745eb914ccac4a80b7e7e691f5b0219a0febb55",
            120_972 => "00c086206154cab7836d1f47b864df0fe7a29203f0947bfe5fdc72890000000000000000f9d5371bd0391c63b1b2abb81f66309112ded0dbe5b9ef5120712fde643fbc3fbc827e69ffff001d220222cc",
            120_973 => "0080c822f253003256b276988cd560c06b8d032703ce46023871814509f6700a000000005fd02869d824e3cd7d5aa7cce53a8e8b20876fa8abe4d914c62076f38859d3b46d877e69ffff001dec003c88",
            120_974 => "00e04020e4709bd4c383e2e20be637902ef10b03d73b74a997160d3c46ac410c00000000491d9ca9a34958c82de6bae527646b945e39fdbf46277f97d43f5c4299ac5d971e8c7e69ffff001d8a035e9e",
            120_975 => "0000ff3f982e58241e2831b148679967fa364b136fd007f72416998b7cddea0a0000000071c48d99cf1a28b13bd9e718871be54074d89d8f06289cef1e9431d505cb083ccf907e69ffff001d8208cba7",
            120_976 => "0000002030d8e1028b0139e2cf21e27ec9cda3cd4906bf7d19ee44503d913708000000005e6c3e49b7a1e98898015ca7b0d3876f3ee248fcfc9bd7393c1fa1f44ad2fa2880957e69ffff001d31470968",
            120_977 => "0080b728710109060437332e014abad87b31617baf7fe121e1e1b6e1c215d00b00000000add9b831ee3f0a988bb1896d4a04bf1a60d07351f335e570912102643dfa879d6d877e691f5b0219903c4333",
            120_978 => "00e0c52049acc4e596ae376ba744c53456b7c2daea69a596d04e472802000000000000005bb77f34d2a6dbcabd81b89eee73da8aedc04fc3fd9cbf92eae77764b66b605d1e8c7e69ffff001dae0376d3",
            120_979 => "0040c220dc6957f342381e7bf93837a9eb8a4d768fa527219b5957347cbcea0100000000d128312ef1f999b403448bc43a4daf468c3e692ca203c8330910d5b0a18f8a7acf907e69ffff001d28035745",
            122_975 => "00e00020497aa21b132f0130ba030dd267d1e0f37ff833bb09315836829cf30f0000000052eef1f25b952cdc4831d70e9396794ce05d890d4a13116acbc5e141c641bb16179d9769ffff001d1f41bd26",
            122_976 => "00a08620cd59688ed04bb1da87cc1f43ea9b88268fee0228abb2d8d1c929da04000000008680fbb086f90dce92ff7cf96094014f22ef25cf3415b59b80e826276a3b02b44af49769be36031918456614",
            122_977 => "00400121786021919e274e99c319dc9b5724c0d57005d7501f4f4e2800000000000000003db8dc9c57b3cd0094ca250b437430c955a0e2c40474e3980a7ba1bbf0c87596fbf89769ffff001de8030657",
            _ => panic!("no testnet4 header at {height}"),
        };
        hdr(hex)
    }

    #[test]
    fn testnet4_retargets_from_the_periods_first_block() {
        let t4 = BNetwork::Testnet4;
        let (first, last, boundary) = (testnet4(120_960), testnet4(122_975), testnet4(122_976));
        assert_eq!(boundary.prev_blockhash, last.block_hash());
        // 122,975 is a minimum-difficulty block: scaling its bits, the old rule, misses the retarget.
        assert_eq!(last.bits, t4.params().max_attainable_target.to_compact_lossy());
        assert_ne!(expected_bits(t4, &last, &first), boundary.bits);
        let below = |h: u32| (h == 120_960).then_some(first);
        assert_eq!(testnet4_bits(122_976, &last, &boundary, &below), Some(boundary.bits));
        assert_eq!(validate(t4, 122_976, &last, &boundary, &below, NOW), Ok(()));
        // Without the period's first block (below the checkpoint) the retarget isn't judged.
        assert_eq!(testnet4_bits(122_976, &last, &boundary, &|_| None), None);
        let mut wrong = boundary;
        wrong.bits = first.bits;
        assert_ne!(testnet4_bits(122_976, &last, &wrong, &below), Some(wrong.bits));
        // The retarget before, at 120,960, from 118,944's bits; it is also at the timewarp limit.
        let (first, last, boundary) = (testnet4(118_944), testnet4(120_959), testnet4(120_960));
        let below = |h: u32| (h == 118_944).then_some(first);
        assert_ne!(first.bits, boundary.bits);
        assert_eq!(testnet4_bits(120_960, &last, &boundary, &below), Some(boundary.bits));
        assert_eq!(validate(t4, 120_960, &last, &boundary, &below, NOW), Ok(()));
    }

    #[test]
    fn testnet4_minimum_difficulty_exception() {
        let t4 = BNetwork::Testnet4;
        let limit = t4.params().max_attainable_target.to_compact_lossy();
        assert_eq!(limit, CompactTarget::from_consensus(0x1d00_ffff));
        let below = |h: u32| (120_959..=120_979).contains(&h).then(|| testnet4(h));
        // 20 minutes and a second after 120,960: 120,961 is at the minimum difficulty, as it must be.
        assert_eq!(testnet4(120_961).time - testnet4(120_960).time, 1201);
        assert_eq!(testnet4_bits(120_961, &testnet4(120_960), &testnet4(120_961), &below), Some(limit));
        // Sooner than that: the last bits not set by the exception. 120,966 walks back over five
        // minimum-difficulty blocks to the retarget at 120,960; 120,971 to 120,966, between retargets.
        assert_eq!(testnet4_bits(120_966, &testnet4(120_965), &testnet4(120_966), &below), Some(testnet4(120_960).bits));
        assert_eq!(testnet4_bits(120_971, &testnet4(120_970), &testnet4(120_971), &below), Some(testnet4(120_966).bits));
        // A walk that reaches below the checkpoint judges nothing.
        assert_eq!(testnet4_bits(120_966, &testnet4(120_965), &testnet4(120_966), &|h| (h >= 120_963).then(|| testnet4(h))), None);
        // Bits that differ from the walk's are refused, minimum or not.
        let other = |h: u32| if h == 120_963 { Some(Header { bits: CompactTarget::from_consensus(0x1902_542b), ..testnet4(h) }) } else { below(h) };
        assert_eq!(validate(t4, 120_966, &testnet4(120_965), &testnet4(120_966), &other, NOW), Err(HeaderError::Difficulty(120_966)));
        let mut cheap = testnet4(120_966);
        cheap.bits = limit;
        assert_eq!(testnet4_bits(120_966, &testnet4(120_965), &cheap, &below), Some(testnet4(120_960).bits), "no exception without the 20 minutes");
        // The real chain passes whole, from 120,959.
        let mut c = HeaderChain::from_checkpoint(t4, 120_959, testnet4(120_959));
        let branch: Vec<Header> = (120_960..=120_979).map(testnet4).collect();
        let r = c.try_extend(120_959, &branch, NOW);
        assert_eq!((r.error, c.tip_height()), (None, 120_979));
    }

    #[test]
    fn testnet4_timewarp_rule() {
        // 120,960 is exactly 10 minutes earlier than 120,959: the most BIP94 allows.
        let (prev, boundary) = (testnet4(120_959), testnet4(120_960));
        assert_eq!(i64::from(prev.time) - i64::from(boundary.time), MAX_TIMEWARP);
        assert!(timewarp_ok(120_960, &prev, &boundary));
        let early = Header { time: boundary.time - 1, ..boundary };
        assert!(!timewarp_ok(120_960, &prev, &early));
        // Only retarget blocks: between them, the median time past is the rule.
        assert!(timewarp_ok(120_961, &prev, &early));
        assert_eq!(validate(BNetwork::Testnet4, 120_960, &prev, &boundary, &|_| None, NOW), Ok(()));
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
