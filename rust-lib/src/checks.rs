//! What a server's answer passes before BDK sees it. BDK's graph only grows, so an anchor once
//! applied stays; one left out only shows as unconfirmed, so dropping is always safe.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use bdk_wallet::chain::{ConfirmationBlockTime, TxUpdate};
use bdk_wallet::KeychainKind;
use bitcoin::block::Header;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{BlockHash, Txid};

/// A server's unconfirmed payment that no server has reported for this long is dropped, as Core's
/// mempool drops one.
pub const PENDING_EXPIRY_SECS: u64 = 14 * 24 * 60 * 60;

/// The gap limit: how many unused addresses past the last used one are watched.
pub const GAP_LIMIT: u32 = 20;

/// The chain authority, as the checks see it.
pub trait ChainView {
    /// `None` while the authority has made no progress: nothing confirms then.
    fn tip_height(&self) -> Option<u32>;
    /// The first header the authority holds, its checkpoint.
    fn base_height(&self) -> u32;
    /// The authority's block at `height`, or a hash below the checkpoint proved by linkage.
    fn hash_at(&self, height: u32) -> Option<BlockHash>;
    fn header_at(&self, height: u32) -> Option<Header>;
    /// Whether a reorg recently took this block off the authority's chain.
    fn replaced(&self, _height: u32, _hash: BlockHash) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorVerdict {
    /// On the authority's chain.
    Keep,
    /// Above the authority's tip: checked again when it catches up; pending meanwhile.
    Hold,
    /// Another block at that height: dropped, and the source is suspect.
    Drop,
    /// A block a reorg just replaced: the source is behind, not lying. Dropped without blame.
    Stale,
    /// Below the checkpoint: kept only once the server's headers link up to it.
    NeedsLinkage,
}

pub fn judge_anchor(view: &dyn ChainView, height: u32, hash: BlockHash) -> AnchorVerdict {
    let Some(tip) = view.tip_height() else { return AnchorVerdict::Hold };
    if height > tip {
        return AnchorVerdict::Hold;
    }
    match view.hash_at(height) {
        Some(h) if h == hash => AnchorVerdict::Keep,
        Some(_) if view.replaced(height, hash) => AnchorVerdict::Stale,
        Some(_) => AnchorVerdict::Drop,
        None if height < view.base_height() => AnchorVerdict::NeedsLinkage,
        None => AnchorVerdict::Hold,
    }
}

/// What screening found, for the source ledger and the held-anchor store.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Screened {
    pub kept: Vec<(Txid, ConfirmationBlockTime)>,
    pub held: Vec<(Txid, ConfirmationBlockTime)>,
    pub dropped: Vec<(Txid, ConfirmationBlockTime)>,
    /// Anchors in blocks a reorg just replaced: the source lags, the anchor waits for a fresh one.
    pub stale: Vec<(Txid, ConfirmationBlockTime)>,
    pub needs_linkage: Vec<(Txid, ConfirmationBlockTime)>,
    /// Transactions whose bytes did not hash to the txid they were asked for.
    pub tx_mismatches: Vec<Txid>,
    /// Transactions nothing in the answer refers to.
    pub strays: Vec<Txid>,
    pub evictions_dropped: usize,
    pub pending_stripped: usize,
}

impl Screened {
    /// Anything here marks the source suspect.
    pub fn suspect(&self) -> bool {
        !self.dropped.is_empty() || !self.tx_mismatches.is_empty()
    }
}

/// Screens an answer in place. `mismatched`: requested txid → what its bytes hash to; `known`: the
/// wallet holds it already. Without `takes_pending`, the source's unconfirmed transactions go.
pub fn screen(
    update: &mut TxUpdate<ConfirmationBlockTime>,
    view: &dyn ChainView,
    mismatched: &HashMap<Txid, Txid>,
    known: &dyn Fn(&Txid) -> bool,
    takes_pending: bool,
) -> Screened {
    let mut out = Screened::default();

    // Bytes that hash to something else were never the transaction asked for.
    let bad_bytes: HashSet<Txid> = mismatched.values().copied().collect();
    let bad_ids: HashSet<Txid> = mismatched.keys().copied().collect();
    update.txs.retain(|tx| !bad_bytes.contains(&tx.compute_txid()));
    out.tx_mismatches = bad_ids.iter().copied().collect();
    out.tx_mismatches.sort();

    // Each sync marks what a server didn't return as evicted; with failover that would flicker.
    out.evictions_dropped = update.evicted_ats.len();
    update.evicted_ats.clear();

    let present: HashSet<Txid> = update.txs.iter().map(|tx| tx.compute_txid()).collect();
    let referenced: HashSet<Txid> =
        update.anchors.iter().map(|(_, t)| *t).chain(update.seen_ats.iter().map(|(t, _)| *t)).collect();
    // A transaction with nothing pointing at it would sit in the graph forever, unexplained.
    let strays: Vec<Txid> = present.iter().filter(|t| !referenced.contains(*t) && !known(t)).copied().collect();
    update.txs.retain(|tx| !strays.contains(&tx.compute_txid()));
    out.strays = strays;
    let holds = |t: &Txid| (present.contains(t) && !bad_ids.contains(t)) || known(t);

    let anchors = std::mem::take(&mut update.anchors);
    let mut kept = BTreeSet::new();
    for (anchor, txid) in anchors {
        if !holds(&txid) {
            continue;
        }
        match judge_anchor(view, anchor.block_id.height, anchor.block_id.hash) {
            AnchorVerdict::Keep => {
                out.kept.push((txid, anchor));
                kept.insert((anchor, txid));
            }
            AnchorVerdict::Hold => out.held.push((txid, anchor)),
            AnchorVerdict::Drop => out.dropped.push((txid, anchor)),
            AnchorVerdict::Stale => out.stale.push((txid, anchor)),
            AnchorVerdict::NeedsLinkage => out.needs_linkage.push((txid, anchor)),
        }
    }
    update.anchors = kept;

    let before = update.seen_ats.len();
    update.seen_ats.retain(|(t, _)| holds(t) && takes_pending);
    out.pending_stripped = before - update.seen_ats.len();
    // A doctored transaction's outputs say nothing either.
    update.txouts.retain(|op, _| !bad_ids.contains(&op.txid));
    out
}

/// The highest address index a full scan may reveal: the revealed index plus the gap limit, or
/// higher only where a checked transaction pays the address.
pub fn cap_last_active(claimed: u32, revealed: Option<u32>, proven: Option<u32>, gap: u32) -> u32 {
    let allowed = revealed.map_or(gap.saturating_sub(1), |r| r.saturating_add(gap));
    claimed.min(allowed.max(proven.unwrap_or(0)))
}

pub fn cap_indices(
    claimed: &BTreeMap<KeychainKind, u32>,
    revealed: impl Fn(KeychainKind) -> Option<u32>,
    proven: impl Fn(KeychainKind) -> Option<u32>,
) -> BTreeMap<KeychainKind, u32> {
    claimed.iter().map(|(k, c)| (*k, cap_last_active(*c, revealed(*k), proven(*k), GAP_LIMIT))).collect()
}

/// Walks a Merkle branch from `txid` at `pos` up to the root it proves.
pub fn merkle_root(txid: Txid, pos: usize, branch: &[[u8; 32]]) -> [u8; 32] {
    let mut cur = txid.to_byte_array();
    let mut idx = pos;
    for sibling in branch {
        let mut buf = [0u8; 64];
        if idx & 1 == 1 {
            buf[..32].copy_from_slice(sibling);
            buf[32..].copy_from_slice(&cur);
        } else {
            buf[..32].copy_from_slice(&cur);
            buf[32..].copy_from_slice(sibling);
        }
        cur = sha256d::Hash::hash(&buf).to_byte_array();
        idx >>= 1;
    }
    cur
}

/// Electrum sends each sibling in display byte order; the tree hashes them reversed.
pub fn electrum_branch(branch: &[[u8; 32]]) -> Vec<[u8; 32]> {
    branch
        .iter()
        .map(|b| {
            let mut x = *b;
            x.reverse();
            x
        })
        .collect()
}

/// The tree depth for `tx_count` transactions: every leaf of Bitcoin's tree sits this deep.
pub fn tree_depth(tx_count: u64) -> usize {
    let mut depth = 0;
    while (1u64 << depth) < tx_count {
        depth += 1;
    }
    depth
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerdict {
    Valid,
    /// The branch doesn't lead to the authority's merkle root.
    WrongRoot,
    /// A branch of the wrong length: the 64-byte-transaction trick, or a garbled proof.
    WrongDepth,
}

/// Checks a proof against the authority's header and the block's true depth.
pub fn check_proof(txid: Txid, pos: usize, branch: &[[u8; 32]], header: &Header, depth: usize) -> ProofVerdict {
    if branch.len() != depth || (depth < usize::BITS as usize && pos >= (1usize << depth)) {
        return ProofVerdict::WrongDepth;
    }
    if merkle_root(txid, pos, branch) != header.merkle_root.to_byte_array() {
        return ProofVerdict::WrongRoot;
    }
    ProofVerdict::Valid
}

/// Unconfirmed transactions no server has reported for `PENDING_EXPIRY_SECS`.
pub fn expired(pending: impl IntoIterator<Item = (Txid, Option<u64>)>, now: u64) -> Vec<Txid> {
    pending
        .into_iter()
        .filter(|(_, seen)| seen.is_none_or(|s| now.saturating_sub(s) > PENDING_EXPIRY_SECS))
        .map(|(t, _)| t)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use bdk_wallet::chain::BlockId;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness};

    struct View {
        base: u32,
        tip: Option<u32>,
        hashes: BTreeMap<u32, BlockHash>,
        replaced: Vec<(u32, BlockHash)>,
    }

    impl ChainView for View {
        fn tip_height(&self) -> Option<u32> {
            self.tip
        }
        fn base_height(&self) -> u32 {
            self.base
        }
        fn hash_at(&self, height: u32) -> Option<BlockHash> {
            self.hashes.get(&height).copied()
        }
        fn header_at(&self, _height: u32) -> Option<Header> {
            None
        }
        fn replaced(&self, height: u32, hash: BlockHash) -> bool {
            self.replaced.contains(&(height, hash))
        }
    }

    fn bh(n: u8) -> BlockHash {
        BlockHash::from_byte_array([n; 32])
    }

    fn view() -> View {
        View { base: 100, tip: Some(110), hashes: (100..=110).map(|h| (h, bh(h as u8))).collect(), replaced: vec![(105, bh(205))] }
    }

    fn tx(salt: u8) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([salt; 32]), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1_000 + salt as u64), script_pubkey: ScriptBuf::new() }],
        }
    }

    fn anchor(height: u32, hash: BlockHash) -> ConfirmationBlockTime {
        ConfirmationBlockTime { block_id: BlockId { height, hash }, confirmation_time: 0 }
    }

    #[test]
    fn anchors_match_hold_drop_or_need_linkage() {
        let v = view();
        assert_eq!(judge_anchor(&v, 105, bh(105)), AnchorVerdict::Keep);
        assert_eq!(judge_anchor(&v, 105, bh(1)), AnchorVerdict::Drop);
        assert_eq!(judge_anchor(&v, 105, bh(205)), AnchorVerdict::Stale, "a block a reorg just replaced");
        assert_eq!(judge_anchor(&v, 111, bh(111)), AnchorVerdict::Hold, "above the tip waits");
        assert_eq!(judge_anchor(&v, 50, bh(50)), AnchorVerdict::NeedsLinkage, "below the checkpoint");
        let none = View { base: 100, tip: None, hashes: BTreeMap::new(), replaced: vec![] };
        assert_eq!(judge_anchor(&none, 105, bh(105)), AnchorVerdict::Hold, "no authority: nothing confirms");
        // A hash proved by linkage below the checkpoint counts like any other.
        let mut v = view();
        v.hashes.insert(50, bh(50));
        assert_eq!(judge_anchor(&v, 50, bh(50)), AnchorVerdict::Keep);
        assert_eq!(judge_anchor(&v, 50, bh(51)), AnchorVerdict::Drop);
    }

    #[test]
    fn screening_sorts_every_anchor_and_drops_doctored_bytes() {
        let (a, b, c, d) = (tx(1), tx(2), tx(3), tx(4));
        let (ta, tb, tc, td) = (a.compute_txid(), b.compute_txid(), c.compute_txid(), d.compute_txid());
        let doctored = tx(9);
        let mut u = TxUpdate::<ConfirmationBlockTime>::default();
        u.txs = vec![Arc::new(a), Arc::new(b), Arc::new(c), Arc::new(doctored.clone())];
        u.anchors.insert((anchor(105, bh(105)), ta));
        u.anchors.insert((anchor(106, bh(7)), tb));
        u.anchors.insert((anchor(120, bh(120)), tc));
        // The server answered td's request with other bytes.
        u.anchors.insert((anchor(107, bh(107)), td));
        u.seen_ats.insert((td, 5));
        u.evicted_ats.insert((ta, 9));
        u.txouts.insert(OutPoint { txid: td, vout: 0 }, TxOut::NULL);
        let mismatched = HashMap::from([(td, doctored.compute_txid())]);
        let s = screen(&mut u, &view(), &mismatched, &|_| false, true);
        assert_eq!(s.kept.len(), 1);
        assert_eq!(s.dropped, vec![(tb, anchor(106, bh(7)))]);
        assert_eq!(s.held, vec![(tc, anchor(120, bh(120)))]);
        assert_eq!(s.tx_mismatches, vec![td]);
        assert!(s.suspect());
        assert_eq!(s.evictions_dropped, 1);
        assert!(u.evicted_ats.is_empty());
        assert_eq!(u.anchors.len(), 1);
        assert!(u.txs.iter().all(|t| t.compute_txid() != doctored.compute_txid()));
        assert!(u.seen_ats.is_empty() && u.txouts.is_empty());
    }

    #[test]
    fn strays_and_phantoms_are_left_out() {
        let (a, stray) = (tx(1), tx(2));
        let ta = a.compute_txid();
        let phantom = tx(3).compute_txid();
        let mut u = TxUpdate::<ConfirmationBlockTime>::default();
        u.txs = vec![Arc::new(a), Arc::new(stray.clone())];
        u.seen_ats.insert((ta, 5));
        u.anchors.insert((anchor(105, bh(105)), phantom));
        let s = screen(&mut u, &view(), &HashMap::new(), &|_| false, true);
        assert_eq!(s.strays, vec![stray.compute_txid()]);
        assert_eq!(u.txs.len(), 1);
        assert!(u.anchors.is_empty(), "an anchor for bytes nobody sent is not kept");
        // An anchor for a transaction the wallet already holds is fine.
        let mut u = TxUpdate::<ConfirmationBlockTime>::default();
        u.anchors.insert((anchor(105, bh(105)), phantom));
        screen(&mut u, &view(), &HashMap::new(), &|t| *t == phantom, true);
        assert_eq!(u.anchors.len(), 1);
    }

    #[test]
    fn a_source_not_trusted_for_pending_reports_none() {
        let a = tx(1);
        let ta = a.compute_txid();
        let mut u = TxUpdate::<ConfirmationBlockTime>::default();
        u.txs = vec![Arc::new(a)];
        u.seen_ats.insert((ta, 5));
        u.anchors.insert((anchor(105, bh(105)), ta));
        let s = screen(&mut u, &view(), &HashMap::new(), &|_| false, false);
        assert_eq!((s.pending_stripped, u.seen_ats.len(), u.anchors.len()), (1, 0, 1));
    }

    #[test]
    fn address_indices_are_capped() {
        assert_eq!(cap_last_active(1_000_000, Some(4), None, GAP_LIMIT), 24);
        assert_eq!(cap_last_active(1_000_000, None, None, GAP_LIMIT), 19, "nothing revealed: one gap");
        assert_eq!(cap_last_active(7, Some(4), None, GAP_LIMIT), 7, "within the gap stays");
        assert_eq!(cap_last_active(1_000_000, Some(4), Some(90), GAP_LIMIT), 90, "a paid address counts");
        let claimed = BTreeMap::from([(KeychainKind::External, 1_000_000), (KeychainKind::Internal, 3)]);
        let capped = cap_indices(&claimed, |k| (k == KeychainKind::External).then_some(10), |_| None);
        assert_eq!(capped[&KeychainKind::External], 30);
        assert_eq!(capped[&KeychainKind::Internal], 3);
    }

    /// A block's merkle tree, built the way Bitcoin builds it.
    fn tree(leaves: &[Txid]) -> (Vec<Vec<[u8; 32]>>, [u8; 32]) {
        let mut levels = vec![leaves.iter().map(|t| t.to_byte_array()).collect::<Vec<_>>()];
        while levels.last().unwrap().len() > 1 {
            let cur = levels.last().unwrap().clone();
            let mut next = vec![];
            for pair in cur.chunks(2) {
                let (l, r) = (pair[0], *pair.get(1).unwrap_or(&pair[0]));
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&l);
                buf[32..].copy_from_slice(&r);
                next.push(sha256d::Hash::hash(&buf).to_byte_array());
            }
            levels.push(next);
        }
        let root = levels.last().unwrap()[0];
        (levels, root)
    }

    fn branch(levels: &[Vec<[u8; 32]>], mut pos: usize) -> Vec<[u8; 32]> {
        let mut out = vec![];
        for level in &levels[..levels.len() - 1] {
            let sib = pos ^ 1;
            out.push(*level.get(sib).unwrap_or(&level[pos]));
            pos >>= 1;
        }
        out
    }

    fn header_with_root(root: [u8; 32]) -> Header {
        let mut h = crate::network::BNetwork::Regtest.checkpoint().header;
        h.merkle_root = TxMerkleNode::from_byte_array(root);
        h
    }

    #[test]
    fn proofs_must_reach_the_authoritys_root_at_the_true_depth() {
        let leaves: Vec<Txid> = (1..=5u8).map(|i| tx(i).compute_txid()).collect();
        let (levels, root) = tree(&leaves);
        let header = header_with_root(root);
        let depth = tree_depth(5);
        assert_eq!(depth, 3);
        for (pos, t) in leaves.iter().enumerate() {
            assert_eq!(check_proof(*t, pos, &branch(&levels, pos), &header, depth), ProofVerdict::Valid);
        }
        // Against another block's root.
        assert_eq!(check_proof(leaves[1], 1, &branch(&levels, 1), &header_with_root([0; 32]), depth), ProofVerdict::WrongRoot);
        // One level short or long: the shape of the 64-byte-transaction trick.
        let mut long = branch(&levels, 1);
        long.push([7; 32]);
        assert_eq!(check_proof(leaves[1], 1, &long, &header, depth), ProofVerdict::WrongDepth);
        assert_eq!(check_proof(leaves[1], 1, &branch(&levels, 1)[1..], &header, depth), ProofVerdict::WrongDepth);
        assert_eq!(check_proof(leaves[1], 9, &branch(&levels, 1), &header, depth), ProofVerdict::WrongDepth);
        assert_eq!((tree_depth(1), tree_depth(2), tree_depth(3), tree_depth(4096), tree_depth(4097)), (0, 1, 2, 12, 13));
    }

    #[test]
    fn pending_payments_expire_after_fourteen_days_unseen() {
        let now = 30 * 24 * 3600;
        let (a, b, c) = (tx(1).compute_txid(), tx(2).compute_txid(), tx(3).compute_txid());
        let gone = expired([(a, Some(now - 15 * 24 * 3600)), (b, Some(now - 3600)), (c, None)], now);
        assert_eq!(gone, vec![a, c]);
    }
}
