//! The local node as the chain authority: `bitcoind_module`'s rpc(method, paramsJson) over Logos
//! IPC behind bitcoincore_rpc's RpcApi, followed with bdk_bitcoind_rpc's Emitter. A backlog is
//! scanned with the node's block filters; a pruned block that matches is asked of its peers.

use std::collections::{BTreeMap, VecDeque, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bdk_bitcoind_rpc::bitcoincore_rpc::{self, jsonrpc, RpcApi};
use bdk_bitcoind_rpc::Emitter;
use bdk_wallet::chain::keychain_txout::KeychainTxOutIndex;
use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, IndexedTxGraph, TxUpdate};
use bdk_wallet::KeychainKind;
use bitcoin::bip158::BlockFilter;
use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Block, BlockHash, ScriptBuf, Transaction, Txid};
use serde_json::{json, Value};

use crate::authority::{Authority, Change, ChainAuthority};
use crate::checks::ChainView;
use crate::fees::{self, SourceEstimate};
use crate::network::BNetwork;

/// One call into the node's RPC table, as `bitcoind_module.rpc` makes it: `params` is a JSON
/// array, and the reply is Core's, `{"result": .., "error": null | {code, message}}`.
pub trait NodeRpc: Send + Sync {
    fn remote(&self) -> bool { false }
    fn batch(&self, method: &str, params: &[Value]) -> Result<Vec<String>, String> {
        params.iter().map(|p| self.rpc(method, &p.to_string())).collect()
    }
    fn rpc(&self, method: &str, params: &str) -> Result<String, String>;
}

/// Why a call failed: the node's own refusal, or no answer at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    Rpc { code: i64, message: String },
    Transport(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Rpc { code, message } => write!(f, "{message} ({code})"),
            Failure::Transport(e) => write!(f, "{e}"),
        }
    }
}

/// JSON-RPC's "method not found", which bitcoind_module answers for methods off its allowlist.
const NOT_ALLOWED: i64 = -32601;
/// Core's "not found".
const NOT_FOUND: i64 = -5;

/// The node behind bitcoincore_rpc's RpcApi. Two methods the module doesn't allow are bridged:
/// getblockcount through getblockchaininfo, and getrawtransaction answers "not found".
pub struct NodeClient {
    rpc: Arc<dyn NodeRpc>,
    no_rawtx: AtomicBool,
}

impl NodeClient {
    pub fn new(rpc: Arc<dyn NodeRpc>) -> Self {
        Self { rpc, no_rawtx: AtomicBool::new(false) }
    }

    pub fn raw(&self, method: &str, params: &[Value]) -> Result<Value, Failure> {
        let reply = self.rpc.rpc(method, &Value::from(params.to_vec()).to_string()).map_err(Failure::Transport)?;
        let v: Value = serde_json::from_str(&reply).map_err(|e| Failure::Transport(format!("{method}: not JSON: {e}")))?;
        match &v["error"] {
            Value::Null => Ok(v["result"].clone()),
            e => {
                let message = e["message"].as_str().unwrap_or("refused");
                // Keep only the capability categories the scanner needs from a remote service.
                let message = if !self.remote() { message }
                    else if method == "getblockfilter" && message.contains("not enabled") { "block filter index not enabled" }
                    else if method == "getblock" && message.contains("pruned") { "block pruned" }
                    else if method == "getblockfrompeer" && message.contains("already") { "block already requested" }
                    else { "RPC request refused" };
                Err(Failure::Rpc { code: e["code"].as_i64().unwrap_or(0), message: message.to_string() })
            },
        }
    }

    fn batch(&self, method: &str, params: &[Value]) -> Result<Vec<Value>, String> {
        self.rpc.batch(method, params)?.iter().map(|s| {
            let v: Value = serde_json::from_str(s).map_err(|_| "RPC response is not JSON")?;
            if !v["error"].is_null() { return Err(format!("{method}: RPC error {}", v["error"]["code"])); }
            v.get("result").cloned().ok_or_else(|| "RPC result missing".into())
        }).collect()
    }

    /// Mempool transactions can't be read while the module refuses getrawtransaction.
    pub fn remote(&self) -> bool { self.rpc.remote() }

    pub fn reads_mempool(&self) -> bool {
        !self.no_rawtx.load(Ordering::SeqCst)
    }
}

fn rpc_error(code: i64, message: String) -> bitcoincore_rpc::Error {
    bitcoincore_rpc::Error::JsonRpc(jsonrpc::error::Error::Rpc(jsonrpc::error::RpcError { code: code as i32, message, data: None }))
}

impl RpcApi for NodeClient {
    fn call<T: for<'a> serde::de::Deserialize<'a>>(&self, cmd: &str, args: &[Value]) -> bitcoincore_rpc::Result<T> {
        let got = match cmd {
            "getblockcount" => self.raw("getblockchaininfo", &[]).map(|i| i["blocks"].clone()),
            "getrawtransaction" if self.no_rawtx.load(Ordering::SeqCst) => Err(Failure::Rpc { code: NOT_FOUND, message: "not available from bitcoind_module".into() }),
            _ => self.raw(cmd, args),
        };
        match got {
            Ok(v) => serde_json::from_value(v).map_err(bitcoincore_rpc::Error::Json),
            Err(Failure::Rpc { code: NOT_ALLOWED, message }) if cmd == "getrawtransaction" => {
                tracing::info!(target: "bitcoin", "node: {message}; pending payments come from servers only");
                self.no_rawtx.store(true, Ordering::SeqCst);
                Err(rpc_error(NOT_FOUND, message))
            }
            Err(Failure::Rpc { code, message }) => Err(rpc_error(code, message)),
            Err(Failure::Transport(e)) => Err(bitcoincore_rpc::Error::ReturnedError(e)),
        }
    }
}

/// Core's name for the chain of `net`.
pub fn chain_name(net: BNetwork) -> &'static str {
    match net {
        BNetwork::Mainnet => "main",
        BNetwork::Testnet4 => "testnet4",
        BNetwork::Signet => "signet",
        BNetwork::Regtest => "regtest",
    }
}

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    pub blocks: u32,
    pub headers: u32,
    pub initial_sync: bool,
    pub synced: bool,
    pub pruned: bool,
    /// The lowest block a pruned node still holds.
    pub prune_height: Option<u32>,
    /// Whether the node serves block filters; unknown until a scan asks.
    pub filters: Option<bool>,
    /// Blocks the filters matched this session, and those fetched from the node's peers.
    pub matched: u32,
    pub from_peers: u32,
    pub pruned_gap: Option<PrunedGap>,
    /// Scans started over from the birthday with a wider window, and the highest index the scan
    /// watches per keychain (external, internal).
    pub rescans: u32,
    pub pending_scan_remaining: usize,
    pub window: [u32; 2],
}

/// Matched blocks below a pruned node's prune height that neither it nor its peers gave.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrunedGap {
    /// Where the scan of the missing blocks started; `below` is the prune height.
    pub from: u32,
    pub below: u32,
    /// The heights the filters matched; empty when the node has no filters to say.
    pub heights: Vec<u32>,
    /// Who scanned them instead: a history server, `kyoto`, or nobody yet.
    pub via: Option<String>,
    pub resolved: bool,
}

/// Whether the node runs `net` and is synced: past initial sync, its blocks at its headers.
pub fn status(c: &NodeClient, net: BNetwork) -> Result<NodeStatus, String> {
    let i = c.raw("getblockchaininfo", &[]).map_err(|e| e.to_string())?;
    let chain = i["chain"].as_str().unwrap_or_default();
    if chain != chain_name(net) {
        return Err(format!("the Bitcoin Core node runs {chain}, not {}", chain_name(net)));
    }
    let n = |k: &str| i[k].as_u64().unwrap_or(0) as u32;
    let initial_sync = i["initialblockdownload"].as_bool().unwrap_or(true);
    let (blocks, headers) = (n("blocks"), n("headers"));
    let pruned = i["pruned"].as_bool().unwrap_or(false);
    let prune_height = i["pruneheight"].as_u64().filter(|_| pruned).map(|h| h as u32);
    Ok(NodeStatus { blocks, headers, initial_sync, synced: !initial_sync && blocks + 1 >= headers, pruned, prune_height, ..Default::default() })
}

pub(crate) fn hash_at(c: &NodeClient, height: u32) -> Result<BlockHash, String> {
    c.get_block_hash(u64::from(height)).map_err(|e| format!("getblockhash {height}: {e}"))
}

fn header_of(c: &NodeClient, hash: &BlockHash) -> Result<Header, String> {
    let hex = c.raw("getblockheader", &[json!(hash.to_string()), json!(false)]).map_err(|e| format!("getblockheader: {e}"))?;
    deserialize_hex(hex.as_str().unwrap_or_default()).map_err(|e| format!("getblockheader: {e}"))
}

/// The wallet's finds in the node's blocks and mempool, for the sync thread to apply.
#[derive(Debug, Default)]
pub struct Found {
    pub tx_update: TxUpdate<ConfirmationBlockTime>,
    pub last_active: BTreeMap<KeychainKind, u32>,
    pub evicted: Vec<(Txid, u64)>,
    /// The last block scanned for the wallet.
    pub scanned: Option<(u32, BlockHash)>,
    pub at_tip: bool,
    /// Matched blocks the pruned node no longer holds and its peers didn't send.
    pub missing: Vec<u32>,
    /// Blocks below the prune height left unscanned, without filters to say which matter: from, below.
    pub unscanned: Option<(u32, u32)>,
}

/// Follows the node: its headers into the authority's chain, its blocks and mempool for the wallet.
pub struct Follower {
    client: Arc<NodeClient>,
    emitter: Option<Emitter<Arc<NodeClient>>>,
    scanned: Option<(u32, BlockHash)>,
    /// The blocks scanned lately, to find where a reorg left the scan.
    recent: VecDeque<(u32, BlockHash)>,
    pub filters: Option<bool>,
    pub matched: u32,
    pub from_peers: u32,
    remote_seen: HashSet<Txid>,
    pub pending_scan_remaining: usize,
}

/// Headers fetched per call to `headers`: two calls each over IPC.
pub const HEADERS_PER_POLL: u32 = 2_000;
/// Blocks scanned per call to `scan`.
pub const BLOCKS_PER_POLL: usize = 500;
/// Filters read per call to `scan`: one call each, and a block's when it matches.
pub const FILTERS_PER_POLL: u32 = 1_000;
/// Further behind than this, filters lead and only matching blocks are read.
const FILTER_BACKLOG: u32 = 6;
const RECENT_KEPT: usize = 144;
/// How long a block asked of a peer has to arrive.
const PEER_WAIT: Duration = Duration::from_secs(20);

/// The scripts a filter is matched against: every one the index derived, the lookahead included.
fn watched(index: &KeychainTxOutIndex<KeychainKind>) -> Vec<ScriptBuf> {
    index.inner().all_spks().values().cloned().collect()
}

/// The wallet's index, deriving each keychain's scripts up to its revealed index plus `lookahead`
/// (the first `lookahead` when none is revealed): a scan watches every one of them.
pub fn widened(index: &KeychainTxOutIndex<KeychainKind>, lookahead: u32) -> KeychainTxOutIndex<KeychainKind> {
    let mut wide = index.clone();
    let revealed = wide.last_revealed_indices();
    for k in [KeychainKind::External, KeychainKind::Internal] {
        let top = revealed.get(&k).map_or(lookahead.saturating_sub(1), |r| r.saturating_add(lookahead));
        let _ = wide.lookahead_to_target(k, top);
    }
    wide
}

/// The highest index of each keychain (external, internal) that `index` derived.
pub fn window(index: &KeychainTxOutIndex<KeychainKind>) -> [u32; 2] {
    let top = |k: KeychainKind| index.inner().all_spks().range((k, 0)..=(k, u32::MAX)).next_back().map_or(0, |((_, i), _)| *i);
    [top(KeychainKind::External), top(KeychainKind::Internal)]
}

/// Peers that serve old blocks: NETWORK, not only NETWORK_LIMITED's last 288.
fn full_block_peers(peers: &Value) -> Vec<i64> {
    peers
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|p| p["servicesnames"].as_array().is_some_and(|s| s.iter().any(|n| n == "NETWORK")))
                .filter_map(|p| p["id"].as_i64())
                .collect()
        })
        .unwrap_or_default()
}

fn decode_block(v: &Value, hash: &BlockHash) -> Result<Block, String> {
    let block: Block = deserialize_hex(v.as_str().unwrap_or_default()).map_err(|e| format!("getblock: {e}"))?;
    if block.block_hash() != *hash || !block.check_merkle_root() {
        return Err(format!("block {hash} doesn't match its header"));
    }
    Ok(block)
}

impl Follower {
    pub fn new(client: Arc<NodeClient>, scanned: Option<(u32, BlockHash)>) -> Self {
        Self { client, emitter: None, scanned, recent: VecDeque::new(), filters: None, matched: 0, from_peers: 0, remote_seen: HashSet::new(), pending_scan_remaining: 0 }
    }

    fn mark(&mut self, height: u32, hash: BlockHash) {
        self.scanned = Some((height, hash));
        if self.recent.len() == RECENT_KEPT {
            self.recent.pop_front();
        }
        self.recent.push_back((height, hash));
    }

    /// After a reorg under the last block scanned: back to the newest scanned block still on the
    /// authority's chain, or `RECENT_KEPT` blocks down when none is.
    fn rewind(&mut self, authority: &ChainAuthority) {
        let Some((h, hash)) = self.scanned else { return };
        if authority.hash_at(h) == Some(hash) {
            return;
        }
        self.emitter = None;
        while let Some((rh, rhash)) = self.recent.pop_back() {
            if authority.hash_at(rh) == Some(rhash) {
                self.scanned = Some((rh, rhash));
                self.recent.push_back((rh, rhash));
                return;
            }
        }
        let back = h.saturating_sub(RECENT_KEPT as u32);
        self.scanned = authority.hash_at(back).map(|x| (back, x));
    }

    /// Whether the node has a filter index: `getblockfilter` answers for the block at `height`.
    /// An index still catching up is asked again next round.
    fn has_filters(&mut self, authority: &ChainAuthority, height: u32) -> bool {
        if let Some(f) = self.filters {
            return f;
        }
        let Some(hash) = authority.hash_at(height) else { return false };
        match self.client.raw("getblockfilter", &[json!(hash.to_string())]) {
            Ok(v) if v["filter"].is_string() => {
                self.filters = Some(true);
                true
            }
            Err(Failure::Rpc { code, message }) if code == NOT_ALLOWED || message.contains("not enabled") => {
                tracing::info!(target: "bitcoin", "node: no block filters ({message}); scanning whole blocks");
                self.filters = Some(false);
                false
            }
            _ => false,
        }
    }

    /// A block from the node's disk, or from one of its peers when it was pruned; `None` when no
    /// peer sends it in time.
    fn block(&mut self, hash: &BlockHash, stop: &AtomicBool) -> Result<Option<Block>, String> {
        let get = |c: &NodeClient| c.raw("getblock", &[json!(hash.to_string()), json!(0)]);
        match get(&self.client) {
            Ok(v) => return decode_block(&v, hash).map(Some),
            Err(Failure::Rpc { message, .. }) if message.contains("pruned") => {}
            Err(e) => return Err(format!("getblock {hash}: {e}")),
        }
        let peers = self.client.raw("getpeerinfo", &[]).map_err(|e| format!("getpeerinfo: {e}"))?;
        for id in full_block_peers(&peers) {
            // The node asks a peer it is already connected to, so its own proxy setting holds.
            match self.client.raw("getblockfrompeer", &[json!(hash.to_string()), json!(id)]) {
                Ok(_) => {}
                Err(Failure::Rpc { message, .. }) if message.contains("already") => {}
                Err(e) => {
                    tracing::info!(target: "bitcoin", "node: getblockfrompeer from peer {id}: {e}");
                    continue;
                }
            }
            let until = Instant::now() + PEER_WAIT;
            while Instant::now() < until && !stop.load(Ordering::SeqCst) {
                if let Ok(v) = get(&self.client) {
                    self.from_peers += 1;
                    return decode_block(&v, hash).map(Some);
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        Ok(None)
    }

    /// Scans up to `FILTERS_PER_POLL` blocks from `start` with the node's filters, reading only the
    /// blocks they match.
    fn scan_filters(&mut self, authority: &ChainAuthority, index: &KeychainTxOutIndex<KeychainKind>, start: u32, end: u32, stop: &AtomicBool) -> Result<Found, String> {
        let mut graph = IndexedTxGraph::<ConfirmationBlockTime, _>::new(index.clone());
        let mut spks = watched(&graph.index);
        let mut found = Found::default();
        let end = end.min(start + if self.client.remote() { 64 } else { FILTERS_PER_POLL } - 1);
        let filters = if self.client.remote() {
            let params: Result<Vec<_>, String> = (start..=end).map(|h| authority.hash_at(h).map(|hash| json!([hash.to_string()])).ok_or_else(|| format!("no header at {h}"))).collect();
            Some(self.client.batch("getblockfilter", &params?)?)
        } else { None };
        for h in start..=end {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let hash = authority.hash_at(h).ok_or_else(|| format!("no header at {h} yet"))?;
            let f = match filters.as_ref().map(|v| Ok(v[(h-start) as usize].clone())).unwrap_or_else(|| self.client.raw("getblockfilter", &[json!(hash.to_string())])) {
                Ok(f) => f,
                Err(e) => {
                    // The index hasn't reached it yet: this round ends here, the next goes on.
                    tracing::info!(target: "bitcoin", "node: getblockfilter {h}: {e}; waiting for the filter index");
                    break;
                }
            };
            let content = hex::decode(f["filter"].as_str().unwrap_or_default()).map_err(|e| format!("getblockfilter {h}: {e}"))?;
            if BlockFilter::new(&content).match_any(&hash, spks.iter().map(|s| s.as_bytes())).map_err(|e| format!("filter {h}: {e}"))? {
                self.matched += 1;
                match self.block(&hash, stop)? {
                    Some(block) => {
                        let _ = graph.apply_block_relevant(&block, h);
                        spks = watched(&graph.index);
                    }
                    None => found.missing.push(h),
                }
            }
            self.mark(h, hash);
            found.scanned = self.scanned;
        }
        found.last_active = graph.index.last_used_indices();
        found.tx_update = TxUpdate::from(graph.graph().clone());
        Ok(found)
    }

    pub fn client(&self) -> &Arc<NodeClient> {
        &self.client
    }

    /// Brings the authority's chain onto the node's, from their fork, up to `HEADERS_PER_POLL`.
    pub fn headers(&self, authority: &mut ChainAuthority, node_tip: u32, now: u32) -> Result<Change, String> {
        let base = authority.base_height();
        if node_tip < base {
            return Err(format!("the Bitcoin Core node is at {node_tip}, below the wallet's checkpoint {base}"));
        }
        let mut fork = authority.chain().tip_height().min(node_tip);
        loop {
            if authority.hash_at(fork) == Some(hash_at(&self.client, fork)?) {
                break;
            }
            if fork == base {
                return Err("the Bitcoin Core node's chain does not contain the wallet's checkpoint".into());
            }
            fork -= 1;
        }
        let end = node_tip.min(fork + if self.client.remote() { 128 } else { HEADERS_PER_POLL });
        let mut branch = Vec::with_capacity((end - fork) as usize);
        if self.client.remote() && end > fork {
            let params: Vec<_> = (fork+1..=end).map(|h| json!([h])).collect();
            let hashes = self.client.batch("getblockhash", &params)?;
            let params: Vec<_> = hashes.iter().map(|h| json!([h, false])).collect();
            for (raw, hash) in self.client.batch("getblockheader", &params)?.iter().zip(hashes.iter()) {
                let header: Header = deserialize_hex(raw.as_str().ok_or("RPC header is not hex")?).map_err(|e| e.to_string())?;
                if header.block_hash().to_string() != hash.as_str().unwrap_or_default() { return Err("RPC header hash mismatch".into()); }
                branch.push(header);
            }
        } else {
            for h in fork + 1..=end { branch.push(header_of(&self.client, &hash_at(&self.client, h)?)?); }
        }
        Ok(authority.adopt(fork, &branch, now))
    }

    /// Scans blocks after the last one scanned, from `birthday`, then the mempool once at the tip.
    /// A backlog goes by the node's filters when it has them. Without them, a pruned node's
    /// missing blocks are skipped and reported as `unscanned`.
    pub fn scan(&mut self, authority: &ChainAuthority, index: &KeychainTxOutIndex<KeychainKind>, expected: Vec<Arc<Transaction>>, birthday: u32, prune_height: Option<u32>, stop: &AtomicBool) -> Result<Found, String> {
        self.rewind(authority);
        let mut start = self.scanned.map_or(birthday, |(h, _)| h + 1).max(1);
        let tip = authority.chain().tip_height();
        if tip >= start + FILTER_BACKLOG && self.has_filters(authority, start) {
            // A backlog, as after the node was away: filters, and a fresh Emitter at the tip.
            self.emitter = None;
            return self.scan_filters(authority, index, start, tip, stop);
        }
        let mut unscanned = None;
        if let Some(p) = prune_height.filter(|p| self.emitter.is_none() && start < *p) {
            let hash = authority.hash_at(p - 1).ok_or_else(|| format!("no header at {} yet", p - 1))?;
            unscanned = Some((start, p));
            self.mark(p - 1, hash);
            start = p;
        }
        if self.emitter.is_none() {
            // The emitter finds its footing on the authority's hash below `start`, as the node holds
            // it. Its start height is that block's too: past the node's tip it would fail to start.
            let below = start - 1;
            let hash = authority.hash_at(below).ok_or_else(|| format!("no header at {below} yet"))?;
            let cp = CheckPoint::new(BlockId { height: below, hash });
            self.emitter = Some(Emitter::new(self.client.clone(), cp, below, expected.clone()));
        }
        let emitter = self.emitter.as_mut().expect("set above");
        let mut graph = IndexedTxGraph::<ConfirmationBlockTime, _>::new(index.clone());
        let mut found = Found::default();
        let mut emitted = vec![];
        let mut ahead = false;
        loop {
            if stop.load(Ordering::SeqCst) || emitted.len() == if self.client.remote() { 2 } else { BLOCKS_PER_POLL } {
                break;
            }
            match emitter.next_block().map_err(|e| format!("node: {e}"))? {
                Some(ev) => {
                    let (height, hash) = (ev.block_height(), ev.block_hash());
                    // The emitter names the hash it asked for: the block must be that one, whole.
                    if ev.block.block_hash() != hash || !ev.block.check_merkle_root() {
                        self.emitter = None;
                        return Err(format!("block {hash} at {height} doesn't match its header"));
                    }
                    if authority.hash_at(height) != Some(hash) {
                        // The node moved past the headers just taken: the next poll takes them.
                        ahead = true;
                        break;
                    }
                    let _ = graph.apply_block_relevant(&ev.block, height);
                    emitted.push((height, hash));
                }
                None => {
                    found.at_tip = true;
                    break;
                }
            }
        }
        if ahead {
            self.emitter = None;
        }
        if !emitted.is_empty() || unscanned.is_some() {
            for (height, hash) in emitted {
                self.mark(height, hash);
            }
            found.scanned = self.scanned;
        }
        if found.at_tip && !stop.load(Ordering::SeqCst) {
            if self.client.remote() {
                // A public node can have a large mempool. Scan bounded batches, never one
                // blocking Emitter pass over every transaction. Check every returned txid.
                let pool = self.client.get_raw_mempool().map_err(|_| "RPC mempool unavailable")?;
                let current: HashSet<_> = pool.iter().copied().collect();
                self.remote_seen.retain(|id| current.contains(id));
                let pending: Vec<_> = pool.iter().filter(|id| !self.remote_seen.contains(*id)).copied().collect();
                let ids: Vec<_> = pending.iter().take(32).copied().collect();
                let params: Vec<_> = ids.iter().map(|id| json!([id.to_string(), false])).collect();
                let replies = self.client.rpc.batch("getrawtransaction", &params)?;
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let mut txs = vec![];
                for (id, reply) in ids.iter().zip(replies) {
                    let v: Value = serde_json::from_str(&reply).map_err(|_| "invalid RPC transaction reply")?;
                    if v["error"]["code"] == -5 { continue; } // mined/evicted between the two calls
                    if !v["error"].is_null() { return Err("RPC mempool transaction unavailable".into()); }
                    let tx: Transaction = deserialize_hex(v["result"].as_str().ok_or("RPC transaction is not hex")?).map_err(|_| "invalid RPC transaction")?;
                    if tx.compute_txid() != *id { return Err("RPC transaction ID mismatch".into()); }
                    txs.push((tx, now));
                    self.remote_seen.insert(*id);
                }
                self.pending_scan_remaining = current.len().saturating_sub(self.remote_seen.len());
                let _ = graph.batch_insert_relevant_unconfirmed(txs);
                found.evicted = expected.iter().map(|tx| tx.compute_txid()).filter(|id| !current.contains(id)).map(|id| (id, now)).collect();
            } else if let Some(e) = self.emitter.as_mut() {
                let m = e.mempool().map_err(|e| format!("node mempool: {e}"))?;
                let _ = graph.batch_insert_relevant_unconfirmed(m.update.into_iter().map(|(tx, at)| (tx, at)));
                found.evicted = m.evicted;
            }
        }
        found.last_active = graph.index.last_used_indices();
        found.tx_update = TxUpdate::from(graph.graph().clone());
        found.unscanned = unscanned;
        Ok(found)
    }
}

/// sendrawtransaction: `Ok` once the node holds it; its refusal names why.
pub fn broadcast(c: &NodeClient, tx: &Transaction) -> Result<(), String> {
    match c.raw("sendrawtransaction", &[json!(serialize_hex(tx))]) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// estimatesmartfee for the targets, and the node's relay floor, in sat/vB.
pub fn fees(c: &NodeClient, id: &str) -> Result<SourceEstimate, String> {
    let mut rates = [None; 3];
    for (i, t) in fees::TARGETS.iter().enumerate() {
        let r = c.raw("estimatesmartfee", &[json!(t)]).map_err(|e| e.to_string())?;
        rates[i] = r["feerate"].as_f64().and_then(fees::from_btc_per_kb);
    }
    let minimum = c.raw("getnetworkinfo", &[]).ok().and_then(|n| n["relayfee"].as_f64()).and_then(fees::from_btc_per_kb);
    Ok(SourceEstimate { source: id.to_string(), rates, minimum, basis: fees::Basis::Estimate })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Answers like bitcoind_module: its allowlist, then canned replies.
    struct Canned {
        calls: Mutex<Vec<String>>,
        replies: BTreeMap<&'static str, Value>,
    }

    impl NodeRpc for Canned {
        fn rpc(&self, method: &str, params: &str) -> Result<String, String> {
            self.calls.lock().unwrap().push(format!("{method} {params}"));
            if method == "getrawtransaction" || method == "getblockcount" {
                return Ok(json!({"result": null, "error": {"code": -32601, "message": format!("method not allowed: {method}")}}).to_string());
            }
            Ok(match self.replies.get(method) {
                Some(r) => json!({"result": r, "error": null}).to_string(),
                None => json!({"result": null, "error": {"code": -8, "message": "boom"}}).to_string(),
            })
        }
    }

    fn canned(replies: Vec<(&'static str, Value)>) -> (Arc<Canned>, NodeClient) {
        let c = Arc::new(Canned { calls: Mutex::default(), replies: replies.into_iter().collect() });
        (c.clone(), NodeClient::new(c))
    }

    #[test]
    fn the_rpc_bridge_maps_replies_and_bridges_two_methods() {
        let info = json!({"chain": "regtest", "blocks": 120, "headers": 120, "initialblockdownload": false});
        let (log, c) = canned(vec![("getblockchaininfo", info)]);
        assert_eq!(c.get_block_count().unwrap(), 120, "getblockcount through getblockchaininfo");
        let st = status(&c, BNetwork::Regtest).unwrap();
        assert!(st.synced && st.blocks == 120);
        assert!(status(&c, BNetwork::Mainnet).unwrap_err().contains("regtest"));
        // The module's refusal of getrawtransaction reads as "not found", once, then isn't asked again.
        use bdk_bitcoind_rpc::BitcoindRpcErrorExt;
        use bitcoin::hashes::Hash;
        let e = c.get_raw_transaction(&Txid::all_zeros(), None).unwrap_err();
        assert!(e.is_not_found_error() && !c.reads_mempool());
        let asked = log.calls.lock().unwrap().iter().filter(|l| l.starts_with("getrawtransaction")).count();
        assert!(c.get_raw_transaction(&Txid::all_zeros(), None).unwrap_err().is_not_found_error());
        assert_eq!(log.calls.lock().unwrap().iter().filter(|l| l.starts_with("getrawtransaction")).count(), asked);
        // Other errors keep Core's code and message.
        match c.call::<Value>("getmempoolentry", &[json!("x")]) {
            Err(bitcoincore_rpc::Error::JsonRpc(jsonrpc::error::Error::Rpc(r))) => assert_eq!((r.code, r.message.as_str()), (-8, "boom")),
            other => panic!("{other:?}"),
        }
        assert!(log.calls.lock().unwrap().iter().any(|l| l == "getmempoolentry [\"x\"]"), "params go as a JSON array");
    }

    #[test]
    fn a_node_in_initial_sync_is_not_the_authority() {
        let (_, c) = canned(vec![("getblockchaininfo", json!({"chain": "main", "blocks": 900_000, "headers": 935_000, "initialblockdownload": true}))]);
        let st = status(&c, BNetwork::Mainnet).unwrap();
        assert!(!st.synced && st.initial_sync);
        let (_, c) = canned(vec![("getblockchaininfo", json!({"chain": "main", "blocks": 935_000, "headers": 935_001, "initialblockdownload": false}))]);
        assert!(status(&c, BNetwork::Mainnet).unwrap().synced, "one block behind its headers is synced");
    }

    /// A regtest chain of `n` blocks, one of them paying `to` at height `pay_at`, served as a
    /// pruned node with filters would: blocks in `pruned` come back only once a peer sent them.
    struct Pruned {
        blocks: Vec<Block>,
        pruned: Mutex<std::collections::HashSet<BlockHash>>,
        peers_send: bool,
        asked: Mutex<Vec<String>>,
    }

    impl Pruned {
        fn new(n: u32, pay_at: u32, to: ScriptBuf, prune_below: u32, peers_send: bool) -> Self {
            use bitcoin::hashes::Hash;
            let mut blocks = vec![bitcoin::constants::genesis_block(bitcoin::Network::Regtest)];
            for h in 1..=n {
                let coinbase = Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: bitcoin::absolute::LockTime::ZERO,
                    input: vec![bitcoin::TxIn { script_sig: bitcoin::script::Builder::new().push_int(i64::from(h)).into_script(), ..Default::default() }],
                    output: vec![bitcoin::TxOut { value: bitcoin::Amount::from_sat(50), script_pubkey: ScriptBuf::new_op_return([h as u8]) }],
                };
                let mut txdata = vec![coinbase];
                if h == pay_at {
                    txdata.push(Transaction {
                        version: bitcoin::transaction::Version::TWO,
                        lock_time: bitcoin::absolute::LockTime::ZERO,
                        input: vec![bitcoin::TxIn { previous_output: bitcoin::OutPoint { txid: Txid::from_byte_array([7; 32]), vout: 0 }, ..Default::default() }],
                        output: vec![bitcoin::TxOut { value: bitcoin::Amount::from_sat(40_000), script_pubkey: to.clone() }],
                    });
                }
                let prev = blocks.last().unwrap().header;
                let mut header = bitcoin::block::Header { version: prev.version, prev_blockhash: prev.block_hash(), merkle_root: bitcoin::TxMerkleNode::all_zeros(), time: prev.time + 600, bits: prev.bits, nonce: 0 };
                let mut block = Block { header, txdata };
                header.merkle_root = block.compute_merkle_root().unwrap();
                while header.validate_pow(header.target()).is_err() {
                    header.nonce += 1;
                }
                block.header = header;
                blocks.push(block);
            }
            let pruned = blocks.iter().take(prune_below as usize).map(|b| b.block_hash()).collect();
            Self { blocks, pruned: Mutex::new(pruned), peers_send, asked: Mutex::default() }
        }

        fn by_hash(&self, hash: &str) -> Option<&Block> {
            self.blocks.iter().find(|b| b.block_hash().to_string() == hash)
        }
    }

    impl NodeRpc for Pruned {
        fn rpc(&self, method: &str, params: &str) -> Result<String, String> {
            self.asked.lock().unwrap().push(format!("{method} {params}"));
            let p: Value = serde_json::from_str(params).unwrap();
            let ok = |v: Value| Ok(json!({"result": v, "error": null}).to_string());
            let err = |code: i64, m: &str| Ok(json!({"result": null, "error": {"code": code, "message": m}}).to_string());
            let block = p[0].as_str().and_then(|h| self.by_hash(h));
            match (method, block) {
                ("getblockfilter", Some(b)) => {
                    let f = BlockFilter::new_script_filter(b, |_| Ok::<_, bitcoin::bip158::Error>(ScriptBuf::new_op_return([0u8]))).unwrap();
                    ok(json!({"filter": hex::encode(f.content), "header": "00".repeat(32)}))
                }
                ("getblock", Some(b)) if self.pruned.lock().unwrap().contains(&b.block_hash()) => err(-1, "Block not available (pruned data)"),
                ("getblock", Some(b)) => ok(json!(serialize_hex(b))),
                ("getpeerinfo", _) => ok(json!([{"id": 3, "servicesnames": ["NETWORK_LIMITED", "WITNESS"]}, {"id": 7, "servicesnames": ["NETWORK", "WITNESS"]}])),
                ("getblockfrompeer", Some(b)) if self.peers_send && p[1] == 7 => {
                    self.pruned.lock().unwrap().remove(&b.block_hash());
                    ok(json!({}))
                }
                ("getblockfrompeer", _) => err(-1, "Peer does not exist"),
                _ => err(-8, "unexpected"),
            }
        }
    }

    /// The wallet's index and an authority holding `chain`'s headers.
    fn wallet_and_authority(chain: &Pruned) -> (KeychainTxOutIndex<KeychainKind>, ChainAuthority) {
        let x = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
        let w = bdk_wallet::Wallet::create(format!("wpkh([73c5da0a/84'/1'/0']{x}/0/*)"), format!("wpkh([73c5da0a/84'/1'/0']{x}/1/*)"))
            .network(bitcoin::Network::Regtest)
            .create_wallet_no_persist()
            .unwrap();
        let headers = chain.blocks.iter().enumerate().skip(1).map(|(h, b)| (h as u32, b.header)).collect();
        (w.spk_index().clone(), ChainAuthority::restore(BNetwork::Regtest, BNetwork::Regtest.checkpoint(), headers, vec![], 2_000_000_000))
    }

    fn wallet_script() -> ScriptBuf {
        let x = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
        let mut w = bdk_wallet::Wallet::create(format!("wpkh([73c5da0a/84'/1'/0']{x}/0/*)"), format!("wpkh([73c5da0a/84'/1'/0']{x}/1/*)"))
            .network(bitcoin::Network::Regtest)
            .create_wallet_no_persist()
            .unwrap();
        // An address past the first, within the lookahead.
        w.reveal_next_address(KeychainKind::External);
        w.reveal_next_address(KeychainKind::External).script_pubkey()
    }

    #[test]
    fn a_filter_scan_reads_only_matching_blocks_and_asks_peers_for_pruned_ones() {
        let chain = Arc::new(Pruned::new(12, 3, wallet_script(), 6, true));
        let (index, authority) = wallet_and_authority(&chain);
        let mut f = Follower::new(Arc::new(NodeClient::new(chain.clone())), None);
        let found = f.scan(&authority, &index, vec![], 1, Some(6), &AtomicBool::new(false)).unwrap();
        assert_eq!(found.scanned.map(|s| s.0), Some(12), "the backlog to the tip by filters");
        assert_eq!((f.filters, f.matched, f.from_peers, found.missing.clone()), (Some(true), 1, 1, vec![]));
        let paid = chain.blocks[3].txdata[1].compute_txid();
        assert!(found.tx_update.txs.iter().any(|t| t.compute_txid() == paid));
        assert!(found.tx_update.anchors.iter().any(|(a, t)| *t == paid && a.block_id.height == 3));
        let asked = chain.asked.lock().unwrap().clone();
        let n = |m: &str| asked.iter().filter(|l| l.starts_with(&format!("{m} "))).count();
        assert_eq!(n("getblock"), 2, "the pruned block, then the copy its peer sent: {asked:?}");
        assert!(asked.iter().any(|l| l.starts_with("getblockfrompeer") && l.ends_with(",7]")), "the full node, not the NETWORK_LIMITED one");
        assert!(!asked.iter().any(|l| l.starts_with("getblockfrompeer") && l.ends_with(",3]")));
    }

    #[test]
    fn a_pruned_block_no_peer_sends_is_reported_missing() {
        let chain = Arc::new(Pruned::new(12, 3, wallet_script(), 6, false));
        let (index, authority) = wallet_and_authority(&chain);
        let mut f = Follower::new(Arc::new(NodeClient::new(chain.clone())), None);
        let found = f.scan(&authority, &index, vec![], 1, Some(6), &AtomicBool::new(false)).unwrap();
        assert_eq!((found.missing.clone(), found.scanned.map(|s| s.0)), (vec![3], Some(12)), "the scan goes on past it");
        assert!(found.tx_update.txs.is_empty());
        // After a reorg under the last block scanned, the scan resumes below it.
        let (_, other) = wallet_and_authority(&Pruned::new(12, 0, wallet_script(), 0, false));
        f.rewind(&other);
        assert!(f.scanned.is_none_or(|(h, _)| h < 12), "{:?}", f.scanned);
    }

    #[test]
    fn a_payment_past_the_lookahead_is_found_once_the_scan_watches_further() {
        let x = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
        let w = bdk_wallet::Wallet::create(format!("wpkh([73c5da0a/84'/1'/0']{x}/0/*)"), format!("wpkh([73c5da0a/84'/1'/0']{x}/1/*)"))
            .network(bitcoin::Network::Regtest)
            .create_wallet_no_persist()
            .unwrap();
        let far = w.peek_address(KeychainKind::External, 40).script_pubkey();
        let chain = Arc::new(Pruned::new(12, 3, far, 0, true));
        let (index, authority) = wallet_and_authority(&chain);
        assert_eq!(window(&index), [24, 24], "a fresh wallet derives its first 25 of each keychain");
        let found = Follower::new(Arc::new(NodeClient::new(chain.clone())), None).scan(&authority, &index, vec![], 1, None, &AtomicBool::new(false)).unwrap();
        assert!(found.tx_update.txs.is_empty(), "index 40 is past what the wallet watches");
        let wide = widened(&index, 60);
        assert_eq!(window(&wide), [59, 59]);
        let found = Follower::new(Arc::new(NodeClient::new(chain.clone())), None).scan(&authority, &wide, vec![], 1, None, &AtomicBool::new(false)).unwrap();
        assert_eq!(found.tx_update.txs.len(), 1, "a wider scan finds it");
        assert_eq!(found.last_active.get(&KeychainKind::External), Some(&40));
    }

    #[test]
    fn fees_come_in_sat_per_vbyte() {
        let (_, c) = canned(vec![("estimatesmartfee", json!({"feerate": 0.0002, "blocks": 2})), ("getnetworkinfo", json!({"relayfee": 0.00001}))]);
        let f = fees(&c, "local").unwrap();
        assert_eq!(f.rates, [Some(20.0), Some(20.0), Some(20.0)]);
        assert_eq!(f.minimum, Some(1.0));
    }
}
