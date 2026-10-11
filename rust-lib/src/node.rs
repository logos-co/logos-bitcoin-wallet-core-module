//! The local node as the chain authority: `bitcoind_module`'s rpc(method, paramsJson) over Logos
//! IPC behind bitcoincore_rpc's RpcApi, followed with bdk_bitcoind_rpc's Emitter.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bdk_bitcoind_rpc::bitcoincore_rpc::{self, jsonrpc, RpcApi};
use bdk_bitcoind_rpc::Emitter;
use bdk_wallet::chain::keychain_txout::KeychainTxOutIndex;
use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, IndexedTxGraph, TxUpdate};
use bdk_wallet::KeychainKind;
use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{BlockHash, Transaction, Txid};
use serde_json::{json, Value};

use crate::authority::{Authority, Change, ChainAuthority};
use crate::checks::ChainView;
use crate::fees::{self, SourceEstimate};
use crate::network::BNetwork;

/// One call into the node's RPC table, as `bitcoind_module.rpc` makes it: `params` is a JSON
/// array, and the reply is Core's, `{"result": .., "error": null | {code, message}}`.
pub trait NodeRpc: Send + Sync {
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
            e => Err(Failure::Rpc { code: e["code"].as_i64().unwrap_or(0), message: e["message"].as_str().unwrap_or("refused").to_string() }),
        }
    }

    /// Mempool transactions can't be read while the module refuses getrawtransaction.
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
}

/// Whether the node runs `net` and is synced: past initial sync, its blocks at its headers.
pub fn status(c: &NodeClient, net: BNetwork) -> Result<NodeStatus, String> {
    let i = c.raw("getblockchaininfo", &[]).map_err(|e| e.to_string())?;
    let chain = i["chain"].as_str().unwrap_or_default();
    if chain != chain_name(net) {
        return Err(format!("the local node runs {chain}, not {}", chain_name(net)));
    }
    let n = |k: &str| i[k].as_u64().unwrap_or(0) as u32;
    let initial_sync = i["initialblockdownload"].as_bool().unwrap_or(true);
    let (blocks, headers) = (n("blocks"), n("headers"));
    Ok(NodeStatus { blocks, headers, initial_sync, synced: !initial_sync && blocks + 1 >= headers })
}

fn hash_at(c: &NodeClient, height: u32) -> Result<BlockHash, String> {
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
}

/// Follows the node: its headers into the authority's chain, its blocks and mempool for the wallet.
pub struct Follower {
    client: Arc<NodeClient>,
    emitter: Option<Emitter<Arc<NodeClient>>>,
    scanned: Option<(u32, BlockHash)>,
}

/// Headers fetched per call to `headers`: two calls each over IPC.
pub const HEADERS_PER_POLL: u32 = 2_000;
/// Blocks scanned per call to `scan`.
pub const BLOCKS_PER_POLL: usize = 500;

impl Follower {
    pub fn new(client: Arc<NodeClient>, scanned: Option<(u32, BlockHash)>) -> Self {
        Self { client, emitter: None, scanned }
    }

    pub fn client(&self) -> &Arc<NodeClient> {
        &self.client
    }

    /// Brings the authority's chain onto the node's, from their fork, up to `HEADERS_PER_POLL`.
    pub fn headers(&self, authority: &mut ChainAuthority, node_tip: u32, now: u32) -> Result<Change, String> {
        let base = authority.base_height();
        if node_tip < base {
            return Err(format!("the local node is at {node_tip}, below the wallet's checkpoint {base}"));
        }
        let mut fork = authority.chain().tip_height().min(node_tip);
        loop {
            if authority.hash_at(fork) == Some(hash_at(&self.client, fork)?) {
                break;
            }
            if fork == base {
                return Err("the local node's chain does not contain the wallet's checkpoint".into());
            }
            fork -= 1;
        }
        let end = node_tip.min(fork + HEADERS_PER_POLL);
        let mut branch = Vec::with_capacity((end - fork) as usize);
        for h in fork + 1..=end {
            branch.push(header_of(&self.client, &hash_at(&self.client, h)?)?);
        }
        Ok(authority.adopt(fork, &branch, now))
    }

    /// Scans blocks after the last one scanned, from `birthday`, then the mempool once at the tip.
    pub fn scan(&mut self, authority: &ChainAuthority, index: &KeychainTxOutIndex<KeychainKind>, expected: Vec<Arc<Transaction>>, birthday: u32) -> Result<Found, String> {
        let start = self.scanned.map_or(birthday, |(h, _)| h + 1).max(1);
        if self.emitter.is_none() {
            // The emitter finds its footing on the authority's hash below `start`, as the node holds it.
            let below = start - 1;
            let hash = authority.hash_at(below).ok_or_else(|| format!("no header at {below} yet"))?;
            let cp = CheckPoint::new(BlockId { height: below, hash });
            self.emitter = Some(Emitter::new(self.client.clone(), cp, start, expected));
        }
        let emitter = self.emitter.as_mut().expect("set above");
        let mut graph = IndexedTxGraph::<ConfirmationBlockTime, _>::new(index.clone());
        let mut found = Found::default();
        let mut blocks = 0;
        loop {
            if blocks == BLOCKS_PER_POLL {
                break;
            }
            match emitter.next_block().map_err(|e| format!("node: {e}"))? {
                Some(ev) => {
                    let (height, hash) = (ev.block_height(), ev.block_hash());
                    if authority.hash_at(height) != Some(hash) {
                        // The node moved past the headers just taken: the next poll takes them.
                        self.emitter = None;
                        break;
                    }
                    let _ = graph.apply_block_relevant(&ev.block, height);
                    self.scanned = Some((height, hash));
                    found.scanned = self.scanned;
                    blocks += 1;
                }
                None => {
                    found.at_tip = true;
                    break;
                }
            }
        }
        if found.at_tip {
            if let Some(e) = self.emitter.as_mut() {
                let m = e.mempool().map_err(|e| format!("node mempool: {e}"))?;
                let _ = graph.batch_insert_relevant_unconfirmed(m.update.into_iter().map(|(tx, at)| (tx, at)));
                found.evicted = m.evicted;
            }
        }
        found.last_active = graph.index.last_used_indices();
        found.tx_update = TxUpdate::from(graph.graph().clone());
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
    Ok(SourceEstimate { source: id.to_string(), rates, minimum })
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

    #[test]
    fn fees_come_in_sat_per_vbyte() {
        let (_, c) = canned(vec![("estimatesmartfee", json!({"feerate": 0.0002, "blocks": 2})), ("getnetworkinfo", json!({"relayfee": 0.00001}))]);
        let f = fees(&c, "local").unwrap();
        assert_eq!(f.rates, [Some(20.0), Some(20.0), Some(20.0)]);
        assert_eq!(f.minimum, Some(1.0));
    }
}
