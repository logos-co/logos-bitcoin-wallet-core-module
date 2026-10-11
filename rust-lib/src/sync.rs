//! The open wallet's sync thread: it moves the chain from the authority only (the local node,
//! Kyoto, or the Electrum header chain), and applies what the authority finds and what a history
//! server reports, after the checks. Network calls never hold the wallet lock.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bdk_electrum::electrum_client::ElectrumApi;
use bdk_electrum::BdkElectrumClient;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::chain::keychain_txout::{FullScanRequestBuilderExt, SyncRequestBuilderExt};
use bdk_wallet::chain::spk_client::{FullScanRequest, SyncRequest};
use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::{KeychainKind, Update};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, ScriptBuf, Txid};
use parking_lot::Mutex;
use serde_json::{json, Value};

use crate::authority::{self, Authority, ChainAuthority, Change, ElectrumHeaders, HeaderSource, ELECTRUM_HEADERS, KYOTO, LOCAL_NODE};
use crate::checks::{self, ChainView, ProofVerdict};
use crate::crosscheck::{self, Answer, Verdict};
use crate::fees::{self, SourceEstimate};
use crate::kyoto::{self, Feed, PeerBook, Start};
use crate::ledger::Ledger;
use crate::net::{self, Checked};
use crate::network::{BNetwork, Family};
use crate::node::{self, Follower, NodeClient, NodeRpc};
use crate::routes::{Isolation, Kind, Routes, Source};
use crate::storage::{meta_get, meta_set};
use crate::wallet::{Cell, Held};
use crate::walletdir::now_secs;

pub type Electrum = BdkElectrumClient<Checked<net::Conn>>;

/// Alerts and state changes the engine turns into events.
pub enum Note {
    State,
    Alert { source: String, kind: &'static str, detail: String },
}

pub type Notify = Arc<dyn Fn(Note) + Send + Sync>;

/// Where routes come from: `bitcoin_node_module` over IPC, or nothing on regtest.
pub trait RouteSource: Send + Sync {
    fn route_table(&self, network: &str) -> Result<String, String>;
    /// Tells the node module a source served something false. Best effort.
    fn report_mismatch(&self, _network: &str, _source: &str, _kind: &str, _height: Option<u32>) {}
    /// An Esplora server's `(username, password)`, held by the node module, never stored here.
    fn source_credentials(&self, _network: &str, _source: &str) -> Result<Option<(String, String)>, String> {
        Ok(None)
    }
}

/// What the sync thread shares with readers and with send jobs.
#[derive(Default)]
pub struct NetState {
    pub routes: Routes,
    pub ledger: Ledger,
    pub iso: HashMap<String, Isolation>,
    /// Who feeds the chain: local_node, kyoto or electrum_headers.
    pub chain_by: &'static str,
    /// The running Kyoto client, for broadcasts.
    pub kyoto: Option<bdk_kyoto::Requester>,
}

impl NetState {
    pub fn iso(&mut self, id: &str) -> Isolation {
        self.iso.entry(id.to_string()).or_insert_with(Isolation::fresh).clone()
    }
}

/// Kyoto's state for `status`.
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KyotoStatus {
    pub running: bool,
    pub phase: &'static str,
    /// Kyoto's header height, and the share of filter headers and filters done.
    pub height: u32,
    pub progress: f32,
    pub connected: usize,
    pub dialled: usize,
    pub skipped: usize,
    pub restarts: u32,
    pub rebuilds: u32,
    pub last_warning: Option<String>,
    pub last_stop: Option<String>,
}

/// Figures for `status`, written by the sync thread.
#[derive(Default, Clone)]
pub struct Progress {
    pub authority: authority::Summary,
    pub synced_tip: Option<u32>,
    pub last_history_sync: Option<u64>,
    pub history_server: Option<String>,
    pub fees: Option<fees::FeeRates>,
    pub last_error: Option<String>,
    pub full_scan_done: bool,
    pub kyoto: Option<KyotoStatus>,
    pub node: Option<node::NodeStatus>,
}

pub struct Ctx {
    pub net: BNetwork,
    pub family: Family,
    pub birthday: u32,
    pub cell: Arc<Mutex<Option<Cell>>>,
    pub netstate: Arc<Mutex<NetState>>,
    pub progress: Arc<Mutex<Progress>>,
    pub stop: Arc<AtomicBool>,
    pub wake: Arc<AtomicBool>,
    pub reload_routes: Arc<AtomicBool>,
    pub notify: Notify,
    pub rt: tokio::runtime::Handle,
    pub routes_src: Option<Arc<dyn RouteSource>>,
    /// `bitcoind_module`'s rpc, for the local node.
    pub node_src: Option<Arc<dyn NodeRpc>>,
}

const ROUTES_EVERY: Duration = Duration::from_secs(300);
const FEES_EVERY: Duration = Duration::from_secs(300);
const EXPIRY_EVERY: Duration = Duration::from_secs(600);

/// Who feeds the chain this round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Feeder {
    Servers,
    Kyoto,
    Node,
}

/// What Kyoto or the node found for the wallet in blocks and the mempool.
struct Found {
    source: &'static str,
    tx_update: TxUpdate<ConfirmationBlockTime>,
    last_active: BTreeMap<KeychainKind, u32>,
    evicted: Vec<(Txid, u64)>,
    /// The meta key and the last block whose filters or contents were scanned.
    scanned: Option<(&'static str, (u32, BlockHash))>,
}

const KYOTO_SCANNED: &str = "kyoto_scanned";
const NODE_SCANNED: &str = "node_scanned";
const KYOTO_PEERS: &str = "kyoto_peers";
/// The local node is asked whether it is synced this often while it isn't the authority.
const NODE_PROBE_EVERY: Duration = Duration::from_secs(30);
/// Kyoto's restarts back off up to this, while starts make no progress.
const KYOTO_RETRY_MAX: Duration = Duration::from_secs(120);

struct Loop {
    ctx: Ctx,
    authority: ChainAuthority,
    feeder: Feeder,
    kyoto: Option<kyoto::Client>,
    kyoto_book: PeerBook,
    kyoto_retry_at: Instant,
    kyoto_backoff: Duration,
    kyoto_status: KyotoStatus,
    /// The headers-only phase of a first start: the rescan from the birthday waits for its headers.
    kyoto_rescan: Option<u32>,
    node: Option<Follower>,
    node_ok: bool,
    node_probe: Option<Instant>,
    clients: HashMap<String, Electrum>,
    esplora: HashMap<String, esplora_client_alias::AsyncClient>,
    depths: HashMap<BlockHash, usize>,
    last_history: Option<Instant>,
    last_cross: Option<Instant>,
    cross_delay: Duration,
    last_fees: Option<Instant>,
    last_expiry: Option<Instant>,
    last_routes: Instant,
}

mod esplora_client_alias {
    pub use bdk_esplora::esplora_client::AsyncClient;
}

fn cp_from(blocks: &[(u32, BlockHash)]) -> Option<CheckPoint> {
    CheckPoint::from_block_ids(blocks.iter().map(|(height, hash)| BlockId { height: *height, hash: *hash })).ok()
}

/// Brings BDK's local chain onto the authority's, with checkpoints at `wanted` heights.
pub fn apply_chain(cell: &mut Cell, view: &dyn ChainView, wanted: &BTreeSet<u32>) -> Result<bool, String> {
    let bdk: Vec<(u32, BlockHash)> = cell.wallet.checkpoints().map(|c| (c.height(), c.hash())).collect::<Vec<_>>().into_iter().rev().collect();
    let Some(blocks) = authority::chain_update(view, &bdk, wanted) else { return Ok(false) };
    let Some(cp) = cp_from(&blocks) else { return Ok(false) };
    cell.wallet.apply_update(Update { chain: Some(cp), ..Default::default() }).map_err(|e| format!("chain update: {e}"))?;
    Ok(true)
}

impl Loop {
    fn now(&self) -> u64 {
        now_secs()
    }

    fn stopped(&self) -> bool {
        self.ctx.stop.load(Ordering::SeqCst)
    }

    fn alert(&self, source: &str, kind: &'static str, detail: String) {
        tracing::warn!(target: "bitcoin", "source {source}: {kind}: {detail}");
        (self.ctx.notify)(Note::Alert { source: source.into(), kind, detail });
    }

    fn mark_suspect(&mut self, source: &str, reason: &str) {
        // Its client's caches hold what it served; a cleared suspect starts afresh.
        self.clients.remove(source);
        self.esplora.remove(source);
        let fresh = self.ctx.netstate.lock().ledger.suspect(source, reason);
        if fresh {
            if let Some(cell) = self.ctx.cell.lock().as_ref() {
                let _ = cell.store_suspect(source, reason, self.now());
            }
            if let Some(r) = &self.ctx.routes_src {
                r.report_mismatch(self.ctx.net.name(), source, "wallet_core", None);
            }
            self.alert(source, "suspect", reason.to_string());
        }
    }

    fn reload_routes(&mut self) {
        let Some(src) = &self.ctx.routes_src else { return };
        match src.route_table(self.ctx.net.name()).and_then(|r| Routes::from_table(&r)) {
            Ok(r) => {
                let mut ns = self.ctx.netstate.lock();
                if ns.routes != r {
                    tracing::info!(target: "bitcoin", "routes changed: {} chain, {} history", r.chain.len(), r.history.len());
                    self.clients.clear();
                    self.esplora.clear();
                    ns.routes = r;
                }
            }
            Err(e) => tracing::warn!(target: "bitcoin", "route_table: {e}"),
        }
        self.last_routes = Instant::now();
    }

    fn electrum(&mut self, s: &Source) -> Result<&Electrum, String> {
        if !self.clients.contains_key(&s.id) {
            let (proxy, iso) = {
                let mut ns = self.ctx.netstate.lock();
                (ns.routes.proxy.clone(), ns.iso(&s.id))
            };
            let c = net::electrum(s, proxy.as_ref(), &iso)?;
            self.clients.insert(s.id.clone(), BdkElectrumClient::new(Checked::new(c)));
        }
        Ok(&self.clients[&s.id])
    }

    fn esplora(&mut self, s: &Source) -> Result<&esplora_client_alias::AsyncClient, String> {
        if !self.esplora.contains_key(&s.id) {
            let (proxy, iso) = {
                let mut ns = self.ctx.netstate.lock();
                (ns.routes.proxy.clone(), ns.iso(&s.id))
            };
            let creds = match (&self.ctx.routes_src, s.credentials) {
                (Some(r), true) => r.source_credentials(self.ctx.net.name(), &s.id)?.map(|(u, p)| zeroize::Zeroizing::new((u, p))),
                _ => None,
            };
            let c = net::esplora(s, proxy.as_ref(), &iso, creds.as_deref())?;
            self.esplora.insert(s.id.clone(), c);
        }
        Ok(&self.esplora[&s.id])
    }

    fn failed(&mut self, id: &str, e: &str) {
        self.clients.remove(id);
        self.esplora.remove(id);
        self.ctx.netstate.lock().ledger.failed(id, e, now_secs());
        tracing::info!(target: "bitcoin", "source {id}: {e}");
    }

    /// The local node while it is synced, else Kyoto, else the Electrum header chain.
    fn choose(&mut self) -> Feeder {
        let (local, kyoto) = {
            let ns = self.ctx.netstate.lock();
            (ns.routes.local.is_some(), ns.routes.kyoto.is_some())
        };
        if local && self.ctx.node_src.is_some() {
            let due = self.feeder == Feeder::Node || self.node_probe.is_none_or(|t| t.elapsed() >= NODE_PROBE_EVERY);
            if due && self.feeder != Feeder::Node {
                self.node_probe = Some(Instant::now());
                let c = NodeClient::new(self.ctx.node_src.clone().expect("checked"));
                match node::status(&c, self.ctx.net) {
                    Ok(st) => {
                        self.node_ok = st.synced;
                        self.ctx.progress.lock().node = Some(st);
                    }
                    Err(e) => {
                        self.node_ok = false;
                        tracing::info!(target: "bitcoin", "local node: {e}");
                    }
                }
            }
            if self.node_ok {
                return Feeder::Node;
            }
        } else {
            self.node_ok = false;
        }
        if kyoto {
            Feeder::Kyoto
        } else {
            Feeder::Servers
        }
    }

    /// Hands the chain to another feeder: the header chain stays, the old feeder stops.
    fn switch(&mut self, to: Feeder) {
        if to == self.feeder {
            return;
        }
        tracing::info!(target: "bitcoin", "the chain authority is now {to:?}, was {:?}", self.feeder);
        if self.feeder == Feeder::Kyoto {
            self.stop_kyoto(None);
        }
        if self.feeder == Feeder::Node {
            self.node = None;
        }
        self.feeder = to;
        let kind = match to {
            Feeder::Servers => ELECTRUM_HEADERS,
            Feeder::Kyoto => KYOTO,
            Feeder::Node => LOCAL_NODE,
        };
        self.authority.set_kind(kind);
        self.ctx.netstate.lock().chain_by = kind;
    }

    /// Moves the authority's chain from its feeder, stores what changed, and restates BDK's chain.
    fn refresh_authority(&mut self) -> bool {
        let to = self.choose();
        self.switch(to);
        let (change, found) = match self.feeder {
            Feeder::Servers => (self.refresh_servers(), vec![]),
            Feeder::Kyoto => self.tend_kyoto(),
            Feeder::Node => match self.follow_node() {
                Ok(x) => x,
                Err(e) => {
                    tracing::info!(target: "bitcoin", "local node: {e}");
                    self.ctx.progress.lock().last_error = Some(format!("local node: {e}"));
                    self.node_ok = false;
                    self.node = None;
                    (Change::default(), vec![])
                }
            },
        };
        if let Some(from) = change.changed_from {
            if change.reorg_depth > 0 {
                tracing::info!(target: "bitcoin", "authority reorg of {} from {from}", change.reorg_depth);
                // bdk_electrum caches headers by height, and anchors by them: start them afresh.
                self.clients.clear();
            }
            let mut guard = self.ctx.cell.lock();
            if let Some(cell) = guard.as_mut() {
                if let Err(e) = cell.store_headers(self.authority.chain(), from) {
                    tracing::warn!(target: "bitcoin", "store headers: {e}");
                }
            }
        }
        for (who, why) in &change.suspects {
            if self.feeder != Feeder::Servers {
                tracing::warn!(target: "bitcoin", "{who} named a chain that fails the checks: {why}");
                self.alert(who, "suspect", format!("its headers fail the checks: {why}"));
            }
        }
        if change.tip_moved {
            self.move_chain();
        }
        let moved = change.tip_moved || !found.is_empty();
        for f in found {
            if let Err(e) = self.apply_found(f) {
                tracing::warn!(target: "bitcoin", "apply: {e}");
                self.ctx.progress.lock().last_error = Some(e);
            }
        }
        self.ctx.progress.lock().authority = self.authority.summary(now_secs());
        moved
    }

    /// Asks the Electrum header sources and keeps the most-work valid chain.
    fn refresh_servers(&mut self) -> Change {
        let sources: Vec<Source> = {
            let ns = self.ctx.netstate.lock();
            ns.routes
                .chain
                .iter()
                .filter(|s| s.down.is_none() && ns.ledger.may_ask(&s.id, now_secs()) && ns.ledger.health.get(&s.id).is_none_or(|h| h.suspect.is_none()))
                .cloned()
                .collect()
        };
        if sources.is_empty() {
            self.ctx.progress.lock().last_error = Some("no Electrum server is usable for the chain".to_string());
        }
        let mut ready = vec![];
        for s in &sources {
            match self.electrum(s) {
                Ok(_) => ready.push(s.clone()),
                Err(e) => self.failed(&s.id.clone(), &e),
            }
        }
        let adapters: Vec<ElectrumHeaders<'_, Checked<net::Conn>>> =
            ready.iter().map(|s| ElectrumHeaders { id: &s.id, client: &self.clients[&s.id].inner }).collect();
        let dyns: Vec<&dyn HeaderSource> = adapters.iter().map(|a| a as &dyn HeaderSource).collect();
        let change = self.authority.refresh(&dyns, now_secs() as u32);
        drop(dyns);
        drop(adapters);
        for (id, e) in &change.failures {
            self.failed(id, e);
        }
        for (id, why) in &change.suspects {
            self.mark_suspect(id, &format!("served invalid headers: {why}"));
        }
        {
            let mut ns = self.ctx.netstate.lock();
            let tip = self.authority.tip_height();
            for id in &change.agreeing {
                ns.ledger.ok(id, now_secs());
                ns.ledger.health_mut(id).tip = tip;
            }
        }
        Change { suspects: vec![], ..change }
    }

    // ── Kyoto ────────────────────────────────────────────────────────────

    fn kyoto_meta(&self, key: &str) -> Option<String> {
        self.ctx.cell.lock().as_ref().and_then(|c| meta_get(&c.conn, key).ok().flatten())
    }

    /// Where Kyoto starts: below the last height it scanned; else from the birthday, after a
    /// headers-only phase when the chain doesn't reach it yet; else from Kyoto's own checkpoint.
    fn kyoto_start(&self) -> Start {
        let a = &self.authority;
        let base = a.base_height();
        if let Some((h, hash)) = self.kyoto_meta(KYOTO_SCANNED).as_deref().and_then(parse_scanned) {
            if a.hash_at(h) == Some(hash) {
                let s = h.saturating_sub(kyoto::RESTART_DEPTH).max(base);
                if let Some(sh) = a.hash_at(s) {
                    return Start { from: (s, sh), headers_only: false, rescan_from: None };
                }
            }
        }
        let want = self.ctx.birthday.saturating_sub(1);
        if want >= base {
            if let Some(hash) = a.hash_at(want) {
                return Start { from: (want, hash), headers_only: false, rescan_from: None };
            }
            let tip = a.chain().tip_height();
            return Start { from: (tip, a.chain().tip_hash()), headers_only: true, rescan_from: Some(want) };
        }
        Start { from: kyoto::builtin_checkpoint(self.ctx.net, want), headers_only: false, rescan_from: None }
    }

    fn save_book(&self) {
        if let Some(c) = self.ctx.cell.lock().as_ref() {
            let _ = meta_set(&c.conn, KYOTO_PEERS, &serde_json::to_string(&self.kyoto_book).unwrap_or_default());
        }
    }

    /// Stops the client; with `why`, it stopped by itself: peers never seen this start count a failure.
    fn stop_kyoto(&mut self, why: Option<Option<String>>) {
        let Some(c) = self.kyoto.take() else { return };
        let now = now_secs();
        for p in c.seen() {
            self.kyoto_book.connected(&p);
        }
        if let Some(why) = why {
            for p in c.unseen() {
                self.kyoto_book.failed(&p, now);
            }
            self.kyoto_status.restarts += 1;
            self.kyoto_status.last_stop = Some(why.unwrap_or_else(|| "stopped".into()));
            // A start that got somewhere retries soon; one that didn't backs off.
            self.kyoto_backoff = if c.updated { Duration::from_secs(2) } else { (self.kyoto_backoff * 2).clamp(Duration::from_secs(2), KYOTO_RETRY_MAX) };
            self.kyoto_retry_at = Instant::now() + self.kyoto_backoff;
            tracing::info!(target: "bitcoin", "kyoto stopped ({}); {} of {} peers never connected; again in {:?}",
                self.kyoto_status.last_stop.as_deref().unwrap_or(""), c.unseen().len(), c.peers.len(), self.kyoto_backoff);
        }
        c.stop();
        self.kyoto_rescan = None;
        self.kyoto_status.running = false;
        self.kyoto_status.connected = 0;
        self.ctx.netstate.lock().kyoto = None;
        self.save_book();
    }

    /// Starts Kyoto when it isn't running, takes its updates, restarts it when it runs out of
    /// peers, and rebuilds it when the wallet reveals addresses past what it watches.
    fn tend_kyoto(&mut self) -> (Change, Vec<Found>) {
        let mut change = Change::default();
        let mut found = vec![];
        let (route, proxy, quorum) = {
            let ns = self.ctx.netstate.lock();
            (ns.routes.kyoto.clone(), ns.routes.proxy.clone(), ns.routes.kyoto_required)
        };
        let Some(route) = route else { return (change, found) };
        if let Some(d) = &route.down {
            self.stop_kyoto(None);
            self.ctx.progress.lock().last_error = Some(format!("Kyoto: {d}"));
            return (change, found);
        }
        let now = now_secs();
        if self.kyoto.is_none() && Instant::now() >= self.kyoto_retry_at {
            let start = self.kyoto_start();
            let peers = self.kyoto_book.pick(&route.peers, now, &mut rand::thread_rng());
            let required = kyoto::required(self.ctx.net, quorum, peers.len());
            let started = {
                let guard = self.ctx.cell.lock();
                match guard.as_ref() {
                    Some(cell) => kyoto::Client::start(&self.ctx.rt, &cell.wallet, &route, proxy.as_ref(), required, peers, start),
                    None => Err("closed".into()),
                }
            };
            match started {
                Ok(c) => {
                    self.kyoto_rescan = start.rescan_from;
                    self.ctx.netstate.lock().kyoto = Some(c.requester.clone());
                    self.kyoto_status.dialled = c.peers.len();
                    self.kyoto_status.running = true;
                    self.kyoto_status.phase = "headers";
                    self.kyoto = Some(c);
                }
                Err(e) => {
                    self.kyoto_backoff = (self.kyoto_backoff * 2).clamp(Duration::from_secs(2), KYOTO_RETRY_MAX);
                    self.kyoto_retry_at = Instant::now() + self.kyoto_backoff;
                    self.ctx.progress.lock().last_error = Some(format!("Kyoto: {e}"));
                }
            }
        }
        let feeds = self.kyoto.as_mut().map(|c| c.poll()).unwrap_or_default();
        // Updates sent before the node stopped are taken before the stop.
        let mut stopped = None;
        for f in feeds {
            match f {
                Feed::Progress { fraction, height } => {
                    self.kyoto_status.progress = fraction;
                    self.kyoto_status.height = height;
                }
                Feed::Warning(w) => self.kyoto_status.last_warning = Some(w),
                Feed::Stopped(why) => stopped = Some(why),
                Feed::Update(u) => match self.take_kyoto_update(*u) {
                    Ok((c, f)) => {
                        change = merge(change, c);
                        found.extend(f);
                    }
                    Err(e) => {
                        tracing::warn!(target: "bitcoin", "kyoto update: {e}");
                        self.kyoto_status.last_warning = Some(e.clone());
                        self.alert(KYOTO, "authority_suspect", e);
                    }
                },
            }
        }
        if let Some(why) = stopped {
            self.stop_kyoto(Some(why));
        }
        // Addresses revealed past what the client watches need a client that watches them.
        let rebuild = match (&self.kyoto, self.ctx.cell.lock().as_ref()) {
            (Some(c), Some(cell)) => c.needs_rebuild(&cell.wallet),
            _ => false,
        };
        if rebuild {
            tracing::info!(target: "bitcoin", "kyoto: rebuilding for addresses revealed past its lookahead");
            self.stop_kyoto(None);
            self.kyoto_status.rebuilds += 1;
            self.kyoto_retry_at = Instant::now();
        }
        if let Some(c) = &self.kyoto {
            self.kyoto_status.connected = c.connected();
            self.kyoto_status.phase = kyoto::phase(c.updated && self.kyoto_rescan.is_none(), self.kyoto_status.progress);
            self.authority.set_peers(c.connected() as u32);
        }
        self.kyoto_status.skipped = self.kyoto_book.skipped(now);
        self.ctx.progress.lock().kyoto = Some(self.kyoto_status.clone());
        (change, found)
    }

    /// Mirrors Kyoto's chain since its start into the authority's, then hands over what its
    /// filters matched. Below the wallet's checkpoint, Kyoto's chain must reach that checkpoint.
    fn take_kyoto_update(&mut self, u: bdk_wallet::Update) -> Result<(Change, Vec<Found>), String> {
        let (requester, start) = match &self.kyoto {
            Some(c) => (c.requester.clone(), c.start),
            None => return Ok((Change::default(), vec![])),
        };
        let Some(cp) = u.chain else { return Ok((Change::default(), vec![])) };
        let mut ids: Vec<(u32, BlockHash)> = cp.iter().map(|c| (c.height(), c.hash())).take_while(|(h, _)| *h > start.from.0).collect();
        ids.reverse();
        // Kyoto's own headers run contiguously from its start; anything past a gap is BDK's.
        let run = ids.iter().enumerate().take_while(|(i, (h, _))| *h == start.from.0 + 1 + *i as u32).count();
        ids.truncate(run);
        let base = self.authority.base_height();
        if let Some((_, hash)) = ids.iter().find(|(h, _)| *h == base) {
            if self.authority.hash_at(base) != Some(*hash) {
                return Err("Kyoto's peers are on a chain without the wallet's checkpoint".into());
            }
        }
        let above: Vec<(u32, BlockHash)> = ids.iter().filter(|(h, _)| *h > base).copied().collect();
        let fork = above.iter().rev().find(|(h, hash)| self.authority.hash_at(*h) == Some(*hash)).map_or(start.from.0.max(base), |(h, _)| *h);
        if self.authority.hash_at(fork).is_none() {
            return Err(format!("Kyoto's chain doesn't meet the wallet's at {fork}"));
        }
        let wanted: Vec<(u32, BlockHash)> = above.into_iter().filter(|(h, _)| *h > fork).collect();
        // Without the headers, the update's transactions still count: anchors above the chain's
        // tip are held until it reaches them, and the scanned height stays where it was.
        let (change, mirrored) = match kyoto::headers(&self.ctx.rt, &requester, &wanted, &self.ctx.stop) {
            Ok(headers) => {
                let branch: Vec<_> = headers.into_iter().map(|(_, h)| h).collect();
                let change = self.authority.adopt(fork, &branch, now_secs() as u32);
                if !change.suspects.is_empty() {
                    return Err(format!("Kyoto's headers fail the checks: {}", change.suspects[0].1));
                }
                (change, true)
            }
            Err(e) => {
                tracing::info!(target: "bitcoin", "kyoto: headers not taken this round: {e}");
                (Change::default(), false)
            }
        };
        let tip = ids.last().copied().or_else(|| self.authority.hash_at(start.from.0).map(|h| (start.from.0, h))).filter(|_| mirrored);
        let mut found = vec![];
        if let Some(h) = self.kyoto_rescan {
            // The headers-only phase is done: scan filters from the birthday on.
            if self.authority.hash_at(h).is_some() {
                let _ = requester.rescan_from(h);
                tracing::info!(target: "bitcoin", "kyoto: headers synced; scanning filters after {h}");
                self.kyoto_rescan = None;
            }
        } else {
            // Kyoto's blocks below the wallet's checkpoint are named by Kyoto itself.
            for (a, _) in &u.tx_update.anchors {
                if a.block_id.height < base {
                    self.authority.note_old(a.block_id.height, a.block_id.hash);
                    if let Some(c) = self.ctx.cell.lock().as_ref() {
                        let _ = c.store_old(&[(a.block_id.height, a.block_id.hash)]);
                    }
                }
            }
            found.push(Found { source: KYOTO, tx_update: u.tx_update, last_active: u.last_active_indices, evicted: vec![], scanned: tip.map(|t| (KYOTO_SCANNED, t)) });
        }
        Ok((change, found))
    }

    // ── The local node ───────────────────────────────────────────────────

    /// Takes the node's headers up to its tip, then the wallet's transactions in its blocks and mempool.
    fn follow_node(&mut self) -> Result<(Change, Vec<Found>), String> {
        let rpc = self.ctx.node_src.clone().ok_or("no local node")?;
        if self.node.is_none() {
            let scanned = self.kyoto_meta(NODE_SCANNED).as_deref().and_then(parse_scanned).filter(|(h, hash)| self.authority.hash_at(*h) == Some(*hash));
            self.node = Some(Follower::new(Arc::new(NodeClient::new(rpc)), scanned));
        }
        let follower = self.node.as_ref().expect("set above");
        let st = node::status(follower.client(), self.ctx.net)?;
        self.ctx.progress.lock().node = Some(st.clone());
        if !st.synced {
            return Err(format!("the local node is not synced ({} of {} blocks)", st.blocks, st.headers));
        }
        let mut change = Change::default();
        while self.authority.chain().tip_height() < st.blocks || self.authority.tip_height().is_none() {
            let c = self.node.as_ref().expect("set").headers(&mut self.authority, st.blocks, now_secs() as u32)?;
            let progressed = c.tip_moved;
            change = merge(change, c);
            if !progressed || self.stopped() {
                break;
            }
        }
        if !change.suspects.is_empty() {
            return Err(format!("the node's headers fail the checks: {}", change.suspects[0].1));
        }
        self.authority.set_peers(1);
        let (index, expected) = {
            let guard = self.ctx.cell.lock();
            let cell = guard.as_ref().ok_or("closed")?;
            let expected: Vec<Arc<bitcoin::Transaction>> = cell.wallet.transactions().filter(|t| !t.chain_position.is_confirmed()).map(|t| t.tx_node.tx.clone()).collect();
            (cell.wallet.spk_index().clone(), expected)
        };
        let birthday = self.ctx.birthday;
        let mut found = vec![];
        loop {
            let f = self.node.as_mut().expect("set").scan(&self.authority, &index, expected.clone(), birthday)?;
            let done = f.at_tip || f.scanned.is_none();
            found.push(Found { source: LOCAL_NODE, tx_update: f.tx_update, last_active: f.last_active, evicted: f.evicted, scanned: f.scanned.map(|s| (NODE_SCANNED, s)) });
            if done || self.stopped() {
                break;
            }
        }
        Ok((change, found))
    }

    /// Applies what the authority found: checked against its chain all the same, anchors held
    /// above its tip, the chain given a checkpoint at each anchor.
    fn apply_found(&mut self, f: Found) -> Result<(), String> {
        let now = self.now();
        let mut update = f.tx_update;
        let pending: Vec<Txid> = update.seen_ats.iter().map(|(t, _)| *t).collect();
        let mut guard = self.ctx.cell.lock();
        let cell = guard.as_mut().ok_or("closed")?;
        let screened = checks::screen(&mut update, &self.authority, &HashMap::new(), &|t| cell.known(t), true);
        for (txid, a) in &screened.dropped {
            // The authority's own block, gone from its chain since: a reorg raced the update.
            tracing::info!(target: "bitcoin", "{}: {txid} at {} is off the chain now; it comes again", f.source, a.block_id.height);
        }
        for (txid, a) in &screened.held {
            let _ = cell.hold(&Held { txid: *txid, anchor: *a, source: f.source.to_string() });
        }
        let wanted: BTreeSet<u32> = update.anchors.iter().map(|(a, _)| a.block_id.height).collect();
        apply_chain(cell, &self.authority, &wanted)?;
        let capped = cap(cell, &f.last_active, &update);
        cell.wallet.apply_update(Update { last_active_indices: capped, tx_update: update, chain: None }).map_err(|e| e.to_string())?;
        let gone: Vec<(Txid, u64)> = f.evicted.into_iter().filter(|(t, _)| cell.known(t)).collect();
        if !gone.is_empty() {
            cell.wallet.apply_evicted_txs(gone);
        }
        if !pending.is_empty() {
            let _ = cell.reported(&pending, f.source, now);
        }
        cell.settle_sends()?;
        if let Some((key, (h, hash))) = f.scanned {
            meta_set(&cell.conn, key, &format!("{h}:{hash}")).map_err(|e| e.to_string())?;
        }
        cell.persist()?;
        drop(guard);
        let mut p = self.ctx.progress.lock();
        p.full_scan_done = true;
        p.synced_tip = self.authority.tip_height();
        p.last_history_sync = Some(now);
        p.history_server = Some(f.source.to_string());
        p.last_error = None;
        Ok(())
    }

    /// Restates BDK's chain on the authority's and applies held anchors it now covers.
    fn move_chain(&mut self) {
        let mut guard = self.ctx.cell.lock();
        let Some(cell) = guard.as_mut() else { return };
        if let Err(e) = apply_chain(cell, &self.authority, &BTreeSet::new()) {
            tracing::warn!(target: "bitcoin", "{e}");
        }
        let held = cell.held().unwrap_or_default();
        let mut ready = TxUpdate::<ConfirmationBlockTime>::default();
        let mut wanted = BTreeSet::new();
        let mut dropped = vec![];
        for h in &held {
            match checks::judge_anchor(&self.authority, h.anchor.block_id.height, h.anchor.block_id.hash) {
                checks::AnchorVerdict::Keep => {
                    ready.anchors.insert((h.anchor, h.txid));
                    wanted.insert(h.anchor.block_id.height);
                    let _ = cell.unhold(h);
                }
                checks::AnchorVerdict::Drop => {
                    let _ = cell.unhold(h);
                    dropped.push(h.clone());
                }
                checks::AnchorVerdict::Stale => {
                    let _ = cell.unhold(h);
                }
                _ => {}
            }
        }
        if !ready.anchors.is_empty() {
            let _ = apply_chain(cell, &self.authority, &wanted);
            let _ = cell.wallet.apply_update(Update { tx_update: ready, ..Default::default() });
        }
        if let Err(e) = cell.persist() {
            tracing::warn!(target: "bitcoin", "{e}");
        }
        drop(guard);
        for h in dropped {
            let detail = format!("a held confirmation of {} at {} is not on the chain", h.txid, h.anchor.block_id.height);
            self.alert(&h.source, "anchor_mismatch", detail.clone());
            self.mark_suspect(&h.source, &detail);
        }
    }

    /// The block's Merkle depth, from a coinbase proof checked against the authority's header.
    fn depth_electrum(&mut self, id: &str, height: u32, hash: BlockHash) -> Result<usize, String> {
        if let Some(d) = self.depths.get(&hash) {
            return Ok(*d);
        }
        let header = self.authority.header_at(height).ok_or("no authority header at that height")?;
        let c = self.clients.get(id).ok_or("no client")?;
        let (coinbase, branch) = coinbase_proof(&c.inner.inner, height)?;
        if checks::merkle_root(coinbase, 0, &checks::electrum_branch(&branch)) != header.merkle_root.to_byte_array() {
            return Err(format!("the coinbase proof at {height} doesn't reach the block's merkle root"));
        }
        self.depths.insert(hash, branch.len());
        Ok(branch.len())
    }

    /// One history sync through the first healthy history server.
    fn sync_history(&mut self) -> Result<(), String> {
        let (src, takes_pending) = {
            let ns = self.ctx.netstate.lock();
            match ns.ledger.history(&ns.routes) {
                Some(s) if ns.ledger.may_ask(&s.id, now_secs()) => (s.clone(), ns.routes.pending.iter().any(|p| p.id == s.id)),
                Some(s) => return Err(format!("{} is backing off after failures", s.id)),
                None => return Err("no history server is usable".into()),
            }
        };
        if self.authority.tip_height().is_none() {
            return Err("the chain authority has no tip yet".into());
        }
        match self.sync_with(&src, takes_pending) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.failed(&src.id, &e);
                Err(format!("{}: {e}", src.id))
            }
        }
    }

    fn sync_with(&mut self, src: &Source, takes_pending: bool) -> Result<(), String> {
        let src = src.clone();
        let full = !self.ctx.progress.lock().full_scan_done;
        let now = self.now();
        // The request carries no chain tip, so the server's answer moves no chain.
        let (sync_req, full_req, known_txs, known_anchors) = {
            let guard = self.ctx.cell.lock();
            let cell = guard.as_ref().ok_or("closed")?;
            let w = &cell.wallet;
            let known_txs: Vec<_> = w.tx_graph().full_txs().map(|n| n.tx.clone()).collect();
            let anchors: Vec<(Txid, Vec<ConfirmationBlockTime>)> =
                w.tx_graph().full_txs().map(|n| (n.txid, n.anchors.iter().copied().collect())).collect();
            if full {
                (None, Some(FullScanRequest::builder_at(now).spks_from_indexer(w.spk_index()).build()), known_txs, anchors)
            } else {
                (Some(SyncRequest::builder_at(now).revealed_spks_from_indexer(w.spk_index(), ..).build()), None, known_txs, anchors)
            }
        };
        let mut exposed = false;
        {
            let mut ns = self.ctx.netstate.lock();
            if ns.ledger.expose(&src, "history", now) {
                exposed = true;
            }
        }
        if exposed {
            tracing::info!(target: "bitcoin", "{} now knows the wallet's addresses", src.id);
        }
        let (mut update, last_active, mismatched, proofs) = match src.kind {
            Kind::Electrum => {
                let c = self.electrum(&src)?;
                c.populate_tx_cache(known_txs);
                c.populate_anchor_cache(known_anchors);
                let r = match (sync_req, full_req) {
                    (Some(req), _) => c.sync(req, 25, false).map(|r| (r.tx_update, BTreeMap::new())),
                    (_, Some(req)) => c.full_scan(req, checks::GAP_LIMIT as usize, 25, false).map(|r| (r.tx_update, r.last_active_indices)),
                    _ => unreachable!(),
                };
                let rec = c.inner.take();
                let (update, last) = r.map_err(|e| e.to_string())?;
                (update, last, rec.mismatched, rec.proofs)
            }
            Kind::Esplora => {
                let c = self.esplora(&src)?.clone();
                let rt = self.ctx.rt.clone();
                let r = match (sync_req, full_req) {
                    (Some(req), _) => rt.block_on(c.sync(req, 4)).map(|r| (r.tx_update, BTreeMap::new())),
                    (_, Some(req)) => rt.block_on(c.full_scan(req, checks::GAP_LIMIT as usize, 4)).map(|r| (r.tx_update, r.last_active_indices)),
                    _ => unreachable!(),
                };
                let (update, last) = r.map_err(|e| e.to_string())?;
                (update, last, HashMap::new(), HashMap::new())
            }
        };
        // The checks before BDK sees anything.
        let screened = {
            let guard = self.ctx.cell.lock();
            let cell = guard.as_ref().ok_or("closed")?;
            checks::screen(&mut update, &self.authority, &mismatched, &|t| cell.known(t), takes_pending)
        };
        if !screened.tx_mismatches.is_empty() {
            self.clients.remove(&src.id);
            let d = format!("{} transaction(s) whose bytes don't hash to their txid", screened.tx_mismatches.len());
            self.mark_suspect(&src.id, &d);
        }
        if !screened.stale.is_empty() {
            tracing::info!(target: "bitcoin", "{}: {} anchor(s) in replaced blocks; behind the reorg", src.id, screened.stale.len());
            self.clients.remove(&src.id);
        }
        for (txid, a) in &screened.dropped {
            let d = format!("{txid} anchored at {} in block {}, which is not on the chain", a.block_id.height, a.block_id.hash);
            self.alert(&src.id, "anchor_mismatch", d.clone());
            self.mark_suspect(&src.id, &d);
        }
        // Old anchors: kept once the server's headers link up to the checkpoint.
        if !screened.needs_linkage.is_empty() && src.kind == Kind::Electrum {
            let heights: Vec<u32> = screened.needs_linkage.iter().map(|(_, a)| a.block_id.height).collect();
            let proved = {
                let c = self.clients.get(&src.id).ok_or("no client")?;
                let hs = ElectrumHeaders { id: &src.id, client: &c.inner };
                self.authority.prove_below(&heights, &hs)
            };
            match proved {
                Ok(p) => {
                    if let Some(cell) = self.ctx.cell.lock().as_ref() {
                        let _ = cell.store_old(&p);
                    }
                    for (txid, a) in &screened.needs_linkage {
                        match checks::judge_anchor(&self.authority, a.block_id.height, a.block_id.hash) {
                            checks::AnchorVerdict::Keep => {
                                update.anchors.insert((*a, *txid));
                            }
                            _ => self.mark_suspect(&src.id, &format!("an old anchor of {txid} doesn't link to the checkpoint")),
                        }
                    }
                }
                Err(e) => self.mark_suspect(&src.id, &format!("old headers don't link: {e}")),
            }
        }
        // Each new anchor's Merkle proof must reach the authority's header, at the block's depth.
        let new_anchors: Vec<(ConfirmationBlockTime, Txid)> = {
            let guard = self.ctx.cell.lock();
            let cell = guard.as_ref().ok_or("closed")?;
            update.anchors.iter().filter(|(a, t)| !cell.wallet.tx_graph().get_tx_node(*t).is_some_and(|n| n.anchors.contains(a))).copied().collect()
        };
        for (a, txid) in new_anchors {
            let height = a.block_id.height;
            let header = self.authority.header_at(height);
            let verdict = match src.kind {
                Kind::Electrum => {
                    let proof = match proofs.get(&(txid, height as usize)) {
                        Some(p) => Some(p.clone()),
                        None => self.clients.get(&src.id).and_then(|c| c.inner.inner.transaction_get_merkle(&txid, height as usize).ok()),
                    };
                    match (proof, header) {
                        (Some(p), Some(h)) => match self.depth_electrum(&src.id, height, a.block_id.hash) {
                            Ok(d) => checks::check_proof(txid, p.pos, &checks::electrum_branch(&p.merkle), &h, d),
                            Err(e) => {
                                tracing::info!(target: "bitcoin", "depth at {height}: {e}");
                                ProofVerdict::WrongRoot
                            }
                        },
                        // Below the checkpoint the header isn't held; linkage proved the hash.
                        (Some(_), None) => ProofVerdict::Valid,
                        (None, _) => ProofVerdict::WrongRoot,
                    }
                }
                Kind::Esplora => {
                    let c = self.esplora(&src)?.clone();
                    let rt = self.ctx.rt.clone();
                    let proof = rt.block_on(c.get_merkle_proof(&txid)).ok().flatten();
                    let info = rt.block_on(c.get_block_info(&a.block_id.hash)).ok();
                    match (proof, info, header) {
                        (Some(p), Some(i), Some(h)) if p.block_height == height => {
                            let branch: Vec<[u8; 32]> = p.merkle.iter().map(|t| t.to_byte_array()).collect();
                            checks::check_proof(txid, p.pos, &branch, &h, checks::tree_depth(i.tx_count))
                        }
                        (Some(_), Some(_), None) => ProofVerdict::Valid,
                        _ => ProofVerdict::WrongRoot,
                    }
                }
            };
            if verdict != ProofVerdict::Valid {
                update.anchors.remove(&(a, txid));
                let d = format!("the proof for {txid} at {height} fails: {verdict:?}");
                self.alert(&src.id, "anchor_mismatch", d.clone());
                self.mark_suspect(&src.id, &d);
            }
        }
        // Apply: the chain gets a checkpoint at each anchor's height, then the screened answer.
        let pending: Vec<Txid> = update.seen_ats.iter().map(|(t, _)| *t).collect();
        {
            let mut guard = self.ctx.cell.lock();
            let cell = guard.as_mut().ok_or("closed")?;
            for (txid, a) in &screened.held {
                let _ = cell.hold(&Held { txid: *txid, anchor: *a, source: src.id.clone() });
            }
            let wanted: BTreeSet<u32> = update.anchors.iter().map(|(a, _)| a.block_id.height).collect();
            apply_chain(cell, &self.authority, &wanted)?;
            let capped = cap(cell, &last_active, &update);
            cell.wallet.apply_update(Update { last_active_indices: capped, tx_update: update, chain: None }).map_err(|e| e.to_string())?;
            let _ = cell.reported(&pending, &src.id, now);
            cell.settle_sends()?;
            if full {
                let _ = crate::storage::meta_set(&cell.conn, "full_scan_done", "1");
            }
            cell.persist()?;
        }
        {
            let mut ns = self.ctx.netstate.lock();
            ns.ledger.ok(&src.id, now);
            ns.ledger.health_mut(&src.id).last_sync = Some(now);
            // Broadcasts record exposure too; all of it is kept.
            let exposure: Vec<_> = ns.ledger.exposure.values().cloned().collect();
            if let Some(cell) = self.ctx.cell.lock().as_ref() {
                for e in &exposure {
                    let _ = cell.store_exposure(e);
                }
            }
            ns.ledger.current_history = Some(src.id.clone());
        }
        let mut p = self.ctx.progress.lock();
        p.full_scan_done = true;
        p.synced_tip = self.authority.tip_height();
        p.last_history_sync = Some(now);
        p.history_server = Some(src.id.clone());
        p.last_error = None;
        Ok(())
    }

    /// Tips and one random header from each source enabled for checking.
    fn cross_check(&mut self) {
        let Some(auth_tip) = self.authority.tip_height() else { return };
        let sources: Vec<Source> = {
            let ns = self.ctx.netstate.lock();
            ns.routes.check.iter().filter(|s| s.down.is_none() && ns.ledger.may_ask(&s.id, now_secs())).cloned().collect()
        };
        let anchor_heights: HashSet<u32> = match self.ctx.cell.lock().as_ref() {
            Some(c) => c.wallet.tx_graph().all_anchors().iter().flat_map(|(_, a)| a.iter().map(|x| x.block_id.height)).collect(),
            None => HashSet::new(),
        };
        let birthday = self.ctx.birthday.max(self.authority.base_height());
        for s in sources {
            let lower_of = |tip: u32| tip.min(auth_tip);
            let random = crosscheck::random_height(birthday, auth_tip.saturating_sub(1), &|h| anchor_heights.contains(&h));
            let answer: Result<Answer, String> = match s.kind {
                Kind::Electrum => (|| {
                    let c = self.electrum(&s)?;
                    let tip = c.inner.inner.block_headers_subscribe().map_err(|e| e.to_string())?;
                    let tip_h = tip.height as u32;
                    let lower = lower_of(tip_h);
                    let at_lower = if lower == tip_h { tip.header.block_hash() } else { c.inner.inner.block_header(lower as usize).map_err(|e| e.to_string())?.block_hash() };
                    let random = match random.filter(|r| *r <= lower) {
                        Some(r) => Some((r, c.inner.inner.block_header(r as usize).map_err(|e| e.to_string())?.block_hash())),
                        None => None,
                    };
                    Ok(Answer { tip: tip_h, hash_at_lower: Some(at_lower), random })
                })(),
                Kind::Esplora => (|| {
                    let c = self.esplora(&s)?.clone();
                    let rt = self.ctx.rt.clone();
                    let tip_h = rt.block_on(c.get_height()).map_err(|e| e.to_string())?;
                    let lower = lower_of(tip_h);
                    let at_lower = rt.block_on(c.get_block_hash(lower)).map_err(|e| e.to_string())?;
                    let random = match random.filter(|r| *r <= lower) {
                        Some(r) => Some((r, rt.block_on(c.get_block_hash(r)).map_err(|e| e.to_string())?)),
                        None => None,
                    };
                    Ok(Answer { tip: tip_h, hash_at_lower: Some(at_lower), random })
                })(),
            };
            match answer {
                Err(e) => self.failed(&s.id, &e),
                Ok(a) => {
                    let (before, verdict) = {
                        let mut ns = self.ctx.netstate.lock();
                        ns.ledger.ok(&s.id, now_secs());
                        let h = ns.ledger.health_mut(&s.id);
                        h.tip = Some(a.tip);
                        let before = h.track.verdict;
                        let auth = &self.authority;
                        let v = crosscheck::judge(&mut h.track, auth_tip, &|x| auth.hash_at(x), &a, now_secs());
                        (before, v)
                    };
                    if before != Some(verdict) {
                        match verdict {
                            Verdict::Stale => self.alert(&s.id, "stale", format!("{} blocks behind", auth_tip.saturating_sub(a.tip))),
                            Verdict::AuthorityBehind => {
                                self.alert(&s.id, "authority_behind", format!("{} blocks ahead for half an hour", a.tip - auth_tip))
                            }
                            Verdict::Suspect => self.mark_suspect(&s.id, "another block below the tip, after the next block"),
                            Verdict::Agrees => {}
                        }
                    }
                }
            }
        }
        self.last_cross = Some(Instant::now());
        self.cross_delay = Duration::from_secs(crosscheck::next_delay_secs());
    }

    fn refresh_fees(&mut self) {
        let sources: Vec<Source> = {
            let ns = self.ctx.netstate.lock();
            ns.routes.fees.iter().filter(|s| ns.ledger.usable(s) && ns.ledger.may_ask(&s.id, now_secs())).cloned().collect()
        };
        let mut estimates = vec![];
        for s in sources {
            let r: Result<SourceEstimate, String> = match s.kind {
                Kind::Electrum => (|| {
                    let c = self.electrum(&s)?;
                    let e = c.inner.inner.batch_estimate_fee(fees::TARGETS.iter().map(|t| *t as usize)).map_err(|e| e.to_string())?;
                    let min = c.inner.inner.relay_fee().ok().or_else(|| c.inner.inner.mempool_get_info().ok().map(|m| m.minrelaytxfee)).and_then(fees::from_btc_per_kb);
                    let at = |i: usize| e.get(i).copied().and_then(fees::from_btc_per_kb);
                    Ok(SourceEstimate { source: s.id.clone(), rates: [at(0), at(1), at(2)], minimum: min })
                })(),
                Kind::Esplora => (|| {
                    let c = self.esplora(&s)?.clone();
                    let m = self.ctx.rt.block_on(c.get_fee_estimates()).map_err(|e| e.to_string())?;
                    let at = |t: u16| m.get(&t).copied();
                    Ok(SourceEstimate { source: s.id.clone(), rates: [at(fees::TARGETS[0]), at(fees::TARGETS[1]), at(fees::TARGETS[2])], minimum: None })
                })(),
            };
            match r {
                Ok(e) => estimates.push(e),
                Err(e) => self.failed(&s.id, &e),
            }
        }
        // The local node estimates; Kyoto's peers only state the floor they relay at.
        let (local, kyoto) = {
            let ns = self.ctx.netstate.lock();
            (ns.routes.fees_local && self.feeder == Feeder::Node, ns.kyoto.clone())
        };
        if let (true, Some(rpc)) = (local, self.ctx.node_src.clone()) {
            match node::fees(&NodeClient::new(rpc), "local") {
                Ok(e) => estimates.push(e),
                Err(e) => tracing::info!(target: "bitcoin", "local node fees: {e}"),
            }
        }
        if let Some(m) = kyoto.and_then(|r| kyoto::min_fee_rate(&self.ctx.rt, &r)) {
            estimates.push(SourceEstimate { source: KYOTO.into(), rates: [None; 3], minimum: Some(m) });
        }
        self.ctx.progress.lock().fees = Some(fees::combine(&estimates));
        self.last_fees = Some(Instant::now());
    }

    /// Unconfirmed transactions no server has reported for two weeks drop out of the view.
    fn expire_pending(&mut self) {
        let mut guard = self.ctx.cell.lock();
        if let Some(cell) = guard.as_mut() {
            let pending: Vec<(Txid, Option<u64>)> = cell
                .wallet
                .transactions()
                .filter(|t| !t.chain_position.is_confirmed())
                .map(|t| (t.tx_node.txid, t.tx_node.last_seen))
                .collect();
            let gone = checks::expired(pending, now_secs());
            if !gone.is_empty() {
                tracing::info!(target: "bitcoin", "{} pending transaction(s) expired", gone.len());
                cell.wallet.apply_evicted_txs(gone.into_iter().map(|t| (t, now_secs())));
                let _ = cell.persist();
            }
        }
        self.last_expiry = Some(Instant::now());
    }

    /// History comes from servers when they feed the chain, or when Kyoto has had no peer for a
    /// while and a server is enabled for history.
    fn servers_hold_history(&self) -> bool {
        match self.feeder {
            Feeder::Servers => true,
            Feeder::Node => false,
            Feeder::Kyoto => self.kyoto_status.connected == 0 && self.kyoto_status.restarts >= 3,
        }
    }

    fn run(&mut self) {
        let poll = Duration::from_secs(self.ctx.netstate.lock().routes.poll_secs.max(1));
        let history_every = poll.max(Duration::from_secs(if poll <= Duration::from_secs(5) { 1 } else { 60 }));
        while !self.stopped() {
            // Without routes, as when the node module wasn't up at open, ask again soon.
            let none = self.ctx.routes_src.is_some() && self.ctx.netstate.lock().routes.every().is_empty();
            let due = if none { Duration::from_secs(15) } else { ROUTES_EVERY };
            if self.ctx.reload_routes.swap(false, Ordering::SeqCst) || self.last_routes.elapsed() >= due {
                self.reload_routes();
            }
            let moved = self.refresh_authority();
            if self.stopped() {
                break;
            }
            let woken = self.ctx.wake.swap(false, Ordering::SeqCst);
            // Kyoto and the node find the wallet's transactions themselves; servers enabled for
            // history stand by for when they can't.
            if self.servers_hold_history() && (moved || woken || self.last_history.is_none_or(|t| t.elapsed() >= history_every)) {
                if let Err(e) = self.sync_history() {
                    tracing::info!(target: "bitcoin", "history: {e}");
                    self.ctx.progress.lock().last_error = Some(e);
                }
                self.last_history = Some(Instant::now());
            }
            if self.stopped() {
                break;
            }
            if moved || self.last_cross.is_none_or(|t| t.elapsed() >= self.cross_delay) {
                self.cross_check();
            }
            if self.last_fees.is_none_or(|t| t.elapsed() >= FEES_EVERY) {
                self.refresh_fees();
            }
            if self.last_expiry.is_none_or(|t| t.elapsed() >= EXPIRY_EVERY) {
                self.expire_pending();
            }
            (self.ctx.notify)(Note::State);
            let until = Instant::now() + poll;
            while Instant::now() < until && !self.stopped() && !self.ctx.wake.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        self.stop_kyoto(None);
        tracing::info!(target: "bitcoin", "sync stopped");
    }
}

/// The coinbase's txid and Merkle branch at `height`. electrs names the txid `tx_id` where the
/// protocol says `tx_hash`, so the reply is read raw.
fn coinbase_proof(c: &impl ElectrumApi, height: u32) -> Result<(Txid, Vec<[u8; 32]>), String> {
    use bdk_electrum::electrum_client::Param;
    let v = c
        .raw_call("blockchain.transaction.id_from_pos", vec![Param::Usize(height as usize), Param::Usize(0), Param::Bool(true)])
        .map_err(|e| e.to_string())?;
    let id = v.get("tx_hash").or_else(|| v.get("tx_id")).and_then(Value::as_str).ok_or("id_from_pos: no txid")?;
    let txid = Txid::from_str(id).map_err(|e| e.to_string())?;
    let mut branch = vec![];
    for h in v["merkle"].as_array().ok_or("id_from_pos: no merkle branch")? {
        let mut b = [0u8; 32];
        hex::decode_to_slice(h.as_str().unwrap_or(""), &mut b).map_err(|_| "id_from_pos: a branch entry is not 32 bytes")?;
        branch.push(b);
    }
    Ok((txid, branch))
}

/// Caps a full scan's address indices at the revealed index plus the gap limit, or higher only
/// where a checked transaction in the answer pays the address.
fn cap(cell: &Cell, claimed: &BTreeMap<KeychainKind, u32>, update: &TxUpdate<ConfirmationBlockTime>) -> BTreeMap<KeychainKind, u32> {
    let scripts: HashSet<ScriptBuf> = update.txs.iter().flat_map(|t| t.output.iter().map(|o| o.script_pubkey.clone())).collect();
    let revealed = |k| cell.wallet.derivation_index(k);
    let proven = |k: KeychainKind| {
        let c = *claimed.get(&k)?;
        let from = revealed(k).map_or(checks::GAP_LIMIT, |r| r + checks::GAP_LIMIT + 1);
        let to = c.min(from.saturating_add(5_000));
        (from..=to).rev().find(|i| scripts.contains(&cell.wallet.peek_address(k, *i).script_pubkey()))
    };
    let capped = checks::cap_indices(claimed, revealed, proven);
    for (k, c) in claimed {
        if capped.get(k) != Some(c) {
            tracing::warn!(target: "bitcoin", "capped a claimed address index {c} to {:?}", capped.get(k));
        }
    }
    capped
}

/// Starts the sync thread for an open wallet.
pub fn spawn(ctx: Ctx, authority: ChainAuthority) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new().name("bitcoin-sync".into()).spawn(move || {
        let book = ctx.cell.lock().as_ref().and_then(|c| meta_get(&c.conn, KYOTO_PEERS).ok().flatten()).and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        let mut l = Loop {
            ctx,
            authority,
            feeder: Feeder::Servers,
            kyoto: None,
            kyoto_book: book,
            kyoto_retry_at: Instant::now(),
            kyoto_backoff: Duration::from_secs(2),
            kyoto_status: KyotoStatus::default(),
            kyoto_rescan: None,
            node: None,
            node_ok: false,
            node_probe: None,
            clients: HashMap::new(),
            esplora: HashMap::new(),
            depths: HashMap::new(),
            last_history: None,
            last_cross: None,
            cross_delay: Duration::from_secs(crosscheck::next_delay_secs()),
            last_fees: None,
            last_expiry: None,
            last_routes: Instant::now(),
        };
        l.run();
    })
}

/// A status fragment for the progress figures.
pub fn progress_json(p: &Progress) -> Value {
    json!({"authority": p.authority, "syncedTip": p.synced_tip, "lastHistorySync": p.last_history_sync,
           "historyServer": p.history_server, "lastError": p.last_error})
}

fn merge(mut a: Change, b: Change) -> Change {
    a.tip_moved |= b.tip_moved;
    a.changed_from = match (a.changed_from, b.changed_from) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    };
    a.reorg_depth = a.reorg_depth.max(b.reorg_depth);
    a.suspects.extend(b.suspects);
    a.failures.extend(b.failures);
    a.agreeing.extend(b.agreeing);
    a
}

/// A stored `height:hash`.
fn parse_scanned(s: &str) -> Option<(u32, BlockHash)> {
    let (h, hash) = s.split_once(':')?;
    Some((h.parse().ok()?, BlockHash::from_str(hash).ok()?))
}
