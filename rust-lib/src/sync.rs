//! The open wallet's sync thread: it moves the chain from the authority only, and applies what a
//! history server reports after the checks. Network calls never hold the wallet lock.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bdk_electrum::electrum_client::{self, ElectrumApi};
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

use crate::authority::{self, Authority, ElectrumHeaders, HeaderSource};
use crate::checks::{self, ChainView, ProofVerdict};
use crate::crosscheck::{self, Answer, Verdict};
use crate::fees::{self, SourceEstimate};
use crate::ledger::Ledger;
use crate::net::{self, Checked};
use crate::network::{BNetwork, Family};
use crate::routes::{Isolation, Kind, Routes, Source};
use crate::wallet::{Cell, Held};
use crate::walletdir::now_secs;

pub type Electrum = BdkElectrumClient<Checked<electrum_client::Client>>;

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
}

impl NetState {
    pub fn iso(&mut self, id: &str) -> Isolation {
        self.iso.entry(id.to_string()).or_insert_with(Isolation::fresh).clone()
    }
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
}

const ROUTES_EVERY: Duration = Duration::from_secs(300);
const FEES_EVERY: Duration = Duration::from_secs(300);
const EXPIRY_EVERY: Duration = Duration::from_secs(600);

struct Loop {
    ctx: Ctx,
    authority: Box<dyn Authority>,
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

    /// Asks the chain sources and moves BDK's chain when the authority's tip moves.
    fn refresh_authority(&mut self) -> bool {
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
            let ns = self.ctx.netstate.lock();
            let why = if !ns.routes.unsupported_chain.is_empty() {
                format!("the chain is set to {}, which comes in a later pass; enable an Electrum server for it", ns.routes.unsupported_chain.join(", "))
            } else {
                "no Electrum server is usable for the chain".to_string()
            };
            drop(ns);
            self.ctx.progress.lock().last_error = Some(why);
        }
        let mut ready = vec![];
        for s in &sources {
            match self.electrum(s) {
                Ok(_) => ready.push(s.clone()),
                Err(e) => self.failed(&s.id.clone(), &e),
            }
        }
        let adapters: Vec<ElectrumHeaders<'_, Checked<electrum_client::Client>>> =
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
        if change.tip_moved {
            self.move_chain();
        }
        self.ctx.progress.lock().authority = self.authority.summary(now_secs());
        change.tip_moved
    }

    /// Restates BDK's chain on the authority's and applies held anchors it now covers.
    fn move_chain(&mut self) {
        let mut guard = self.ctx.cell.lock();
        let Some(cell) = guard.as_mut() else { return };
        if let Err(e) = apply_chain(cell, &*self.authority, &BTreeSet::new()) {
            tracing::warn!(target: "bitcoin", "{e}");
        }
        let held = cell.held().unwrap_or_default();
        let mut ready = TxUpdate::<ConfirmationBlockTime>::default();
        let mut wanted = BTreeSet::new();
        let mut dropped = vec![];
        for h in &held {
            match checks::judge_anchor(&*self.authority, h.anchor.block_id.height, h.anchor.block_id.hash) {
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
            let _ = apply_chain(cell, &*self.authority, &wanted);
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
            checks::screen(&mut update, &*self.authority, &mismatched, &|t| cell.known(t), takes_pending)
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
                        match checks::judge_anchor(&*self.authority, a.block_id.height, a.block_id.hash) {
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
            apply_chain(cell, &*self.authority, &wanted)?;
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
                        let auth = &*self.authority;
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
            if moved || woken || self.last_history.is_none_or(|t| t.elapsed() >= history_every) {
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
pub fn spawn(ctx: Ctx, authority: Box<dyn Authority>) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new().name("bitcoin-sync".into()).spawn(move || {
        let mut l = Loop {
            ctx,
            authority,
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
