//! Logos glue for `bitcoin_wallet_core_module`: JSON strings in and out, sends, cancels, descriptors
//! and source changes for `bitcoin_wallet_backend` only, and no secret ever taken as a parameter.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use logos_rust_sdk::{AboutToUnload, LogosCaller, LogosError, Shutdown};
use serde_json::{json, Value};

use crate::engine::{Engine, Event, Sink};
use crate::gate::{Caller, Callers};
use crate::manager::SignerManager;
use crate::sync::RouteSource;

pub trait BitcoinWalletCoreModule: Send + Sync + 'static {
    /// `{ ok, version, crates }`.
    fn version(&self) -> String;
    /// `{ ok, jobId, receipt }` for open_wallet, close_wallet, build_send, bump_fee, rebroadcast, and
    /// for the backend sign_and_broadcast, cancel_send, abandon_send, set_birthday and set_gap_limit
    /// (README, Job kinds). open_wallet's params and result carry `gapLimit`, 20 to 1000.
    fn start_job(&self, kind: String, params: String) -> String;
    /// `{ ok, jobId, kind, state: queued|running|done|failed|cancelled, error }`.
    fn job_status(&self, job_id: String, receipt: String) -> String;
    /// `{ ok, result }` once done.
    fn job_result(&self, job_id: String, receipt: String) -> String;
    fn ack_job(&self, job_id: String, receipt: String) -> bool;
    fn cancel_job(&self, job_id: String, receipt: String) -> bool;
    /// `{ ok, state, network, group, family, authority: { kind, height, tipAgeSecs, peers, asked, headers },
    /// synced, busy, needsBirthday, gapLimit, openHandle?, approvalHandle?, ... }`; `asked` is false until
    /// the open's first round of asking the chain's sources ends or a server's first headers are taken;
    /// `headers` is `{ have, target }` while the chain's headers come in (`target` null for Kyoto), else
    /// null. Never waits on the wallet.
    fn status(&self) -> String;
    /// `{ ok, confirmed, waiting, pending, sent, immature, tooSmall: { count, sat }, beyondGap: { count,
    /// sat, confirmedSat } }`, satoshis as decimal strings; empty strings while busy, never zero.
    fn balance(&self) -> String;
    /// `{ ok, address, index, fresh, unused, gapLimit }`: a fresh receive address, or with `fresh`
    /// false the first unused one, when `unused` addresses already stand unused and reach `gapLimit`.
    fn next_address(&self) -> String;
    /// `{ ok, address, index }`: the first unused receive address, revealed only when none is.
    fn current_address(&self) -> String;
    /// `{ ok, addresses: [{ index, address, used }] }`, the revealed receive addresses.
    fn addresses(&self) -> String;
    /// `{ ok, utxos: [...] }`, outputs confirmed on the authority's chain.
    fn utxos(&self) -> String;
    /// `{ ok, rows: [{ txid, intent: send|self|combine|fee_bump|receive, amountSat, feeSat,
    /// counterparties, height, confirmations, time, state, reportedBy, beyondGap }] }`, newest first.
    fn history(&self, page: i64) -> String;
    /// `{ ok, fast, normal, slow, minimum, sources, estimated, basis }` in sat/vB, once every level
    /// has an estimate; until then `{ ok: false, error: "no fee estimate yet" }`. `basis` is
    /// `mempool` when the sources read the levels off their mempools, else `estimate`.
    fn fee_rates(&self) -> String;
    /// An address or BIP21 URI on a network: `{ ok, valid, address, type, dustSat, amountSat? }`; `dustSat`
    /// is the least it can receive, below which build_send fails with code `dust`.
    fn address_valid(&self, text: String, network: String) -> String;
    /// `{ ok, proxy, crossCheck, sources: [{ id, roles, state, suspect, lastSync, error, ... }] }`.
    fn sources_status(&self) -> String;
    /// `{ ok, servers: [{ source, url, operator, role, since, last }] }`.
    fn exposure(&self) -> String;
    /// The wallet's public descriptors, as the keystore gave them. Backend only.
    fn descriptors(&self) -> String;
    /// A send's preview with its state and `approvalHandle`.
    fn preview(&self, preview_id: String) -> String;
    /// `{ ok, wallets: [{ group, family, network, createdAt }] }`.
    fn list_wallets(&self, network: String) -> String;
    /// Clears a source the core marked suspect. Backend only.
    fn clear_suspect(&self, source: String) -> String;
    /// Reads `route_table` again. Backend only.
    fn reload_routes(&self) -> String;

    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

// Read by logos-lidl-gen, which generates the emitters.
#[allow(dead_code, non_snake_case)]
pub trait BitcoinWalletCoreModuleEvents {
    /// status()'s shape, when what it says changes.
    fn walletStateChanged(&self, payload: String);
    fn jobFinished(&self, job_id: String, state: String);
    /// `{ source, kind: suspect|stale|authority_behind|anchor_mismatch|authority_suspect, detail, at }`.
    fn sourceAlert(&self, payload: String);
    /// `list_wallets` shows other wallets: one was unlocked or locked in the Signer app. `locked`
    /// counts the seeds whose wallets it can't list.
    fn walletsChanged(&self, locked: i64);
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
pub struct BitcoinWalletCoreModuleImpl {
    engine: OnceLock<Arc<Engine>>,
    callers: Mutex<Callers>,
}

fn refused() -> String {
    json!({"ok": false, "error": "not authorized"}).to_string()
}

fn not_ready() -> String {
    json!({"ok": false, "error": "starting"}).to_string()
}

impl BitcoinWalletCoreModuleImpl {
    fn backend(&self) -> bool {
        let caller = match logos_rust_sdk::current_caller() {
            LogosCaller::Module { name, .. } => Caller::Module(name),
            LogosCaller::HostAnchor => Caller::Host,
            LogosCaller::Unknown => Caller::Unknown,
            _ => Caller::Other,
        };
        self.callers.lock().unwrap().admits(&caller)
    }

    fn with(&self, f: impl FnOnce(&Arc<Engine>) -> Value) -> String {
        match self.engine.get() {
            Some(e) => f(e).to_string(),
            None => not_ready(),
        }
    }

    fn backend_with(&self, f: impl FnOnce(&Arc<Engine>) -> Value) -> String {
        if !self.backend() {
            return refused();
        }
        self.with(f)
    }
}

impl BitcoinWalletCoreModule for BitcoinWalletCoreModuleImpl {
    fn version(&self) -> String {
        json!({"ok": true, "version": env!("CARGO_PKG_VERSION"),
               "crates": {"bdk_wallet": "3.2.0", "bdk_electrum": "0.24.1", "bdk_esplora": "0.22.3", "bdk_kyoto": "0.18.1",
                          "bip157": "0.7.0+logos.4", "bdk_bitcoind_rpc": "0.22.1"}})
        .to_string()
    }

    fn start_job(&self, kind: String, params: String) -> String {
        if crate::engine::backend_only(&kind) && !self.backend() {
            return refused();
        }
        self.with(|e| e.start_job(&kind, &params))
    }

    fn job_status(&self, job_id: String, receipt: String) -> String {
        self.with(|e| e.jobs().status(&job_id, &receipt))
    }

    fn job_result(&self, job_id: String, receipt: String) -> String {
        self.with(|e| e.jobs().result(&job_id, &receipt))
    }

    fn ack_job(&self, job_id: String, receipt: String) -> bool {
        self.engine.get().is_some_and(|e| e.jobs().ack(&job_id, &receipt))
    }

    fn cancel_job(&self, job_id: String, receipt: String) -> bool {
        self.engine.get().is_some_and(|e| e.jobs().cancel(&job_id, &receipt))
    }

    fn status(&self) -> String {
        self.with(|e| e.status())
    }

    fn balance(&self) -> String {
        self.with(|e| e.balance())
    }

    fn next_address(&self) -> String {
        self.with(|e| e.next_address())
    }

    fn current_address(&self) -> String {
        self.with(|e| e.current_address())
    }

    fn addresses(&self) -> String {
        self.with(|e| e.addresses())
    }

    fn utxos(&self) -> String {
        self.with(|e| e.utxos())
    }

    fn history(&self, page: i64) -> String {
        self.with(|e| e.history(page.clamp(0, u32::MAX as i64) as u32))
    }

    fn fee_rates(&self) -> String {
        self.with(|e| e.fee_rates_json())
    }

    fn address_valid(&self, text: String, network: String) -> String {
        Engine::address_valid(&text, &network).to_string()
    }

    fn sources_status(&self) -> String {
        self.with(|e| e.sources_status())
    }

    fn exposure(&self) -> String {
        self.with(|e| e.exposure())
    }

    fn descriptors(&self) -> String {
        self.backend_with(|e| e.descriptors())
    }

    fn preview(&self, preview_id: String) -> String {
        self.with(|e| e.preview(&preview_id))
    }

    fn list_wallets(&self, network: String) -> String {
        self.with(|e| e.list_wallets(&network))
    }

    fn clear_suspect(&self, source: String) -> String {
        self.backend_with(|e| e.clear_suspect(&source))
    }

    fn reload_routes(&self) -> String {
        self.backend_with(|e| e.reload_routes())
    }

    fn on_context_ready(&self, ctx: &RustModuleContext) {
        let dir = std::path::PathBuf::from(&ctx.instance_persistence_path);
        crate::storage::init_log(&dir);
        // A local test chain's loopback servers, for test harnesses only.
        if let Some(cfg) = std::fs::read_to_string(dir.join("regtest.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<crate::network::RegtestConfig>(&t).ok())
        {
            crate::network::configure_regtest(cfg);
        }
        *self.callers.lock().unwrap() = Callers::from_file(std::fs::read_to_string(dir.join("callers.json")).ok().as_deref());
        let sink: Sink = Arc::new(|ev| {
            if UNLOADING.load(Ordering::SeqCst) {
                return;
            }
            match ev {
                Event::WalletState(v) => emit_wallet_state_changed(&v.to_string()),
                Event::JobFinished { id, state } => emit_job_finished(&id, state),
                Event::SourceAlert(v) => emit_source_alert(&v.to_string()),
                Event::WalletsChanged { locked } => emit_wallets_changed(locked as i64),
            }
        });
        let engine = Engine::new(dir.join("wallets"), sink, Arc::new(ManagerIpc::default()), Some(Arc::new(NodeIpc::default())));
        engine.set_node_source(Arc::new(BitcoindIpc::default()));
        listen(&engine);
        tracing::info!(target: "bitcoin", "ready in {}", dir.display());
        let _ = self.engine.set(engine);
    }
}

static UNLOADING: AtomicBool = AtomicBool::new(false);

/// The manager's handle-only events wake waiters early; its wallet events have the core ask for
/// its keys again; the node's route changes reload routes. Subscribing waits on other modules, so
/// it runs off the dispatch thread, retrying while absent.
fn listen(engine: &Arc<Engine>) {
    let weak = Arc::downgrade(engine);
    std::thread::spawn(move || {
        match weak.upgrade() {
            Some(e) => e.wallets_changed(),
            None => return,
        }
        while !UNLOADING.load(Ordering::SeqCst) {
            let mut c = signer_manager_module::SignerManagerModuleClient::new();
            let subs: Vec<_> = [c.on_wallets_changed(), c.on_wallets_locked()].into_iter().flatten().collect();
            if subs.is_empty() {
                std::thread::sleep(Duration::from_secs(30));
                continue;
            }
            let (tx, rx) = std::sync::mpsc::channel();
            for sub in subs {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    for _ in sub {
                        if tx.send(()).is_err() {
                            return;
                        }
                    }
                });
            }
            drop(tx);
            // One ask at a time; a burst of events is one ask.
            while rx.recv().is_ok() {
                while rx.try_recv().is_ok() {}
                match weak.upgrade() {
                    Some(e) => e.wallets_changed(),
                    None => return,
                }
            }
        }
    });
    let settled = engine.settled.clone();
    std::thread::spawn(move || {
        while !UNLOADING.load(Ordering::SeqCst) {
            let mut c = signer_manager_module::SignerManagerModuleClient::new();
            let subs: Vec<_> = [c.on_approval_settled(), c.on_access_settled()].into_iter().flatten().collect();
            if subs.is_empty() {
                std::thread::sleep(Duration::from_secs(30));
                continue;
            }
            let mut threads = vec![];
            for sub in subs {
                let s = settled.clone();
                threads.push(std::thread::spawn(move || {
                    for ev in sub {
                        if let Some(h) = ev.data.get(0).and_then(Value::as_str) {
                            s.notify(h);
                        }
                    }
                }));
            }
            for t in threads {
                let _ = t.join();
            }
        }
    });
    let weak = Arc::downgrade(engine);
    std::thread::spawn(move || {
        while !UNLOADING.load(Ordering::SeqCst) {
            let mut p = logos_rust_sdk::LogosModuleSDK::new().plugin("bitcoin_node_module");
            match p.on("routes_changed") {
                Ok(sub) => {
                    for _ in sub {
                        match weak.upgrade() {
                            Some(e) => {
                                e.reload_routes();
                            }
                            None => return,
                        }
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_secs(30)),
            }
        }
    });
}

/// The manager's budget per call; the rest is IPC slack.
const BUDGET: Duration = Duration::from_secs(20);

/// Waits for an async reply here: a blocking call would wait in a nested event loop on the main
/// thread, where concurrent ones return only innermost first. Unload answers waiters at once.
fn wait<T>(rx: Receiver<Result<T, LogosError>>) -> Result<T, String> {
    let start = Instant::now();
    loop {
        if UNLOADING.load(Ordering::SeqCst) {
            return Err("unloading".into());
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(r) => return r.map_err(|e| e.to_string()),
            Err(RecvTimeoutError::Timeout) if start.elapsed() < BUDGET + Duration::from_secs(5) => continue,
            Err(_) => return Err("no answer".into()),
        }
    }
}

/// `signer_manager_module` over IPC; one client, made on first use and kept.
#[derive(Default)]
struct ManagerIpc(OnceLock<signer_manager_module::SignerManagerModuleClient>);

impl ManagerIpc {
    fn c(&self) -> &signer_manager_module::SignerManagerModuleClient {
        self.0.get_or_init(signer_manager_module::SignerManagerModuleClient::new)
    }
}

macro_rules! ipc {
    ($self:ident, $method:ident, $($arg:expr),*) => {{
        let (tx, rx) = sync_channel(1);
        $self.c().$method($($arg,)* BUDGET, move |r| {
            let _ = tx.send(r);
        });
        wait(rx)
    }};
}

impl SignerManager for ManagerIpc {
    fn request_open(&self, p: &str) -> Result<String, String> {
        ipc!(self, request_open_async_with_timeout, p)
    }
    fn request_approval(&self, intent: &str) -> Result<String, String> {
        ipc!(self, request_approval_async_with_timeout, intent)
    }
    fn approval_status(&self, h: &str, r: &str) -> Result<String, String> {
        ipc!(self, approval_status_async_with_timeout, h, r)
    }
    fn fetch_result(&self, h: &str, r: &str) -> Result<String, String> {
        ipc!(self, fetch_result_async_with_timeout, h, r)
    }
    fn ack_result(&self, h: &str, r: &str) -> Result<bool, String> {
        ipc!(self, ack_result_async_with_timeout, h, r)
    }
    fn cancel_approval(&self, h: &str, r: &str) -> Result<bool, String> {
        ipc!(self, cancel_approval_async_with_timeout, h, r)
    }
    fn close_account(&self, p: &str) -> Result<String, String> {
        ipc!(self, close_account_async_with_timeout, p)
    }
    fn data_key(&self, p: &str) -> Result<String, String> {
        ipc!(self, data_key_async_with_timeout, p)
    }
}

/// `bitcoin_node_module`, by name: its contract isn't pinned here.
#[derive(Default)]
struct NodeIpc(OnceLock<logos_rust_sdk::PluginProxy>);

impl NodeIpc {
    fn p(&self) -> &logos_rust_sdk::PluginProxy {
        self.0.get_or_init(|| logos_rust_sdk::LogosModuleSDK::new().plugin("bitcoin_node_module"))
    }
}

impl RouteSource for NodeIpc {
    fn route_table(&self, network: &str) -> Result<String, String> {
        let (tx, rx) = sync_channel(1);
        self.p().call_json_async_with_timeout("route_table", &json!([network]), BUDGET, move |r| {
            let _ = tx.send(r);
        });
        let v = wait(rx)?;
        Ok(v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))
    }

    fn report_mismatch(&self, network: &str, source: &str, kind: &str, height: Option<u32>) {
        let h = height.map(|h| h.to_string()).unwrap_or_default();
        self.p().call_json_async_with_timeout("report_mismatch", &json!([network, source, kind, h]), BUDGET, |_| {});
    }

    fn report_peers(&self, network: &str, report: &str) {
        self.p().call_json_async_with_timeout("report_peers", &json!([network, report]), BUDGET, |_| {});
    }

    fn source_credentials(&self, network: &str, source: &str) -> Result<Option<(String, String)>, String> {
        let (tx, rx) = sync_channel(1);
        self.p().call_json_async_with_timeout("source_credentials", &json!([network, source]), BUDGET, move |r| {
            let _ = tx.send(r);
        });
        let v = wait(rx)?;
        let reply: Value = match v.as_str() {
            Some(s) => serde_json::from_str(s).map_err(|e| e.to_string())?,
            None => v,
        };
        if reply["ok"] != true {
            return Err(reply["error"].as_str().unwrap_or("source_credentials refused").to_string());
        }
        Ok(match (reply["username"].as_str(), reply["password"].as_str()) {
            (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
            _ => None,
        })
    }
}

/// `bitcoind_module`'s rpc, by name: the local node is optional, so not a declared dependency.
#[derive(Default)]
struct BitcoindIpc(OnceLock<logos_rust_sdk::PluginProxy>);

impl crate::node::NodeRpc for BitcoindIpc {
    fn rpc(&self, method: &str, params: &str) -> Result<String, String> {
        let p = self.0.get_or_init(|| logos_rust_sdk::LogosModuleSDK::new().plugin("bitcoind_module"));
        let (tx, rx) = sync_channel(1);
        p.call_json_async_with_timeout("rpc", &json!([method, params]), BUDGET, move |r| {
            let _ = tx.send(r);
        });
        let v = wait(rx)?;
        Ok(v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))
    }
}

impl AboutToUnload for BitcoinWalletCoreModuleImpl {
    /// Stops sync between bounded steps and closes the database within the host's grace period.
    /// IPC waits are answered first: their replies would need this thread.
    fn about_to_unload(&self) -> Shutdown {
        let t0 = Instant::now();
        UNLOADING.store(true, Ordering::SeqCst);
        if let Some(e) = self.engine.get() {
            e.shutdown();
        }
        tracing::info!(target: "bitcoin", "unloaded in {} ms", t0.elapsed().as_millis());
        Shutdown::Synchronous
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    logos_install!(BitcoinWalletCoreModuleImpl);
}
