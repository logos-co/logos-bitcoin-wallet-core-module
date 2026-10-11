//! The engine behind the module: jobs with receipts, the open wallet with its sync thread, sends,
//! and reads that never wait on the wallet for more than 750 ms.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bdk_electrum::electrum_client::ElectrumApi;
use bitcoin::{OutPoint, Psbt, Transaction, Txid};
use parking_lot::Mutex;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::authority::{Authority, ServerAuthority};
use crate::jobs::Jobs;
use crate::ledger::Ledger;
use crate::manager::{self, ManagerRef, Settled, Ticket};
use crate::network::{regtest_config, BNetwork, Family};
use crate::routes::{Kind, Routes, Source};
use crate::send::{self, Outcome};
use crate::storage::{meta_get, meta_set};
use crate::sync::{self, Ctx, NetState, Note, Progress, RouteSource};
use crate::wallet::{self, Cell, SendRecord};
use crate::walletdir::{self, now_secs, WalletDir};

pub enum Event {
    WalletState(Value),
    JobFinished { id: String, state: &'static str },
    SourceAlert(Value),
}

pub type Sink = Arc<dyn Fn(Event) + Send + Sync>;

/// A read never waits longer than this for the wallet; past it, it answers busy.
pub const READ_WAIT: Duration = Duration::from_millis(750);
/// A tip older than this is never "synced".
pub const STALE_TIP_SECS: u64 = 3600;
/// An open waits this long at most; the manager expires an unshown request after 5 minutes.
const OPEN_LIMIT: Duration = Duration::from_secs(6 * 3600);
/// A shown approval has no timeout on the person; this only bounds a forgotten one.
const APPROVAL_LIMIT: Duration = Duration::from_secs(6 * 3600);

/// Job kinds only the wallet backend may start.
pub fn backend_only(kind: &str) -> bool {
    matches!(kind, "sign_and_broadcast" | "cancel_send" | "abandon_send")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    NoWallet,
    AwaitingOpen,
    Opening,
    Syncing,
    Ready,
    Closing,
    Failed,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::NoWallet => "no_wallet",
            State::AwaitingOpen => "awaiting_open",
            State::Opening => "opening",
            State::Syncing => "syncing",
            State::Ready => "ready",
            State::Closing => "closing",
            State::Failed => "failed",
        }
    }
}

#[derive(Clone)]
struct Light {
    state: State,
    network: Option<BNetwork>,
    group: Option<String>,
    family: Option<Family>,
    open_handle: Option<String>,
    approval_handle: Option<String>,
    last_error: Option<String>,
    birthday: Option<u32>,
    birthday_source: Option<String>,
    needs_birthday: bool,
}

impl Default for Light {
    fn default() -> Self {
        Self {
            state: State::NoWallet,
            network: None,
            group: None,
            family: None,
            open_handle: None,
            approval_handle: None,
            last_error: None,
            birthday: None,
            birthday_source: None,
            needs_birthday: false,
        }
    }
}

struct OpenWallet {
    group: String,
    family: Family,
    network: BNetwork,
    cell: Arc<Mutex<Option<Cell>>>,
    /// Held while the wallet is open, zeroized when this drops.
    _key: Zeroizing<[u8; 32]>,
    descriptors: (Zeroizing<String>, Zeroizing<String>),
    stop: Arc<AtomicBool>,
    wake: Arc<AtomicBool>,
    reload: Arc<AtomicBool>,
    netstate: Arc<Mutex<NetState>>,
    progress: Arc<Mutex<Progress>>,
    thread: Option<JoinHandle<()>>,
}

pub struct Preview {
    kind: &'static str,
    psbt: Psbt,
    inputs: Vec<OutPoint>,
    replaces: Option<Txid>,
    json: Value,
    ticket: Option<Ticket>,
    state: String,
    cancel: Arc<AtomicBool>,
    busy: bool,
}

/// How a birthday hint is given: a height, or a UTC day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Birthday {
    Height(u32),
    Day(String),
}

enum Task {
    Open { network: BNetwork, group: Option<String>, family: Option<Family>, birthday: Option<Birthday> },
    Close,
    BuildSend(Value),
    BumpFee { txid: Txid, fee_rate: f64 },
    SignAndBroadcast { preview: String },
    CancelSend { preview: String },
    Rebroadcast { txid: Txid },
    Abandon { txid: Txid },
}

struct Queue {
    items: std::sync::Mutex<VecDeque<(String, Task, Arc<AtomicBool>)>>,
    ready: Condvar,
    closed: AtomicBool,
}

pub struct Engine {
    root: PathBuf,
    sink: Sink,
    manager: ManagerRef,
    routes_src: Option<Arc<dyn RouteSource>>,
    pub settled: Arc<Settled>,
    rt: Mutex<Option<tokio::runtime::Runtime>>,
    rt_handle: tokio::runtime::Handle,
    jobs: Arc<std::sync::Mutex<Jobs>>,
    queue: Arc<Queue>,
    worker: std::sync::Mutex<Option<JoinHandle<()>>>,
    light: Mutex<Light>,
    open: Mutex<Option<OpenWallet>>,
    previews: Mutex<HashMap<String, Preview>>,
    next_preview: AtomicU64,
    pending_open: Mutex<Option<Arc<AtomicBool>>>,
    last_emitted: Mutex<String>,
    closed: AtomicBool,
}

fn parse_task(kind: &str, raw: &str) -> Result<Task, String> {
    let v: Value = if raw.trim().is_empty() { json!({}) } else { serde_json::from_str(raw).map_err(|e| format!("params: {e}"))? };
    let obj = v.as_object().ok_or("params must be a JSON object")?;
    let allowed: &[&str] = match kind {
        "open_wallet" => &["network", "group", "family", "birthday"],
        "close_wallet" => &[],
        "build_send" => &["recipients", "feeRate", "target", "sendMax"],
        "bump_fee" => &["txid", "feeRate"],
        "sign_and_broadcast" | "cancel_send" => &["previewId"],
        "rebroadcast" | "abandon_send" => &["txid"],
        other => return Err(format!("unknown job kind {other}")),
    };
    if let Some(k) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("unknown field {k}"));
    }
    let txid = || -> Result<Txid, String> { Txid::from_str(v["txid"].as_str().ok_or("txid is required")?).map_err(|_| "txid is not a txid".to_string()) };
    let preview = || -> Result<String, String> { v["previewId"].as_str().map(str::to_string).ok_or_else(|| "previewId is required".to_string()) };
    Ok(match kind {
        "open_wallet" => {
            let network = v["network"].as_str().and_then(BNetwork::parse).ok_or("network must be mainnet, testnet4, signet or regtest")?;
            let group = match v["group"].as_str() {
                Some(g) if walletdir::valid_group(g) => Some(g.to_string()),
                Some(_) => return Err("not a keystore group".into()),
                None => None,
            };
            let family = match v["family"].as_str() {
                Some(f) => Some(Family::parse(f).ok_or("family must be bitcoin or bitcoin_taproot")?),
                None => None,
            };
            if group.is_none() && family.is_none() {
                return Err("name a group to reopen, or a family".into());
            }
            let birthday = match &v["birthday"] {
                Value::Null => None,
                Value::Number(n) => Some(Birthday::Height(n.as_u64().filter(|h| *h <= u32::MAX as u64).ok_or("birthday height must be a whole number")? as u32)),
                Value::String(s) if wallet::day_to_unix(s).is_some() => Some(Birthday::Day(s.clone())),
                _ => return Err("birthday must be a height or a YYYY-MM-DD day".into()),
            };
            Task::Open { network, group, family, birthday }
        }
        "close_wallet" => Task::Close,
        "build_send" => Task::BuildSend(v.clone()),
        "bump_fee" => Task::BumpFee {
            txid: txid()?,
            fee_rate: v["feeRate"].as_f64().filter(|r| r.is_finite() && *r > 0.0).ok_or("feeRate is required, in sat/vB")?,
        },
        "sign_and_broadcast" => Task::SignAndBroadcast { preview: preview()? },
        "cancel_send" => Task::CancelSend { preview: preview()? },
        "rebroadcast" => Task::Rebroadcast { txid: txid()? },
        "abandon_send" => Task::Abandon { txid: txid()? },
        _ => unreachable!(),
    })
}

impl Engine {
    pub fn new(root: PathBuf, sink: Sink, manager: ManagerRef, routes_src: Option<Arc<dyn RouteSource>>) -> Arc<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("bitcoin-net").enable_all().build().expect("tokio runtime");
        let rt_handle = rt.handle().clone();
        let engine = Arc::new(Self {
            root,
            sink,
            manager,
            routes_src,
            settled: Arc::default(),
            rt: Mutex::new(Some(rt)),
            rt_handle,
            jobs: Arc::default(),
            queue: Arc::new(Queue { items: Default::default(), ready: Condvar::new(), closed: AtomicBool::new(false) }),
            worker: Default::default(),
            light: Mutex::new(Light::default()),
            open: Mutex::new(None),
            previews: Mutex::new(HashMap::new()),
            next_preview: AtomicU64::new(0),
            pending_open: Mutex::new(None),
            last_emitted: Mutex::new(String::new()),
            closed: AtomicBool::new(false),
        });
        let weak = Arc::downgrade(&engine);
        let q = engine.queue.clone();
        let handle = std::thread::Builder::new()
            .name("bitcoin-jobs".into())
            .spawn(move || loop {
                let next = {
                    let mut items = q.items.lock().unwrap();
                    loop {
                        if q.closed.load(Ordering::SeqCst) {
                            return;
                        }
                        if let Some(n) = items.pop_front() {
                            break n;
                        }
                        items = q.ready.wait(items).unwrap();
                    }
                };
                let Some(engine) = weak.upgrade() else { return };
                engine.run(next.0, next.1, next.2);
            })
            .expect("job thread");
        *engine.worker.lock().unwrap() = Some(handle);
        engine
    }

    pub fn jobs(&self) -> std::sync::MutexGuard<'_, Jobs> {
        self.jobs.lock().unwrap()
    }

    pub fn start_job(self: &Arc<Self>, kind: &str, params: &str) -> Value {
        if self.closed.load(Ordering::SeqCst) {
            return json!({"ok": false, "error": "unloading"});
        }
        let task = match parse_task(kind, params) {
            Ok(t) => t,
            Err(e) => return json!({"ok": false, "error": e}),
        };
        let (id, receipt, cancel) = self.jobs.lock().unwrap().add(kind);
        match task {
            // These wait on a person, so they don't hold up the worker.
            Task::Open { .. } | Task::SignAndBroadcast { .. } => {
                let me = self.clone();
                let (jid, flag) = (id.clone(), cancel.clone());
                let spawned = std::thread::Builder::new().name("bitcoin-person".into()).spawn(move || me.run(jid, task, flag));
                if let Err(e) = spawned {
                    self.jobs.lock().unwrap().finish(&id, Err(e.to_string()));
                }
            }
            _ => {
                self.queue.items.lock().unwrap().push_back((id.clone(), task, cancel));
                self.queue.ready.notify_one();
            }
        }
        json!({"ok": true, "jobId": id, "receipt": receipt})
    }

    fn run(self: &Arc<Self>, id: String, task: Task, cancel: Arc<AtomicBool>) {
        if !self.jobs.lock().unwrap().begin(&id) {
            return;
        }
        let outcome = match task {
            Task::Open { network, group, family, birthday } => self.open_flow(network, group, family, birthday, cancel),
            Task::Close => Ok(json!({"closed": self.close(true)})),
            Task::BuildSend(v) => self.build_send(&v),
            Task::BumpFee { txid, fee_rate } => self.bump_fee(txid, fee_rate),
            Task::SignAndBroadcast { preview } => self.sign_and_broadcast(&preview, cancel),
            Task::CancelSend { preview } => self.cancel_send(&preview),
            Task::Rebroadcast { txid } => self.rebroadcast(txid),
            Task::Abandon { txid } => self.abandon(txid),
        };
        if let Err(e) = &outcome {
            tracing::info!(target: "bitcoin", "job {id} failed: {e}");
        }
        if let Some(state) = self.jobs.lock().unwrap().finish(&id, outcome) {
            self.emit(Event::JobFinished { id, state: state.as_str() });
        }
    }

    fn emit(&self, e: Event) {
        if !self.closed.load(Ordering::SeqCst) {
            (self.sink)(e);
        }
    }

    fn set_light(&self, f: impl FnOnce(&mut Light)) {
        f(&mut self.light.lock());
        self.emit_state();
    }

    /// Emits `walletStateChanged` when what status says has changed.
    fn emit_state(&self) {
        let s = self.status_inner(false);
        let digest = json!([s["state"], s["synced"], s["authority"]["height"], s["openHandle"], s["approvalHandle"], s["lastError"], s["historyServer"], s["needsBirthday"]]).to_string();
        let mut last = self.last_emitted.lock();
        if *last != digest {
            *last = digest;
            drop(last);
            self.emit(Event::WalletState(s));
        }
    }

    fn notify(self: &Arc<Self>) -> sync::Notify {
        let weak = Arc::downgrade(self);
        Arc::new(move |n| {
            let Some(e) = weak.upgrade() else { return };
            match n {
                Note::State => e.emit_state(),
                Note::Alert { source, kind, detail } => {
                    let l = e.light.lock().clone();
                    e.emit(Event::SourceAlert(json!({"source": source, "kind": kind, "detail": detail, "at": now_secs(),
                        "network": l.network.map(|n| n.name()), "group": l.group})));
                }
            }
        })
    }

    // ── Opening and closing ──────────────────────────────────────────────

    fn open_flow(self: &Arc<Self>, network: BNetwork, group: Option<String>, family: Option<Family>, birthday: Option<Birthday>, cancel: Arc<AtomicBool>) -> Result<Value, String> {
        if let Some(prev) = self.pending_open.lock().replace(cancel.clone()) {
            prev.store(true, Ordering::SeqCst);
        }
        let r = self.open_flow_inner(network, group, family, birthday, &cancel);
        self.pending_open.lock().take();
        if let Err(e) = &r {
            let failed = !matches!(e.as_str(), "cancelled");
            self.set_light(|l| {
                l.open_handle = None;
                if l.state == State::AwaitingOpen || l.state == State::Opening {
                    l.state = if failed { State::Failed } else { State::NoWallet };
                    l.last_error = failed.then(|| e.clone());
                }
            });
        }
        r
    }

    fn open_flow_inner(self: &Arc<Self>, network: BNetwork, group: Option<String>, family: Option<Family>, birthday: Option<Birthday>, cancel: &AtomicBool) -> Result<Value, String> {
        self.close_open(true);
        self.set_light(|l| {
            *l = Light { state: State::AwaitingOpen, network: Some(network), group: group.clone(), family, ..Light::default() };
        });
        let req = manager::open_params(network, group.as_deref(), family)?;
        let reply = self.manager.request_open(&req).map_err(|e| format!("signer_manager_module: {e}"))?;
        let ticket = manager::ticket(&reply)?;
        tracing::info!(target: "bitcoin", "open requested: {}", ticket.handle);
        self.set_light(|l| l.open_handle = Some(ticket.handle.clone()));
        let reason = manager::wait_settled(&*self.manager, &ticket, &self.settled, cancel, OPEN_LIMIT, |_| {})?;
        self.set_light(|l| l.open_handle = None);
        manager::require_approved(&reason)?;
        let mut grant = None;
        for _ in 0..20 {
            let r = self.manager.fetch_result(&ticket.handle, &ticket.receipt).map_err(|e| format!("signer_manager_module: {e}"))?;
            if let Some(g) = manager::open_grant(&r, network)? {
                grant = Some(g);
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let grant = grant.ok_or("the approved open has no result")?;
        let checked = (|| {
            if !walletdir::valid_group(&grant.group) {
                return Err("the keystore named an unusable group".to_string());
            }
            if group.as_ref().is_some_and(|g| *g != grant.group) {
                return Err("the keystore opened another wallet than the one asked".to_string());
            }
            if family.is_some_and(|f| f != grant.family) {
                return Err("the keystore opened a wallet of another family".to_string());
            }
            Ok(())
        })();
        let opened = checked.and_then(|_| {
            self.set_light(|l| {
                l.state = State::Opening;
                l.group = Some(grant.group.clone());
                l.family = Some(grant.family);
            });
            self.open_with(network, grant, birthday)
        });
        let _ = self.manager.ack_result(&ticket.handle, &ticket.receipt);
        if opened.is_err() {
            if let Some(g) = self.light.lock().group.clone() {
                let _ = self.manager.close_account(&json!({"group": g}).to_string());
            }
        }
        opened
    }

    fn open_with(self: &Arc<Self>, network: BNetwork, grant: manager::OpenGrant, birthday: Option<Birthday>) -> Result<Value, String> {
        let wallets = self.root.clone();
        let dir = WalletDir::new(&wallets, network, &grant.group);
        let existed = dir.exists();
        let meta = if existed {
            let m = dir.meta().map_err(|e| e.to_string())?;
            if m.family != grant.family || m.network != network {
                return Err("the stored wallet is of another family or network".into());
            }
            m
        } else {
            WalletDir::new_meta(&grant.group, grant.family, network)
        };
        // A new database key (a device account's data password forgotten) can't open the old
        // database: it is set aside and the wallet resyncs from its birthday.
        let (mut conn, reset) = match dir.open(&wallets, &meta, &grant.database_key) {
            Ok(c) => (c, None),
            Err(walletdir::DirError::Storage(crate::storage::StorageError::WrongKey)) if existed => {
                let aside = dir.set_aside().map_err(|e| e.to_string())?;
                tracing::warn!(target: "bitcoin", "{}: the database key changed; set the old database aside as {}", meta.group, aside.display());
                (dir.open(&wallets, &meta, &grant.database_key).map_err(|e| e.to_string())?, Some(aside))
            }
            Err(e) => return Err(e.to_string()),
        };
        let (pw, created) = wallet::load_or_create(&mut conn, &grant.external, &grant.internal, network)?;
        let mut cell = Cell { wallet: pw, conn, network, family: grant.family };
        let now = now_secs();
        let authority = ServerAuthority::restore(network, cell.load_headers()?, cell.load_old()?, now as u32);
        let stored = meta_get(&cell.conn, "birthday").map_err(|e| e.to_string())?.and_then(|s| s.parse::<u32>().ok());
        let stored_src = meta_get(&cell.conn, "birthday_source").map_err(|e| e.to_string())?;
        let (bday, source) = resolve_birthday(birthday, grant.birthday.as_deref(), stored.zip(stored_src), authority.chain(), network, grant.family);
        meta_set(&cell.conn, "birthday", &bday.to_string()).map_err(|e| e.to_string())?;
        meta_set(&cell.conn, "birthday_source", &source).map_err(|e| e.to_string())?;
        if let Some(o) = &grant.origin {
            meta_set(&cell.conn, "origin", o).map_err(|e| e.to_string())?;
        }
        let origin = grant.origin.clone().or(meta_get(&cell.conn, "origin").map_err(|e| e.to_string())?);
        let needs_birthday = source == "activation" && origin.as_deref() != Some("created");
        release_stale_locks(&mut cell)?;
        cell.persist()?;
        let full_scan_done = meta_get(&cell.conn, "full_scan_done").map_err(|e| e.to_string())?.is_some();
        let mut ledger = Ledger::default();
        for e in cell.load_exposure()? {
            ledger.exposure.insert(e.source.clone(), e);
        }
        for (s, why) in cell.load_suspects()? {
            ledger.suspect(&s, &why);
        }
        let (routes, routes_err) = self.routes_for(network);
        let netstate = Arc::new(Mutex::new(NetState { routes, ledger, iso: HashMap::new() }));
        let progress = Arc::new(Mutex::new(Progress { full_scan_done, authority: authority.summary(now), last_error: routes_err.clone(), ..Default::default() }));
        let cell = Arc::new(Mutex::new(Some(cell)));
        let (stop, wake, reload) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(routes_err.is_some())));
        let ctx = Ctx {
            net: network,
            family: grant.family,
            birthday: bday,
            cell: cell.clone(),
            netstate: netstate.clone(),
            progress: progress.clone(),
            stop: stop.clone(),
            wake: wake.clone(),
            reload_routes: reload.clone(),
            notify: self.notify(),
            rt: self.rt_handle.clone(),
            routes_src: self.routes_src.clone().filter(|_| network != BNetwork::Regtest),
        };
        let thread = sync::spawn(ctx, Box::new(authority)).map_err(|e| e.to_string())?;
        let result = json!({
            "group": grant.group, "family": grant.family, "network": network.name(), "created": created || !existed,
            "reset": reset.is_some(),
            "fingerprint": grant.fingerprint, "birthday": {"height": bday, "source": source}, "needsBirthday": needs_birthday,
        });
        *self.open.lock() = Some(OpenWallet {
            group: grant.group.clone(),
            family: grant.family,
            network,
            cell,
            _key: grant.database_key,
            descriptors: (Zeroizing::new(grant.external), Zeroizing::new(grant.internal)),
            stop,
            wake,
            reload,
            netstate,
            progress,
            thread: Some(thread),
        });
        self.set_light(|l| {
            l.state = State::Syncing;
            l.birthday = Some(bday);
            l.birthday_source = Some(source.clone());
            l.needs_birthday = needs_birthday;
            l.last_error = None;
        });
        tracing::info!(target: "bitcoin", "opened {} on {}", meta.group, network.name());
        Ok(result)
    }

    fn routes_for(&self, network: BNetwork) -> (Routes, Option<String>) {
        if network == BNetwork::Regtest {
            return (regtest_config().map(Routes::regtest).unwrap_or_default(), None);
        }
        match &self.routes_src {
            None => (Routes::default(), Some("no route source: bitcoin_node_module is not available".into())),
            Some(src) => match src.route_table(network.name()).and_then(|r| Routes::from_table(&r)) {
                Ok(r) => (r, None),
                Err(e) => (Routes::default(), Some(format!("route_table: {e}"))),
            },
        }
    }

    /// Cancels an open still waiting on the person, then closes the open wallet.
    pub fn close(&self, tell_manager: bool) -> Option<String> {
        if let Some(c) = self.pending_open.lock().as_ref() {
            c.store(true, Ordering::SeqCst);
        }
        self.close_open(tell_manager)
    }

    /// Stops sync, closes the database, forgets the key, and tells the manager. Returns the group.
    fn close_open(&self, tell_manager: bool) -> Option<String> {
        let taken = self.open.lock().take();
        let mut w = taken?;
        self.set_light(|l| l.state = State::Closing);
        w.stop.store(true, Ordering::SeqCst);
        if let Some(t) = w.thread.take() {
            let until = Instant::now() + Duration::from_millis(1500);
            while !t.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(20));
            }
            if t.is_finished() {
                let _ = t.join();
            }
        }
        {
            let mut g = w.cell.lock();
            if let Some(c) = g.as_mut() {
                let _ = c.persist();
            }
            *g = None;
        }
        for (_, p) in self.previews.lock().drain() {
            p.cancel.store(true, Ordering::SeqCst);
        }
        let group = w.group.clone();
        drop(w);
        if tell_manager {
            match self.manager.close_account(&json!({"group": group}).to_string()) {
                Ok(r) => tracing::info!(target: "bitcoin", "close_account: {r}"),
                Err(e) => tracing::info!(target: "bitcoin", "close_account: {e}"),
            }
        }
        self.set_light(|l| *l = Light::default());
        Some(group)
    }

    /// For unload: everything stops and nothing more is emitted.
    pub fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Some(c) = self.pending_open.lock().as_ref() {
            c.store(true, Ordering::SeqCst);
        }
        self.close(false);
        self.queue.closed.store(true, Ordering::SeqCst);
        self.queue.ready.notify_all();
        if let Some(h) = self.worker.lock().unwrap().take() {
            let until = Instant::now() + Duration::from_millis(500);
            while !h.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
            if h.is_finished() {
                let _ = h.join();
            }
        }
        if let Some(rt) = self.rt.lock().take() {
            rt.shutdown_background();
        }
    }

    fn with_open<T>(&self, f: impl FnOnce(&OpenWallet) -> Result<T, String>) -> Result<T, String> {
        let g = self.open.lock();
        f(g.as_ref().ok_or("no wallet is open")?)
    }

    /// The open wallet's cell for a job: waits up to `wait` for the sync thread to let go.
    fn cell_job<T>(&self, wait: Duration, f: impl FnOnce(&mut Cell) -> Result<T, String>) -> Result<T, String> {
        let cell = self.with_open(|w| Ok(w.cell.clone()))?;
        let mut g = cell.try_lock_for(wait).ok_or("the wallet is busy; try again")?;
        f(g.as_mut().ok_or("the wallet closed")?)
    }

    fn fee_rates(&self) -> crate::fees::FeeRates {
        self.with_open(|w| Ok(w.progress.lock().fees.clone()))
            .ok()
            .flatten()
            .unwrap_or(crate::fees::FeeRates { fast: 1.0, normal: 1.0, slow: 1.0, minimum: 1.0, sources: vec![] })
    }

    fn wake(&self) {
        let _ = self.with_open(|w| {
            w.wake.store(true, Ordering::SeqCst);
            Ok(())
        });
    }

    // ── Sends ─────────────────────────────────────────────────────────────

    fn keep_preview(&self, cell: &Cell, kind: &'static str, psbt: Psbt, inputs: Vec<OutPoint>, rate: f64, replaces: Option<Txid>) -> Result<Value, String> {
        let id = format!("p{}", self.next_preview.fetch_add(1, Ordering::SeqCst) + 1);
        let json = send::preview_json(cell, &id, kind, &psbt, rate, replaces)?;
        self.previews.lock().insert(
            id,
            Preview { kind, psbt, inputs, replaces, json: json.clone(), ticket: None, state: "built".into(), cancel: Arc::new(AtomicBool::new(false)), busy: false },
        );
        Ok(json)
    }

    fn build_send(&self, v: &Value) -> Result<Value, String> {
        let (net, known) = self.with_open(|w| Ok((w.network, w.progress.lock().fees.is_some())))?;
        let input = send::parse_input(v, net)?;
        if input.fee_rate.is_none() && !known {
            return Err("no fee estimate yet: give feeRate, or wait for the fee sources".into());
        }
        let rate = send::rate_for(input.fee_rate, input.target.as_deref(), &self.fee_rates())?;
        self.cell_job(Duration::from_secs(60), |cell| {
            let psbt = send::build(cell, &input, rate)?;
            let inputs = send::lock(cell, &psbt);
            cell.persist()?;
            self.keep_preview(cell, "send", psbt, inputs, rate, None)
        })
    }

    fn bump_fee(&self, txid: Txid, fee_rate: f64) -> Result<Value, String> {
        let rate = fee_rate.max(self.fee_rates().minimum);
        self.cell_job(Duration::from_secs(60), |cell| {
            if !cell.sends()?.iter().any(|s| s.txid == txid && s.state == "sent") {
                return Err("only an unconfirmed send of this wallet can be bumped".into());
            }
            let psbt = send::build_bump(cell, txid, rate)?;
            let inputs = send::lock(cell, &psbt);
            cell.persist()?;
            self.keep_preview(cell, "fee_bump", psbt, inputs, rate, Some(txid))
        })
    }

    fn update_preview(&self, id: &str, f: impl FnOnce(&mut Preview)) {
        if let Some(p) = self.previews.lock().get_mut(id) {
            f(p);
            p.json["state"] = json!(p.state);
            p.json["approvalHandle"] = json!(p.ticket.as_ref().map(|t| t.handle.clone()));
        }
    }

    fn sign_and_broadcast(self: &Arc<Self>, id: &str, cancel: Arc<AtomicBool>) -> Result<Value, String> {
        let (group, network, family) = self.with_open(|w| Ok((w.group.clone(), w.network, w.family)))?;
        let (psbt, kind, replaces, inputs) = {
            let mut previews = self.previews.lock();
            let p = previews.get_mut(id).ok_or("unknown or cancelled preview")?;
            if p.busy {
                return Err("this preview is already being signed".into());
            }
            p.busy = true;
            p.cancel = cancel.clone();
            (p.psbt.clone(), p.kind, p.replaces, p.inputs.clone())
        };
        let r = self.sign_inner(id, &group, network, family, psbt, kind, replaces, inputs, &cancel);
        self.set_light(|l| l.approval_handle = None);
        match &r {
            Ok(_) => {
                self.previews.lock().remove(id);
            }
            Err(e) => self.update_preview(id, |p| {
                p.busy = false;
                p.ticket = None;
                p.state = format!("failed: {e}");
            }),
        }
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_inner(
        self: &Arc<Self>,
        id: &str,
        group: &str,
        network: BNetwork,
        family: Family,
        psbt: Psbt,
        kind: &str,
        replaces: Option<Txid>,
        inputs: Vec<OutPoint>,
        cancel: &AtomicBool,
    ) -> Result<Value, String> {
        let purpose = if kind == "fee_bump" { "Raise the fee of a Bitcoin send" } else { "Bitcoin send" };
        let intent = manager::approval_intent(group, purpose, network, &psbt.to_string());
        if intent.len() > send::MAX_INTENT_BYTES {
            return Err("the transaction is too large to ask for approval".into());
        }
        let reply = self.manager.request_approval(&intent).map_err(|e| format!("signer_manager_module: {e}"))?;
        let ticket = manager::ticket(&reply)?;
        let handle = ticket.handle.clone();
        tracing::info!(target: "bitcoin", "approval requested: {handle}");
        self.update_preview(id, |p| {
            p.state = "awaiting_approval".into();
            p.ticket = Some(Ticket { handle: ticket.handle.clone(), receipt: ticket.receipt.clone() });
        });
        self.set_light(|l| l.approval_handle = Some(handle.clone()));
        let reason = manager::wait_settled(&*self.manager, &ticket, &self.settled, cancel, APPROVAL_LIMIT, |state| {
            self.update_preview(id, |p| p.state = if state == "settled" { "settled".into() } else { format!("awaiting_approval:{state}") });
        })?;
        manager::require_approved(&reason)?;
        let fetched = self.manager.fetch_result(&ticket.handle, &ticket.receipt).map_err(|e| format!("signer_manager_module: {e}"));
        let outcome = fetched.and_then(|r| {
            let signed = manager::signed_psbts(&r)?;
            let [one] = signed.as_slice() else { return Err("expected exactly one signed PSBT".to_string()) };
            let signed = send::parse_psbt(one)?;
            let merged = send::merge_signatures(&psbt, &signed, family)?;
            send::verify_signatures(&merged, family)?;
            let tx = self.cell_job(Duration::from_secs(60), |cell| send::finalize(cell, merged))?;
            if tx.compute_txid() != psbt.unsigned_tx.compute_txid() {
                return Err("the finalized transaction is not the one built".to_string());
            }
            Ok(tx)
        });
        let _ = self.manager.ack_result(&ticket.handle, &ticket.receipt);
        let tx = outcome?;
        self.update_preview(id, |p| p.state = "broadcasting".into());
        let txid = tx.compute_txid();
        let (out, via) = self.broadcast(&tx)?;
        self.cell_job(Duration::from_secs(60), |cell| {
            cell.store_send(&SendRecord {
                txid,
                tx: tx.clone(),
                inputs: inputs.clone(),
                state: "sent".into(),
                created: now_secs(),
                replaces,
                via: Some(via.clone()),
                broadcast: Some(out.as_str().into()),
            })?;
            if let Some(old) = replaces {
                cell.set_send_state(&old, "replaced")?;
            }
            cell.wallet.apply_unconfirmed_txs([(tx.clone(), now_secs())]);
            cell.persist()
        })?;
        self.wake();
        tracing::info!(target: "bitcoin", "broadcast {txid}: {} via {via}", out.as_str());
        Ok(json!({"txid": txid.to_string(), "broadcast": out.as_str(), "via": via}))
    }

    /// Sends through the broadcast route: the first enabled source that takes it.
    fn broadcast(&self, tx: &Transaction) -> Result<(Outcome, String), String> {
        let (sources, proxy, netstate) = self.with_open(|w| {
            let ns = w.netstate.lock();
            let list: Vec<Source> = ns.routes.broadcast.iter().filter(|s| s.down.is_none() && ns.ledger.health.get(&s.id).is_none_or(|h| h.suspect.is_none())).cloned().collect();
            Ok((list, ns.routes.proxy.clone(), w.netstate.clone()))
        })?;
        if sources.is_empty() {
            return Err("no source is enabled for broadcast".into());
        }
        let txid = tx.compute_txid();
        let mut maybe_left: Option<String> = None;
        for s in sources {
            let iso = netstate.lock().iso(&s.id);
            let sent: Result<Outcome, String> = match s.kind {
                Kind::Electrum => crate::net::electrum(&s, proxy.as_ref(), &iso).and_then(|c| match c.transaction_broadcast(tx) {
                    Ok(_) => Ok(if c.transaction_get(&txid).is_ok() { Outcome::Seen } else { Outcome::Requested }),
                    Err(e) => Err(e.to_string()),
                }),
                Kind::Esplora => {
                    let creds = match (&self.routes_src, s.credentials) {
                        (Some(r), true) => r.source_credentials(&self.light.lock().network.map(|n| n.name()).unwrap_or_default(), &s.id)?.map(Zeroizing::new),
                        _ => None,
                    };
                    let c = crate::net::esplora(&s, proxy.as_ref(), &iso, creds.as_deref())?;
                    match self.rt_handle.block_on(c.broadcast(tx)) {
                        Ok(()) => Ok(if self.rt_handle.block_on(c.get_tx(&txid)).ok().flatten().is_some() { Outcome::Seen } else { Outcome::Requested }),
                        Err(e) => Err(e.to_string()),
                    }
                }
            };
            netstate.lock().ledger.expose(&s, "broadcast", now_secs());
            match sent {
                Ok(o) => return Ok((o, s.id)),
                Err(e) if send::already_known(&e) => return Ok((Outcome::Seen, s.id)),
                Err(e) if send::refused(&e) => return Err(format!("{} refused the transaction: {e}", s.id)),
                Err(e) => {
                    tracing::info!(target: "bitcoin", "broadcast via {}: {e}", s.id);
                    maybe_left = Some(s.id);
                }
            }
        }
        match maybe_left {
            Some(via) => Ok((Outcome::Unknown, via)),
            None => Err("no broadcast source answered".into()),
        }
    }

    fn cancel_send(&self, id: &str) -> Result<Value, String> {
        let p = {
            let mut previews = self.previews.lock();
            match previews.get(id) {
                None => return Err("unknown or settled preview".into()),
                Some(p) if p.state == "broadcasting" => return Err("too late: the transaction is going out".into()),
                Some(_) => previews.remove(id).expect("present"),
            }
        };
        p.cancel.store(true, Ordering::SeqCst);
        if let Some(t) = &p.ticket {
            let _ = self.manager.cancel_approval(&t.handle, &t.receipt);
        }
        let unlocked = self.cell_job(Duration::from_secs(60), |cell| {
            let live: std::collections::HashSet<OutPoint> = cell.sends()?.iter().filter(|s| s.state == "sent").flat_map(|s| s.inputs.clone()).collect();
            let mut out = vec![];
            for op in &p.inputs {
                if !live.contains(op) {
                    cell.wallet.unlock_outpoint(*op);
                    out.push(op.to_string());
                }
            }
            cell.persist()?;
            Ok(out)
        })?;
        self.set_light(|l| {
            if p.ticket.as_ref().is_some_and(|t| l.approval_handle.as_deref() == Some(t.handle.as_str())) {
                l.approval_handle = None;
            }
        });
        Ok(json!({"cancelled": true, "previewId": id, "unlocked": unlocked}))
    }

    fn rebroadcast(&self, txid: Txid) -> Result<Value, String> {
        let tx = self.cell_job(Duration::from_secs(30), |cell| {
            if let Some(s) = cell.sends()?.into_iter().find(|s| s.txid == txid) {
                return Ok(s.tx);
            }
            cell.wallet.tx_graph().get_tx(txid).map(|t| (*t).clone()).ok_or_else(|| "unknown transaction".to_string())
        })?;
        let (out, via) = self.broadcast(&tx)?;
        Ok(json!({"txid": txid.to_string(), "broadcast": out.as_str(), "via": via}))
    }

    fn abandon(&self, txid: Txid) -> Result<Value, String> {
        self.cell_job(Duration::from_secs(60), |cell| {
            let s = cell.sends()?.into_iter().find(|s| s.txid == txid && s.state == "sent").ok_or("no unconfirmed send with that txid")?;
            for op in &s.inputs {
                cell.wallet.unlock_outpoint(*op);
            }
            cell.set_send_state(&txid, "abandoned")?;
            cell.wallet.apply_evicted_txs([(txid, now_secs())]);
            cell.persist()?;
            Ok(json!({"abandoned": txid.to_string(), "unlocked": s.inputs.iter().map(|o| o.to_string()).collect::<Vec<_>>()}))
        })
    }

    // ── Reads ─────────────────────────────────────────────────────────────

    fn status_inner(&self, wait_wallet: bool) -> Value {
        let l = self.light.lock().clone();
        let mut v = json!({
            "ok": true, "state": l.state.as_str(), "network": l.network.map(|n| n.name()), "group": l.group,
            "family": l.family, "openHandle": l.open_handle, "approvalHandle": l.approval_handle,
            "needsBirthday": l.needs_birthday, "birthday": l.birthday, "birthdaySource": l.birthday_source,
            "lastError": l.last_error, "synced": false, "busy": false,
            "authority": {"kind": null, "height": null, "tipAgeSecs": null, "peers": 0},
        });
        let Some(open) = self.open.try_lock_for(READ_WAIT) else {
            v["busy"] = json!(true);
            return v;
        };
        if let Some(w) = open.as_ref() {
            let p = w.progress.lock().clone();
            let a = &p.authority;
            let fresh = a.tip_age_secs.is_some_and(|age| age <= STALE_TIP_SECS);
            let caught_up = a.height.is_some() && p.synced_tip == a.height;
            v["authority"] = json!(a);
            v["synced"] = json!(fresh && caught_up);
            v["historyServer"] = json!(p.history_server);
            v["lastHistorySync"] = json!(p.last_history_sync);
            if l.state == State::Syncing || l.state == State::Ready {
                v["state"] = json!(if caught_up { "ready" } else { "syncing" });
            }
            if v["lastError"].is_null() {
                v["lastError"] = json!(p.last_error);
            }
            if wait_wallet {
                match w.cell.try_lock_for(READ_WAIT) {
                    Some(g) => {
                        if let Some(c) = g.as_ref() {
                            v["walletTip"] = json!(c.tip_height());
                        }
                    }
                    None => v["busy"] = json!(true),
                }
            }
        }
        v
    }

    pub fn status(&self) -> Value {
        self.status_inner(true)
    }

    /// Runs a read on the cell, or answers busy after 750 ms.
    fn read<T>(&self, f: impl FnOnce(&Cell, &OpenWallet) -> Result<T, String>) -> Result<Option<T>, String> {
        let open = self.open.try_lock_for(READ_WAIT).ok_or("busy")?;
        let w = open.as_ref().ok_or("no wallet is open")?;
        let Some(g) = w.cell.try_lock_for(READ_WAIT) else { return Ok(None) };
        let c = g.as_ref().ok_or("the wallet closed")?;
        f(c, w).map(Some)
    }

    pub fn balance(&self) -> Value {
        let rate = self.fee_rates().normal;
        match self.read(|c, _| Ok(c.balance(&c.held()?, rate))) {
            Ok(Some(mut b)) => {
                b["ok"] = json!(true);
                b["busy"] = json!(false);
                b
            }
            // Busy: empty strings are "not read", never zero.
            Ok(None) => json!({"ok": true, "busy": true, "confirmed": "", "waiting": "", "pending": "", "sent": "", "immature": "", "tooSmall": {"count": null, "sat": ""}}),
            Err(e) => json!({"ok": false, "error": e}),
        }
    }

    pub fn next_address(&self) -> Value {
        let r = self.cell_job(Duration::from_secs(5), |c| c.next_address());
        self.wake();
        match r {
            Ok(mut v) => {
                v["ok"] = json!(true);
                v
            }
            Err(e) => json!({"ok": false, "error": e}),
        }
    }

    fn read_json(&self, f: impl FnOnce(&Cell, &OpenWallet) -> Result<Value, String>, key: &str) -> Value {
        match self.read(f) {
            Ok(Some(v)) => json!({"ok": true, key: v}),
            Ok(None) => json!({"ok": true, "busy": true}),
            Err(e) => json!({"ok": false, "error": e}),
        }
    }

    pub fn addresses(&self) -> Value {
        self.read_json(|c, _| Ok(c.addresses()), "addresses")
    }

    pub fn utxos(&self) -> Value {
        let rate = self.fee_rates().normal;
        self.read_json(|c, _| Ok(c.utxos(rate)), "utxos")
    }

    pub fn history(&self, page: u32) -> Value {
        match self.read(|c, _| c.history(page, 50, &c.held()?)) {
            Ok(Some(mut v)) => {
                v["ok"] = json!(true);
                v
            }
            Ok(None) => json!({"ok": true, "busy": true}),
            Err(e) => json!({"ok": false, "error": e}),
        }
    }

    pub fn fee_rates_json(&self) -> Value {
        match self.with_open(|w| Ok(w.progress.lock().fees.clone())) {
            Ok(Some(f)) => {
                let mut v = json!(f);
                v["ok"] = json!(true);
                v
            }
            Ok(None) => json!({"ok": false, "error": "no fee estimate yet"}),
            Err(e) => json!({"ok": false, "error": e}),
        }
    }

    pub fn sources_status(&self) -> Value {
        match self.with_open(|w| {
            let ns = w.netstate.lock();
            Ok(json!({"ok": true, "proxy": ns.routes.proxy.as_ref().map(|p| p.addr()), "crossCheck": ns.routes.cross_check,
                      "unsupportedChain": ns.routes.unsupported_chain, "sources": ns.ledger.status(&ns.routes)}))
        }) {
            Ok(v) => v,
            Err(e) => json!({"ok": false, "error": e}),
        }
    }

    pub fn exposure(&self) -> Value {
        match self.with_open(|w| Ok(json!({"ok": true, "servers": w.netstate.lock().ledger.exposure.values().collect::<Vec<_>>()}))) {
            Ok(v) => v,
            Err(e) => json!({"ok": false, "error": e}),
        }
    }

    pub fn descriptors(&self) -> Value {
        match self.with_open(|w| Ok(json!({"ok": true, "group": w.group, "external": w.descriptors.0.as_str(), "internal": w.descriptors.1.as_str()}))) {
            Ok(v) => v,
            Err(e) => json!({"ok": false, "error": e}),
        }
    }

    pub fn preview(&self, id: &str) -> Value {
        match self.previews.lock().get(id) {
            Some(p) => {
                let mut v = p.json.clone();
                v["ok"] = json!(true);
                v["state"] = json!(p.state);
                v["approvalHandle"] = json!(p.ticket.as_ref().map(|t| t.handle.clone()));
                v
            }
            None => json!({"ok": false, "error": "unknown preview"}),
        }
    }

    pub fn list_wallets(&self, network: &str) -> Value {
        let Some(n) = BNetwork::parse(network) else { return json!({"ok": false, "error": "unknown network"}) };
        json!({"ok": true, "wallets": walletdir::list(&self.root, n)})
    }

    pub fn clear_suspect(&self, source: &str) -> Value {
        match self.with_open(|w| {
            let had = w.netstate.lock().ledger.clear_suspect(source);
            if let Some(c) = w.cell.lock().as_ref() {
                c.clear_suspect(source)?;
            }
            w.wake.store(true, Ordering::SeqCst);
            Ok(had)
        }) {
            Ok(had) => json!({"ok": true, "cleared": had}),
            Err(e) => json!({"ok": false, "error": e}),
        }
    }

    pub fn reload_routes(&self) -> Value {
        match self.with_open(|w| {
            w.reload.store(true, Ordering::SeqCst);
            w.wake.store(true, Ordering::SeqCst);
            Ok(())
        }) {
            Ok(()) => json!({"ok": true}),
            Err(e) => json!({"ok": false, "error": e}),
        }
    }

    pub fn address_valid(text: &str, network: &str) -> Value {
        match BNetwork::parse(network) {
            Some(n) => crate::address::validate(text, n),
            None => json!({"ok": false, "error": "unknown network"}),
        }
    }
}

/// Override, then a birthday kept from an earlier open, then the keystore's day, then the family's
/// activation height.
pub fn resolve_birthday(
    over: Option<Birthday>,
    keystore_day: Option<&str>,
    stored: Option<(u32, String)>,
    chain: &crate::headers::HeaderChain,
    net: BNetwork,
    family: Family,
) -> (u32, String) {
    let floor = net.activation_height(family);
    let day = |d: &str| wallet::height_for_day(d, net, family, chain);
    match (over, stored, keystore_day) {
        (Some(Birthday::Height(h)), _, _) => (h.max(floor), "override".into()),
        (Some(Birthday::Day(d)), _, _) if day(&d).is_some() => (day(&d).expect("checked"), "override".into()),
        (_, Some((h, src)), _) if src != "activation" => (h, src),
        (_, _, Some(d)) if day(d).is_some() => (day(d).expect("checked"), "keystore".into()),
        _ => (floor, "activation".into()),
    }
}

/// Locks that belong to no live send: previews die with the session that built them.
fn release_stale_locks(cell: &mut Cell) -> Result<(), String> {
    let live: std::collections::HashSet<OutPoint> = cell.sends()?.iter().filter(|s| s.state == "sent").flat_map(|s| s.inputs.clone()).collect();
    let stale: Vec<OutPoint> = cell.wallet.list_locked_outpoints().filter(|o| !live.contains(o)).collect();
    for o in stale {
        cell.wallet.unlock_outpoint(o);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::HeaderChain;

    #[test]
    fn job_params_are_checked_before_queueing() {
        crate::network::configure_regtest(Default::default());
        assert!(parse_task("open_wallet", r#"{"network":"regtest","family":"bitcoin"}"#).is_ok());
        assert!(parse_task("open_wallet", r#"{"network":"regtest"}"#).is_err(), "a group or a family");
        assert!(parse_task("open_wallet", r#"{"network":"regtest","group":"../x"}"#).is_err());
        assert!(parse_task("open_wallet", r#"{"network":"regtest","family":"bitcoin","password":"x"}"#).is_err());
        assert!(parse_task("open_wallet", r#"{"network":"regtest","family":"bitcoin","birthday":"2024-01-01"}"#).is_ok());
        assert!(parse_task("open_wallet", r#"{"network":"regtest","family":"bitcoin","birthday":"soon"}"#).is_err());
        assert!(parse_task("sign_and_broadcast", r#"{"previewId":"p1"}"#).is_ok());
        assert!(parse_task("sign_and_broadcast", r#"{"previewId":"p1","psbt":"x"}"#).is_err());
        assert!(parse_task("bump_fee", r#"{"txid":"nope","feeRate":5}"#).is_err());
        assert!(parse_task("teleport", "{}").is_err());
        assert!(backend_only("sign_and_broadcast") && backend_only("cancel_send") && !backend_only("build_send"));
    }

    /// Opens a native segwit wallet with the BIP84 test vector's account key, under a database
    /// key that changes on every open, as a device account's forgotten data password does.
    struct KeyChanging {
        opens: std::sync::atomic::AtomicU8,
    }

    impl manager::SignerManager for KeyChanging {
        fn request_open(&self, _p: &str) -> Result<String, String> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"ok": true, "handle": "sma_1", "receipt": "r1", "state": "offered"}).to_string())
        }
        fn request_approval(&self, _i: &str) -> Result<String, String> {
            Ok(json!({"ok": false, "error": "not authorized"}).to_string())
        }
        fn approval_status(&self, _h: &str, _r: &str) -> Result<String, String> {
            Ok(json!({"ok": true, "state": "settled", "reason": "approved"}).to_string())
        }
        fn fetch_result(&self, _h: &str, _r: &str) -> Result<String, String> {
            let x = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
            let key = format!("{:02x}", self.opens.load(Ordering::SeqCst)).repeat(32);
            Ok(json!({"ok": true, "result": {"group": "g_reset", "family": "bitcoin", "chain": "test", "network": "regtest",
                "external": format!("wpkh([73c5da0a/84'/1'/0']{x}/0/*)"), "internal": format!("wpkh([73c5da0a/84'/1'/0']{x}/1/*)"),
                "fingerprint": "73c5da0a", "databaseKey": key, "origin": "restored", "birthday": null, "unlocked": null}}).to_string())
        }
        fn ack_result(&self, _h: &str, _r: &str) -> Result<bool, String> {
            Ok(true)
        }
        fn cancel_approval(&self, _h: &str, _r: &str) -> Result<bool, String> {
            Ok(true)
        }
        fn close_account(&self, _p: &str) -> Result<String, String> {
            Ok(json!({"ok": true, "closed": true}).to_string())
        }
    }

    fn finish(e: &Arc<Engine>, kind: &str, params: Value) -> Value {
        let j = e.start_job(kind, &params.to_string());
        let (id, r) = (j["jobId"].as_str().unwrap().to_string(), j["receipt"].as_str().unwrap().to_string());
        let t0 = Instant::now();
        loop {
            let st = e.jobs().status(&id, &r);
            if st["state"] == "done" {
                return e.jobs().result(&id, &r)["result"].clone();
            }
            assert!(st["state"] != "failed" && t0.elapsed() < Duration::from_secs(30), "{kind}: {st}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_new_database_key_sets_the_old_database_aside_and_starts_fresh() {
        crate::network::configure_regtest(Default::default());
        let root = tempfile::tempdir().unwrap();
        let mgr = Arc::new(KeyChanging { opens: Default::default() });
        let e = Engine::new(root.path().join("wallets"), Arc::new(|_| {}), mgr, None);
        let first = finish(&e, "open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
        assert_eq!((first["created"].clone(), first["reset"].clone()), (json!(true), json!(false)));
        assert_eq!(e.next_address()["index"], 0);
        assert_eq!(e.next_address()["index"], 1);
        finish(&e, "close_wallet", json!({}));
        let again = finish(&e, "open_wallet", json!({"network": "regtest", "group": "g_reset"}));
        assert_eq!(again["reset"], true, "{again}");
        assert_eq!(e.next_address()["index"], 0, "the wallet starts fresh");
        assert_eq!(e.status()["birthdaySource"], "activation");
        let dir = root.path().join("wallets/regtest/g_reset");
        let aside: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().filter(|f| f.file_name().to_string_lossy().contains("unreadable")).collect();
        assert!(!aside.is_empty(), "the old database is kept aside");
        e.shutdown();
    }

    #[test]
    fn birthdays_resolve_in_order() {
        let chain = HeaderChain::new(BNetwork::Mainnet);
        let (net, fam) = (BNetwork::Mainnet, Family::Bitcoin);
        assert_eq!(resolve_birthday(None, None, None, &chain, net, fam), (481_824, "activation".to_string()));
        assert_eq!(resolve_birthday(Some(Birthday::Height(100)), None, None, &chain, net, fam).0, 481_824, "never below activation");
        let (h, src) = resolve_birthday(None, Some("2024-04-20"), None, &chain, net, fam);
        assert!(h > 835_000 && h < 840_000 && src == "keystore", "{h} {src}");
        // A day kept from an earlier open stands; an override replaces it.
        assert_eq!(resolve_birthday(None, Some("2024-04-20"), Some((900_000, "keystore".into())), &chain, net, fam).0, 900_000);
        assert_eq!(resolve_birthday(Some(Birthday::Height(910_000)), None, Some((900_000, "keystore".into())), &chain, net, fam).0, 910_000);
        // An activation fallback kept earlier yields to a day the keystore now knows.
        let (_, src) = resolve_birthday(None, Some("2024-04-20"), Some((481_824, "activation".into())), &chain, net, fam);
        assert_eq!(src, "keystore");
    }
}
