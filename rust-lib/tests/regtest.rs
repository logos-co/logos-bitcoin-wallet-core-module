//! The engine on tools/regtest/chain.sh's chain, no Logos runtime: a doctoring proxy, and a manager
//! over the interface's MockSigner. The run command and its environment are in the README.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Psbt, Transaction, Txid};
use bitcoin_wallet_core::engine::{Engine, Event, Sink};
use bitcoin_wallet_core::manager::SignerManager;
use bitcoin_wallet_core::network::{configure_regtest, RegtestConfig};
use logos_signer_interface::mock::{MockOptions, MockSigner};
use logos_signer_interface::{Payload, RequestKind, SignRequest, Signer};
use serde_json::{json, Value};

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// ── The signer manager, in process ───────────────────────────────────────

struct Record {
    receipt: String,
    ready_at: Instant,
    result: Value,
    acked: bool,
    cancelled: bool,
}

/// Answers as signer_manager_module does: handles, receipts, a decision after a delay, and PSBTs
/// with the signatures added but not finalized. The person always approves.
struct MockManager {
    signer: Mutex<MockSigner>,
    next: AtomicU64,
    records: Mutex<HashMap<String, Record>>,
    delay: Duration,
    keys: Mutex<HashMap<String, String>>,
    log: Mutex<Vec<String>>,
}

impl MockManager {
    fn new(delay: Duration) -> Self {
        let mut signer = MockSigner::new(MockOptions { phrase: PHRASE.into(), ..Default::default() });
        signer.set_request_kinds(vec![RequestKind::BtcPsbt]);
        Self { signer: Mutex::new(signer), next: AtomicU64::new(0), records: Mutex::default(), delay, keys: Mutex::default(), log: Mutex::default() }
    }

    fn account(&self, id: &str) -> (String, String, String) {
        let mut s = self.signer.lock().unwrap();
        let a = s.accounts().unwrap().into_iter().find(|a| a.id == id).unwrap();
        (a.fingerprint.unwrap(), a.path.unwrap(), a.xpub.unwrap())
    }

    /// The descriptors the keystore would return: origin with `'`, then the checksum.
    fn descriptors(&self, family: &str) -> (String, String) {
        let (id, f) = if family == "bitcoin" { ("mock-segwit", "wpkh") } else { ("mock-taproot", "tr") };
        let (fp, path, xpub) = self.account(id);
        let origin = path.trim_start_matches("m/");
        let d = |c: u32| {
            let body = format!("{f}([{fp}/{origin}]{xpub}/{c}/*)");
            let parsed = bdk_wallet::miniscript::Descriptor::<bdk_wallet::miniscript::DescriptorPublicKey>::from_str(&body).unwrap();
            parsed.to_string()
        };
        (d(0), d(1))
    }

    fn issue(&self, prefix: &str, result: Value) -> String {
        let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let handle = format!("{prefix}_{n:08x}");
        let receipt = format!("r{n:032x}");
        self.records.lock().unwrap().insert(handle.clone(), Record { receipt: receipt.clone(), ready_at: Instant::now() + self.delay, result, acked: false, cancelled: false });
        json!({"ok": true, "handle": handle, "receipt": receipt, "state": "offered"}).to_string()
    }

    fn with<T>(&self, h: &str, r: &str, f: impl FnOnce(&mut Record) -> T) -> Result<T, String> {
        let mut recs = self.records.lock().unwrap();
        match recs.get_mut(h) {
            Some(rec) if rec.receipt == r => Ok(f(rec)),
            _ => Err("not authorized".into()),
        }
    }

    /// Checks what the real manager refuses before showing anything, then signs like it does.
    fn sign(&self, psbt_b64: &str) -> Result<String, String> {
        let mut psbt = Psbt::from_str(psbt_b64).map_err(|e| e.to_string())?;
        let taproot = psbt.inputs.iter().any(|i| i.tap_internal_key.is_some());
        for (i, (txin, input)) in psbt.unsigned_tx.input.iter().zip(&psbt.inputs).enumerate() {
            if !input.partial_sigs.is_empty() || input.tap_key_sig.is_some() {
                return Err(format!("input {i} is already signed"));
            }
            if taproot {
                if input.witness_utxo.is_none() || input.tap_key_origins.values().any(|(leaves, _)| !leaves.is_empty()) || !input.tap_scripts.is_empty() {
                    return Err(format!("input {i}: not a key-path taproot input"));
                }
            } else {
                let prev = input.non_witness_utxo.as_ref().ok_or(format!("input {i} has no previous transaction"))?;
                if prev.compute_txid() != txin.previous_output.txid {
                    return Err(format!("input {i}'s previous transaction is not the one it spends"));
                }
            }
            if input.sighash_type.is_some() {
                return Err(format!("input {i} asks for a sighash"));
            }
        }
        let account = if taproot { "mock-taproot" } else { "mock-segwit" };
        let mut s = self.signer.lock().unwrap();
        let job = s
            .sign(SignRequest { account: account.into(), payload: Payload::BtcPsbt { network: "regtest".into(), psbt: psbt_b64.into() }, secret: None })
            .map_err(|e| e.to_string())?;
        let sigs = s.result(&job).map_err(|e| e.to_string())?;
        for sig in sigs {
            let bytes = hex::decode(&sig.signature).unwrap();
            let input = &mut psbt.inputs[sig.item];
            if taproot {
                let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&bytes).unwrap();
                input.tap_key_sig = Some(bitcoin::taproot::Signature { signature, sighash_type: bitcoin::TapSighashType::Default });
            } else {
                let signature = bitcoin::secp256k1::ecdsa::Signature::from_compact(&bytes).unwrap();
                let pk = bitcoin::PublicKey::from_slice(&hex::decode(&sig.pubkey).unwrap()).unwrap();
                input.partial_sigs.insert(pk, bitcoin::ecdsa::Signature { signature, sighash_type: bitcoin::EcdsaSighashType::All });
            }
        }
        Ok(psbt.to_string())
    }
}

impl SignerManager for MockManager {
    fn request_open(&self, p: &str) -> Result<String, String> {
        let v: Value = serde_json::from_str(p).unwrap();
        for k in v.as_object().unwrap().keys() {
            assert!(["group", "family", "network", "reason", "unlock"].contains(&k.as_str()), "the manager refuses unknown keys: {k}");
        }
        let family = match (v["group"].as_str(), v["family"].as_str()) {
            (Some(g), _) => if g.starts_with("g_tap") { "bitcoin_taproot" } else { "bitcoin" },
            (None, Some(f)) => f,
            _ => return Ok(json!({"ok": false, "error": "invalid parameters: open: name a Bitcoin group, or a Bitcoin family and a network"}).to_string()),
        };
        let group = if family == "bitcoin" { "g_seg00000000000000000000000000000000" } else { "g_tap00000000000000000000000000000000" };
        let key = self.keys.lock().unwrap().entry(group.into()).or_insert_with(|| hex::encode(rand::random::<[u8; 32]>())).clone();
        let (external, internal) = self.descriptors(family);
        self.log.lock().unwrap().push(format!("open {family}"));
        Ok(self.issue("sma", json!({"group": group, "family": family, "chain": "test", "network": v["network"], "external": external,
            "internal": internal, "fingerprint": "73c5da0a", "databaseKey": key, "origin": "restored", "birthday": null, "unlocked": null})))
    }

    fn request_approval(&self, intent: &str) -> Result<String, String> {
        let v: Value = serde_json::from_str(intent).unwrap();
        let legs = v["legs"].as_array().unwrap();
        assert_eq!(legs.len(), 1, "a Bitcoin intent carries exactly one psbt leg");
        assert_eq!(legs[0]["kind"], "psbt");
        assert!(intent.len() <= 64 * 1024);
        self.log.lock().unwrap().push(format!("approval {}", v["purpose"]));
        match self.sign(legs[0]["psbt"].as_str().unwrap()) {
            Ok(signed) => Ok(self.issue("smh", json!({"signed": [signed]}))),
            Err(e) => Ok(json!({"ok": false, "error": format!("invalid parameters: psbt: {e}")}).to_string()),
        }
    }

    fn approval_status(&self, h: &str, r: &str) -> Result<String, String> {
        Ok(match self.with(h, r, |rec| (rec.cancelled, Instant::now() >= rec.ready_at)) {
            Ok((true, _)) => json!({"ok": true, "state": "settled", "reason": "cancelled"}),
            Ok((false, true)) => json!({"ok": true, "state": "settled", "reason": "approved"}),
            Ok((false, false)) => json!({"ok": true, "state": "rendered", "reason": null}),
            Err(e) => json!({"ok": false, "error": e}),
        }
        .to_string())
    }

    fn fetch_result(&self, h: &str, r: &str) -> Result<String, String> {
        Ok(match self.with(h, r, |rec| (rec.acked, rec.result.clone())) {
            Ok((false, res)) if res.get("signed").is_some() => json!({"ok": true, "signed": res["signed"]}),
            Ok((false, res)) => json!({"ok": true, "result": res}),
            _ => json!({"ok": false, "error": "not authorized"}),
        }
        .to_string())
    }

    fn ack_result(&self, h: &str, r: &str) -> Result<bool, String> {
        Ok(self.with(h, r, |rec| rec.acked = true).is_ok())
    }

    fn cancel_approval(&self, h: &str, r: &str) -> Result<bool, String> {
        Ok(self.with(h, r, |rec| rec.cancelled = true).is_ok())
    }

    fn close_account(&self, p: &str) -> Result<String, String> {
        self.log.lock().unwrap().push(format!("close {p}"));
        Ok(json!({"ok": true, "closed": true}).to_string())
    }
}

// ── A doctoring proxy in front of electrs ────────────────────────────────

#[derive(Default)]
struct Doctor {
    /// Rewrite `blockchain.block.header` at this height: same merkle root, another hash.
    header_at: Option<u64>,
    /// Rewrite `blockchain.transaction.get` for this txid: bytes that hash to something else.
    tx: Option<String>,
    hits: Vec<String>,
}

fn doctor_line(doctor: &Mutex<Doctor>, method: &str, params: &Value, mut reply: Value) -> Value {
    let mut d = doctor.lock().unwrap();
    match method {
        "blockchain.block.header" if params[0].as_u64().is_some() && params[0].as_u64() == d.header_at => {
            if let Some(hexs) = reply["result"].as_str() {
                let mut bytes = hex::decode(hexs).unwrap();
                bytes[79] ^= 0x5a;
                reply["result"] = json!(hex::encode(bytes));
                d.hits.push(format!("header {}", params[0]));
            }
        }
        "blockchain.transaction.get" if params[0].as_str().is_some() && params[0].as_str().map(str::to_string) == d.tx => {
            if let Some(hexs) = reply["result"].as_str() {
                let mut tx: Transaction = deserialize_hex(hexs).unwrap();
                tx.output[0].value = bitcoin::Amount::from_sat(tx.output[0].value.to_sat() + 1);
                reply["result"] = json!(serialize_hex(&tx));
                d.hits.push(format!("tx {}", params[0]));
            }
        }
        _ => {}
    }
    reply
}

fn proxy(upstream: SocketAddr, doctor: Arc<Mutex<Doctor>>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for client in l.incoming().flatten() {
            let Ok(up) = TcpStream::connect(upstream) else { continue };
            let asked: Arc<Mutex<HashMap<u64, (String, Value)>>> = Arc::default();
            let (mut c_w, mut u_w) = (client.try_clone().unwrap(), up.try_clone().unwrap());
            let a2 = asked.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(client).lines().map_while(Result::ok) {
                    if let Ok(v) = serde_json::from_str::<Value>(&line) {
                        if let (Some(id), Some(m)) = (v["id"].as_u64(), v["method"].as_str()) {
                            a2.lock().unwrap().insert(id, (m.to_string(), v["params"].clone()));
                        }
                    }
                    if u_w.write_all(format!("{line}\n").as_bytes()).is_err() {
                        break;
                    }
                }
            });
            let d = doctor.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(up).lines().map_while(Result::ok) {
                    let out = match serde_json::from_str::<Value>(&line) {
                        Ok(v) => match v["id"].as_u64().and_then(|id| asked.lock().unwrap().remove(&id)) {
                            Some((m, p)) => doctor_line(&d, &m, &p, v).to_string(),
                            None => line,
                        },
                        Err(_) => line,
                    };
                    if c_w.write_all(format!("{out}\n").as_bytes()).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

// ── The chain and the engine ─────────────────────────────────────────────

struct T {
    engine: Arc<Engine>,
    rpc: String,
    cookie: String,
    events: Arc<Mutex<Vec<(String, Value)>>>,
    doctor: Arc<Mutex<Doctor>>,
    manager: Arc<MockManager>,
}

impl T {
    fn rpc_at(&self, path: &str, method: &str, params: Value) -> Value {
        let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
        let out = Command::new("curl")
            .args(["-s", "--max-time", "120", "--user", self.cookie.trim(), "-H", "content-type: application/json", "--data-binary", &body, &format!("{}{path}", self.rpc)])
            .output()
            .expect("curl");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("rpc {method}: {}", String::from_utf8_lossy(&out.stdout)));
        assert!(v["error"].is_null(), "rpc {method}: {v}");
        v["result"].clone()
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        self.rpc_at("/", method, params)
    }

    fn wallet_rpc(&self, method: &str, params: Value) -> Value {
        self.rpc_at("/wallet/miner", method, params)
    }

    fn tip(&self) -> u64 {
        self.rpc("getblockcount", json!([])).as_u64().unwrap()
    }

    fn mine(&self, n: u32) {
        let to = self.wallet_rpc("getnewaddress", json!(["mine"]));
        self.rpc("generatetoaddress", json!([n, to]));
    }

    fn fund(&self, address: &str, btc: f64) -> Txid {
        Txid::from_str(self.wallet_rpc("sendtoaddress", json!([address, btc])).as_str().unwrap()).unwrap()
    }

    fn job(&self, kind: &str, params: Value) -> Value {
        let r = self.engine.start_job(kind, &params.to_string());
        assert_eq!(r["ok"], true, "{kind}: {r}");
        let (id, receipt) = (r["jobId"].as_str().unwrap().to_string(), r["receipt"].as_str().unwrap().to_string());
        let t0 = Instant::now();
        loop {
            let s = self.engine.jobs().status(&id, &receipt);
            match s["state"].as_str().unwrap() {
                "done" => {
                    let out = self.engine.jobs().result(&id, &receipt)["result"].clone();
                    assert!(self.engine.jobs().ack(&id, &receipt));
                    return out;
                }
                "failed" | "cancelled" => panic!("{kind}: {s}"),
                _ => {}
            }
            assert!(t0.elapsed() < Duration::from_secs(300), "{kind} timed out");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn wait(&self, what: &str, secs: u64, mut f: impl FnMut() -> bool) {
        let t0 = Instant::now();
        while !f() {
            assert!(t0.elapsed() < Duration::from_secs(secs), "timed out waiting for {what}; status {}", self.engine.status());
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// The wallet has synced the node's tip.
    fn synced(&self) {
        let want = self.tip();
        self.wait("sync", 120, || {
            let s = self.engine.status();
            s["synced"] == true && s["authority"]["height"].as_u64() == Some(want)
        });
    }

    fn sats(&self, field: &str) -> u64 {
        let b = self.engine.balance();
        b[field].as_str().and_then(|s| s.parse().ok()).unwrap_or(0)
    }

    fn row(&self, txid: &str) -> Value {
        let h = self.engine.history(0);
        h["rows"].as_array().unwrap().iter().find(|r| r["txid"] == txid).cloned().unwrap_or(Value::Null)
    }

    fn alerts(&self, kind: &str, source: &str) -> usize {
        self.events.lock().unwrap().iter().filter(|(n, v)| n == "sourceAlert" && v["kind"] == kind && v["source"] == source).count()
    }

    fn in_mempool(&self, txid: &str) -> bool {
        self.rpc("getrawmempool", json!([])).as_array().unwrap().iter().any(|t| t == txid)
    }

    /// A send end to end: preview, approval, broadcast, confirmation.
    fn send(&self, to: &str, sat: u64, fee_rate: Option<f64>) -> (Value, Value) {
        let mut p = json!({"recipients": [{"address": to, "amountSat": sat.to_string()}]});
        if let Some(r) = fee_rate {
            p["feeRate"] = json!(r);
        }
        let preview = self.job("build_send", p);
        assert_eq!(preview["outputs"].as_array().unwrap().iter().filter(|o| o["change"] == false).count(), 1, "{preview}");
        let id = preview["previewId"].as_str().unwrap().to_string();
        let sent = self.sign(&id);
        assert_eq!(sent["txid"], preview["txid"], "the broadcast transaction is the one previewed");
        (preview, sent)
    }

    fn sign(&self, preview_id: &str) -> Value {
        let r = self.engine.start_job("sign_and_broadcast", &json!({"previewId": preview_id}).to_string());
        let (id, receipt) = (r["jobId"].as_str().unwrap().to_string(), r["receipt"].as_str().unwrap().to_string());
        // While the person decides, the handle shows in status and in the preview.
        let mut seen_handle = false;
        let t0 = Instant::now();
        loop {
            let st = self.engine.jobs().status(&id, &receipt);
            if !seen_handle {
                let s = self.engine.status();
                let pv = self.engine.preview(preview_id);
                if let (Some(a), Some(b)) = (s["approvalHandle"].as_str(), pv["approvalHandle"].as_str()) {
                    assert!(a.starts_with("smh_") && a == b, "{s} {pv}");
                    seen_handle = true;
                }
            }
            match st["state"].as_str().unwrap() {
                "done" => break,
                "failed" | "cancelled" => panic!("sign_and_broadcast: {st}"),
                _ => {}
            }
            assert!(t0.elapsed() < Duration::from_secs(120));
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(seen_handle, "the approval handle was exposed while waiting");
        let out = self.engine.jobs().result(&id, &receipt)["result"].clone();
        self.engine.jobs().ack(&id, &receipt);
        out
    }
}

#[test]
#[ignore]
fn bitcoin_wallet_on_regtest() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Ok(rpc) = std::env::var("REGTEST_RPC") else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    let cookie = std::fs::read_to_string(std::env::var("REGTEST_COOKIE").expect("REGTEST_COOKIE")).unwrap();
    let servers: Vec<SocketAddr> = std::env::var("REGTEST_ELECTRUM").expect("REGTEST_ELECTRUM").split(',').map(|s| s.trim().trim_start_matches("tcp://").parse().unwrap()).collect();
    let doctor: Arc<Mutex<Doctor>> = Arc::default();
    let via_proxy = proxy(servers[0], doctor.clone());
    // The proxy is first: it holds the history until it lies, then the honest electrs takes over.
    configure_regtest(RegtestConfig { electrum: vec![format!("tcp://{via_proxy}"), format!("tcp://{}", servers[1])], esplora: vec![], poll_secs: Some(1) });
    let events: Arc<Mutex<Vec<(String, Value)>>> = Arc::default();
    let ev = events.clone();
    let sink: Sink = Arc::new(move |e| {
        let entry = match e {
            Event::WalletState(v) => ("walletStateChanged".to_string(), v),
            Event::JobFinished { id, state } => ("jobFinished".to_string(), json!({"jobId": id, "state": state})),
            Event::SourceAlert(v) => ("sourceAlert".to_string(), v),
        };
        ev.lock().unwrap().push(entry);
    });
    let manager = Arc::new(MockManager::new(Duration::from_millis(1500)));
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(root.path().join("wallets"), sink, manager.clone(), None);
    let t = T { engine, rpc, cookie, events, doctor, manager };
    let started = Instant::now();

    // Open: the core asks the manager, shows the open handle while the person decides, then opens.
    let opened = t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    assert_eq!(opened["family"], "bitcoin");
    assert_eq!(opened["needsBirthday"], true, "a restored wallet without a day asks for one: {opened}");
    assert!(t.events.lock().unwrap().iter().any(|(n, v)| n == "walletStateChanged" && v["state"] == "awaiting_open" && v["openHandle"].as_str().is_some_and(|h| h.starts_with("sma_"))));
    t.synced();
    let sync_ms = started.elapsed().as_millis();
    println!("opened and synced to {} in {sync_ms} ms", t.tip());
    let st = t.engine.status();
    assert_eq!((st["state"].clone(), st["authority"]["kind"].clone()), (json!("ready"), json!("electrum_headers")));
    assert_eq!(t.engine.history(0)["total"], 0, "the test phrase's wallet must be empty: start from a fresh `chain.sh prepare`");
    assert!(t.engine.descriptors()["external"].as_str().unwrap().starts_with("wpkh([73c5da0a/84'/1'/0']tpub"));

    // Receive, pending, then confirmed.
    let addr = t.engine.next_address()["address"].as_str().unwrap().to_string();
    assert!(addr.starts_with("bcrt1q"));
    let funded = t.fund(&addr, 1.0);
    t.wait("the payment as pending", 60, || t.sats("pending") == 100_000_000);
    assert_eq!(t.row(&funded.to_string())["state"], "pending");
    assert_eq!(t.row(&funded.to_string())["reportedBy"], "electrum-0");
    t.mine(1);
    t.synced();
    t.wait("the payment confirmed", 60, || t.sats("confirmed") == 100_000_000);
    assert_eq!(t.row(&funded.to_string())["intent"], "receive");

    // Send from native segwit: approval through the manager, BDK finalizes, the node accepts it.
    let theirs = t.wallet_rpc("getnewaddress", json!(["payee"])).as_str().unwrap().to_string();
    let (preview, sent) = t.send(&theirs, 10_000_000, None);
    let txid = sent["txid"].as_str().unwrap().to_string();
    assert!(["seen", "requested"].contains(&sent["broadcast"].as_str().unwrap()), "{sent}");
    assert!(t.in_mempool(&txid));
    let fee: u64 = preview["feeSat"].as_str().unwrap().parse().unwrap();
    t.mine(1);
    t.synced();
    t.wait("the send confirmed", 60, || t.row(&txid)["state"] == "confirmed");
    assert_eq!(t.row(&txid)["intent"], "send");
    assert_eq!(t.sats("confirmed"), 100_000_000 - 10_000_000 - fee);
    println!("segwit send {txid}: fee {fee} sat, vsize {}", preview["vsize"]);

    // Bump a low-fee send through build_fee_bump; the replacement confirms, the original doesn't.
    let (_, slow) = t.send(&theirs, 5_000_000, Some(1.0));
    let slow_id = slow["txid"].as_str().unwrap().to_string();
    assert!(t.in_mempool(&slow_id));
    let bump = t.job("bump_fee", json!({"txid": slow_id, "feeRate": 6.0}));
    assert_eq!((bump["kind"].clone(), bump["replaces"].clone()), (json!("fee_bump"), json!(slow_id)));
    let bumped = t.sign(bump["previewId"].as_str().unwrap());
    let bump_id = bumped["txid"].as_str().unwrap().to_string();
    t.wait("the replacement in the mempool", 30, || t.in_mempool(&bump_id) && !t.in_mempool(&slow_id));
    t.mine(1);
    t.synced();
    t.wait("the bump confirmed", 60, || t.row(&bump_id)["state"] == "confirmed");
    assert_eq!(t.row(&bump_id)["intent"], "fee_bump");
    assert_eq!(t.row(&slow_id)["state"], "replaced");

    // A doctored anchor: the proxy serves another header for the block confirming a payment.
    t.wait("history on the proxy", 30, || t.engine.status()["historyServer"] == "electrum-0");
    let addr3 = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let anchored = t.fund(&addr3, 0.05).to_string();
    t.wait("the payment as pending", 60, || t.row(&anchored)["state"] == "pending");
    let before = t.alerts("anchor_mismatch", "electrum-0");
    t.doctor.lock().unwrap().header_at = Some(t.tip() + 1);
    t.mine(1);
    t.wait("the anchor refused", 60, || t.alerts("anchor_mismatch", "electrum-0") > before);
    assert!(t.doctor.lock().unwrap().hits.iter().any(|h| h.starts_with("header ")));
    t.synced();
    t.wait("the payment confirmed through the honest server", 60, || t.row(&anchored)["state"] == "confirmed");
    assert_eq!(t.row(&anchored)["height"].as_u64(), Some(t.tip()));
    let sources = t.engine.sources_status();
    let proxy_row = sources["sources"].as_array().unwrap().iter().find(|s| s["id"] == "electrum-0").unwrap().clone();
    assert_eq!(proxy_row["suspect"], true, "{sources}");
    assert_eq!(t.engine.status()["historyServer"], "electrum-1");
    t.doctor.lock().unwrap().header_at = None;

    // A doctored transaction: bytes that don't hash to the txid are refused.
    assert_eq!(t.engine.clear_suspect("electrum-0")["cleared"], true);
    let addr4 = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let raw = t.wallet_rpc("createrawtransaction", json!([[], {addr4.clone(): 0.03}]));
    let funded_raw = t.wallet_rpc("fundrawtransaction", json!([raw]))["hex"].clone();
    let signed = t.wallet_rpc("signrawtransactionwithwallet", json!([funded_raw]))["hex"].as_str().unwrap().to_string();
    let doctored_tx: Transaction = deserialize_hex(&signed).unwrap();
    let doctored_id = doctored_tx.compute_txid().to_string();
    t.doctor.lock().unwrap().tx = Some(doctored_id.clone());
    // Back on the proxy for history before the payment goes out.
    t.wait("history back on the proxy", 30, || t.engine.status()["historyServer"] == "electrum-0");
    let alerts_before = t.alerts("suspect", "electrum-0");
    t.rpc("sendrawtransaction", json!([signed]));
    t.wait("the doctored bytes refused", 60, || t.alerts("suspect", "electrum-0") > alerts_before);
    t.wait("the payment through the honest server", 60, || t.row(&doctored_id)["state"] == "pending");
    assert_eq!(t.row(&doctored_id)["amountSat"], "3000000", "the wallet holds the real transaction");
    assert!(t.doctor.lock().unwrap().hits.iter().any(|h| h.starts_with("tx ")));
    t.doctor.lock().unwrap().tx = None;
    t.mine(1);
    t.synced();

    // A reorg under server anchors: the block holding a payment is replaced; the anchor follows.
    let addr2 = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let reorged = t.fund(&addr2, 0.2).to_string();
    t.mine(1);
    t.synced();
    t.wait("the payment confirmed", 60, || t.row(&reorged)["state"] == "confirmed");
    let old_block = t.rpc("getbestblockhash", json!([]));
    let h = t.tip();
    let suspects_before = t.alerts("suspect", "electrum-0") + t.alerts("suspect", "electrum-1");
    // The fork node replaces the block offline and reconnects: the node electrs follows reorgs as
    // on a live network, keeping the old block as a valid stale fork.
    let out = Command::new(std::env::var("REGTEST_CHAIN").expect("REGTEST_CHAIN: the path of tools/regtest/chain.sh")).args(["reorg", "1"]).output().unwrap();
    assert!(out.status.success(), "reorg: {}", String::from_utf8_lossy(&out.stdout));
    let new_block = t.rpc("getblockhash", json!([h]));
    assert_ne!(old_block, new_block);
    t.synced();
    t.wait("the payment re-anchored in the new block", 60, || {
        let r = t.row(&reorged);
        r["state"] == "confirmed" && r["height"].as_u64() == Some(h) && r["confirmations"] == 2
    });
    println!("reorg at {h}: {} replaced by {}", old_block, new_block);
    // A server that is only behind the reorg is not blamed for it.
    assert_eq!(t.alerts("suspect", "electrum-0") + t.alerts("suspect", "electrum-1"), suspects_before, "a lagging server was blamed");

    // Exposure: both servers learned the addresses, the first since the wallet opened.
    let exposure = t.engine.exposure();
    assert_eq!(exposure["servers"].as_array().unwrap().len(), 2, "{exposure}");

    // Taproot: a second wallet, same flow.
    t.job("close_wallet", json!({}));
    assert_eq!(t.engine.status()["state"], "no_wallet");
    assert!(t.manager.log.lock().unwrap().iter().any(|l| l.starts_with("close ") && l.contains("g_seg")));
    let tr = t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin_taproot"}));
    assert_eq!(tr["family"], "bitcoin_taproot");
    t.synced();
    let taddr = t.engine.next_address()["address"].as_str().unwrap().to_string();
    assert!(taddr.starts_with("bcrt1p"));
    t.fund(&taddr, 0.5);
    t.mine(1);
    t.synced();
    t.wait("taproot funds confirmed", 60, || t.sats("confirmed") == 50_000_000);
    let (tpreview, tsent) = t.send(&theirs, 20_000_000, None);
    let ttxid = tsent["txid"].as_str().unwrap().to_string();
    t.mine(1);
    t.synced();
    t.wait("the taproot send confirmed", 60, || t.row(&ttxid)["state"] == "confirmed");
    println!("taproot send {ttxid}: fee {} sat, vsize {}", tpreview["feeSat"], tpreview["vsize"]);

    // Reopen by group: the key and descriptors come from the manager again, the history from disk.
    let group = t.engine.status()["group"].as_str().unwrap().to_string();
    t.job("close_wallet", json!({}));
    let again = t.job("open_wallet", json!({"network": "regtest", "group": group}));
    assert_eq!(again["created"], false);
    t.synced();
    assert_eq!(t.row(&ttxid)["state"], "confirmed");

    let t0 = Instant::now();
    t.engine.shutdown();
    let unload_ms = t0.elapsed().as_millis();
    println!("shutdown in {unload_ms} ms; whole run {} s", started.elapsed().as_secs());
    assert!(unload_ms < 2000, "unload took {unload_ms} ms");
}
