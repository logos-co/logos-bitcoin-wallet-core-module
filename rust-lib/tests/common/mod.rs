//! What the regtest tests share: a manager over the interface's MockSigner, and a harness that
//! drives the engine against tools/regtest/chain.sh's chain.
#![allow(dead_code)]

use std::collections::HashMap;
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::{Psbt, Txid};
use bitcoin_wallet_core::engine::{Engine, Event, Sink};
use bitcoin_wallet_core::manager::SignerManager;
use logos_signer_interface::mock::{MockOptions, MockSigner};
use logos_signer_interface::{Payload, RequestKind, SignRequest, Signer};
use serde_json::{json, Value};

pub const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// ── The signer manager, in process ───────────────────────────────────────

pub struct Record {
    receipt: String,
    ready_at: Instant,
    result: Value,
    acked: bool,
    cancelled: bool,
    /// How the person decides: approved, or what the test asked for.
    reason: &'static str,
}

/// Answers as signer_manager_module does: handles, receipts, a decision after a delay, and PSBTs
/// with the signatures added but not finalized. The person always approves.
pub struct MockManager {
    signer: Mutex<MockSigner>,
    next: AtomicU64,
    records: Mutex<HashMap<String, Record>>,
    delay: Duration,
    keys: Mutex<HashMap<String, String>>,
    pub log: Mutex<Vec<String>>,
    /// The next approval settles this way instead of approved.
    pub next_reason: Mutex<Option<&'static str>>,
}

impl MockManager {
    pub fn new(delay: Duration) -> Self {
        let mut signer = MockSigner::new(MockOptions { phrase: PHRASE.into(), ..Default::default() });
        signer.set_request_kinds(vec![RequestKind::BtcPsbt]);
        Self { signer: Mutex::new(signer), next: AtomicU64::new(0), records: Mutex::default(), delay, keys: Mutex::default(), log: Mutex::default(), next_reason: Mutex::default() }
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

    fn issue(&self, prefix: &str, result: Value, reason: &'static str) -> String {
        let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let handle = format!("{prefix}_{n:08x}");
        let receipt = format!("r{n:032x}");
        let rec = Record { receipt: receipt.clone(), ready_at: Instant::now() + self.delay, result, acked: false, cancelled: false, reason };
        self.records.lock().unwrap().insert(handle.clone(), rec);
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
            "internal": internal, "fingerprint": "73c5da0a", "databaseKey": key, "origin": "restored", "birthday": null, "unlocked": null}), "approved"))
    }

    fn request_approval(&self, intent: &str) -> Result<String, String> {
        let v: Value = serde_json::from_str(intent).unwrap();
        let legs = v["legs"].as_array().unwrap();
        assert_eq!(legs.len(), 1, "a Bitcoin intent carries exactly one psbt leg");
        assert_eq!(legs[0]["kind"], "psbt");
        assert!(intent.len() <= 64 * 1024);
        self.log.lock().unwrap().push(format!("approval {}", v["purpose"]));
        let reason = self.next_reason.lock().unwrap().take().unwrap_or("approved");
        match self.sign(legs[0]["psbt"].as_str().unwrap()) {
            Ok(signed) => Ok(self.issue("smh", json!({"signed": [signed]}), reason)),
            Err(e) => Ok(json!({"ok": false, "error": format!("invalid parameters: psbt: {e}")}).to_string()),
        }
    }

    fn approval_status(&self, h: &str, r: &str) -> Result<String, String> {
        Ok(match self.with(h, r, |rec| (rec.cancelled, Instant::now() >= rec.ready_at, rec.reason)) {
            Ok((true, _, _)) => json!({"ok": true, "state": "settled", "reason": "cancelled"}),
            Ok((false, true, reason)) => json!({"ok": true, "state": "settled", "reason": reason}),
            Ok((false, false, _)) => json!({"ok": true, "state": "rendered", "reason": null}),
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

// ── The chain and the engine ─────────────────────────────────────────────

pub struct T {
    pub engine: Arc<Engine>,
    pub rpc: String,
    pub cookie: String,
    pub events: Arc<Mutex<Vec<(String, Value)>>>,
    pub manager: Arc<MockManager>,
}

impl T {
    pub fn rpc_at(&self, path: &str, method: &str, params: Value) -> Value {
        let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
        // The body goes on stdin: Linux caps one argument at 128 KiB.
        let mut child = Command::new("curl")
            .args(["-s", "--max-time", "120", "--user", self.cookie.trim(), "-H", "content-type: application/json", "--data-binary", "@-", &format!("{}{path}", self.rpc)])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("curl");
        std::io::Write::write_all(&mut child.stdin.take().expect("stdin"), body.as_bytes()).expect("curl stdin");
        let out = child.wait_with_output().expect("curl");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("rpc {method}: {}", String::from_utf8_lossy(&out.stdout)));
        assert!(v["error"].is_null(), "rpc {method}: {v}");
        v["result"].clone()
    }

    pub fn rpc(&self, method: &str, params: Value) -> Value {
        self.rpc_at("/", method, params)
    }

    pub fn wallet_rpc(&self, method: &str, params: Value) -> Value {
        self.rpc_at("/wallet/miner", method, params)
    }

    pub fn tip(&self) -> u64 {
        self.rpc("getblockcount", json!([])).as_u64().unwrap()
    }

    pub fn mine(&self, n: u32) {
        let to = self.wallet_rpc("getnewaddress", json!(["mine"]));
        self.rpc("generatetoaddress", json!([n, to]));
    }

    pub fn fund(&self, address: &str, btc: f64) -> Txid {
        Txid::from_str(self.wallet_rpc("sendtoaddress", json!([address, btc])).as_str().unwrap()).unwrap()
    }

    pub fn job(&self, kind: &str, params: Value) -> Value {
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

    /// A job expected to fail: its code and error.
    pub fn job_fail(&self, kind: &str, params: Value) -> (String, String) {
        let r = self.engine.start_job(kind, &params.to_string());
        let (id, receipt) = (r["jobId"].as_str().unwrap().to_string(), r["receipt"].as_str().unwrap().to_string());
        let t0 = Instant::now();
        loop {
            let s = self.engine.jobs().status(&id, &receipt);
            match s["state"].as_str().unwrap() {
                "failed" => return (s["code"].as_str().unwrap_or("").to_string(), s["error"].as_str().unwrap_or("").to_string()),
                "done" => panic!("{kind} should have failed: {s}"),
                _ => {}
            }
            assert!(t0.elapsed() < Duration::from_secs(120), "{kind} timed out");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// A job expected to fail: its error.
    pub fn job_err(&self, kind: &str, params: Value) -> String {
        let r = self.engine.start_job(kind, &params.to_string());
        let (id, receipt) = (r["jobId"].as_str().unwrap().to_string(), r["receipt"].as_str().unwrap().to_string());
        let t0 = Instant::now();
        loop {
            let s = self.engine.jobs().status(&id, &receipt);
            match s["state"].as_str().unwrap() {
                "failed" => return s["error"].as_str().unwrap_or("").to_string(),
                "done" => panic!("{kind} should have failed: {s}"),
                _ => {}
            }
            assert!(t0.elapsed() < Duration::from_secs(120), "{kind} timed out");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn wait(&self, what: &str, secs: u64, mut f: impl FnMut() -> bool) {
        let t0 = Instant::now();
        while !f() {
            assert!(t0.elapsed() < Duration::from_secs(secs), "timed out waiting for {what}; status {}", self.engine.status());
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// The wallet has synced the node's tip.
    pub fn synced(&self) {
        let want = self.tip();
        self.wait("sync", 120, || {
            let s = self.engine.status();
            s["synced"] == true && s["authority"]["height"].as_u64() == Some(want)
        });
    }

    pub fn sats(&self, field: &str) -> u64 {
        let b = self.engine.balance();
        b[field].as_str().and_then(|s| s.parse().ok()).unwrap_or(0)
    }

    pub fn row(&self, txid: &str) -> Value {
        let h = self.engine.history(0);
        h["rows"].as_array().unwrap().iter().find(|r| r["txid"] == txid).cloned().unwrap_or(Value::Null)
    }

    pub fn alerts(&self, kind: &str, source: &str) -> usize {
        self.events.lock().unwrap().iter().filter(|(n, v)| n == "sourceAlert" && v["kind"] == kind && v["source"] == source).count()
    }

    pub fn in_mempool(&self, txid: &str) -> bool {
        self.rpc("getrawmempool", json!([])).as_array().unwrap().iter().any(|t| t == txid)
    }

    /// A send end to end: preview, approval, broadcast, confirmation.
    pub fn send(&self, to: &str, sat: u64, fee_rate: Option<f64>) -> (Value, Value) {
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

    pub fn sign(&self, preview_id: &str) -> Value {
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


/// The sink, collecting events by name.
pub fn collecting() -> (Sink, Arc<Mutex<Vec<(String, Value)>>>) {
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
    (sink, events)
}

/// REGTEST_RPC and the cookie, or None when the chain isn't set up.
pub fn chain_env() -> Option<(String, String)> {
    let rpc = std::env::var("REGTEST_RPC").ok()?;
    let cookie = std::fs::read_to_string(std::env::var("REGTEST_COOKIE").expect("REGTEST_COOKIE")).unwrap();
    Some((rpc, cookie))
}

/// tools/regtest/chain.sh with `args`.
pub fn chain(args: &[&str]) -> String {
    let out = Command::new(std::env::var("REGTEST_CHAIN").expect("REGTEST_CHAIN: the path of tools/regtest/chain.sh")).args(args).output().unwrap();
    assert!(out.status.success(), "chain.sh {args:?}: {}", String::from_utf8_lossy(&out.stdout));
    String::from_utf8_lossy(&out.stdout).to_string()
}
