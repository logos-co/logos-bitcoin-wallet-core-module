//! The wallet core's side of `signer_manager_module`: open grants and PSBT approvals. The core is
//! the requester; it keeps every receipt and hands only handles upward.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::network::{BNetwork, Family};

/// The manager over IPC, or in process for tests. `Err` means it could not be reached; a reply,
/// refusals included, comes back as `Ok` with the manager's JSON.
pub trait SignerManager: Send + Sync {
    fn request_open(&self, params_json: &str) -> Result<String, String>;
    fn request_approval(&self, intent_json: &str) -> Result<String, String>;
    fn approval_status(&self, handle: &str, receipt: &str) -> Result<String, String>;
    fn fetch_result(&self, handle: &str, receipt: &str) -> Result<String, String>;
    fn ack_result(&self, handle: &str, receipt: &str) -> Result<bool, String>;
    fn cancel_approval(&self, handle: &str, receipt: &str) -> Result<bool, String>;
    fn close_account(&self, params_json: &str) -> Result<String, String>;
}

/// A request in flight: the handle goes up to the backend and the app, the receipt never leaves.
pub struct Ticket {
    pub handle: String,
    pub receipt: Zeroizing<String>,
}

fn parse(reply: &str) -> Result<Value, String> {
    let v: Value = serde_json::from_str(reply).map_err(|e| format!("signer manager: {e}"))?;
    if v["ok"] != true {
        return Err(v["error"].as_str().unwrap_or("the signer manager refused").to_string());
    }
    Ok(v)
}

pub fn ticket(reply: &str) -> Result<Ticket, String> {
    let v = parse(reply)?;
    let handle = v["handle"].as_str().ok_or("signer manager: no handle")?.to_string();
    let receipt = Zeroizing::new(v["receipt"].as_str().ok_or("signer manager: no receipt")?.to_string());
    Ok(Ticket { handle, receipt })
}

/// `(state, reason)`; the reason is set once settled.
pub fn status(reply: &str) -> Result<(String, Option<String>), String> {
    let v = parse(reply)?;
    Ok((v["state"].as_str().unwrap_or("").to_string(), v["reason"].as_str().map(str::to_string)))
}

/// The open request: reopen a group, or let the person pick, create or restore one of a family.
pub fn open_params(network: BNetwork, group: Option<&str>, family: Option<Family>) -> Result<String, String> {
    let reason = "The Bitcoin wallet opens it to sync, show the balance and prepare sends.";
    match (group, family) {
        (Some(g), _) => Ok(json!({"group": g, "network": network.name(), "reason": reason}).to_string()),
        (None, Some(f)) => Ok(json!({"family": f.name(), "network": network.name(), "reason": reason}).to_string()),
        (None, None) => Err("name a group to reopen, or a family".into()),
    }
}

/// What an approved open hands over. The database key lives only here and in the open wallet.
pub struct OpenGrant {
    pub group: String,
    pub family: Family,
    pub network: Option<String>,
    pub external: String,
    pub internal: String,
    pub fingerprint: String,
    pub database_key: Zeroizing<[u8; 32]>,
    /// `created` or `restored`, from managers that say.
    pub origin: Option<String>,
    /// The UTC day the wallet was made, or the day the person gave on restore.
    pub birthday: Option<String>,
}

/// `Ok(None)` while the person hasn't decided.
pub fn open_grant(reply: &str, net: BNetwork) -> Result<Option<OpenGrant>, String> {
    let v: Value = serde_json::from_str(reply).map_err(|e| format!("signer manager: {e}"))?;
    if v["ok"] != true {
        let e = v["error"].as_str().unwrap_or("the signer manager refused");
        return if e.contains("no result for this handle") { Ok(None) } else { Err(e.to_string()) };
    }
    let r = &v["result"];
    let s = |k: &str| r[k].as_str().map(str::to_string).ok_or_else(|| format!("open result: no {k}"));
    let family = Family::parse(&s("family")?).ok_or("open result: not a Bitcoin family")?;
    if s("chain")? != net.chain() {
        return Err(format!("the wallet is on the {} chain, not {}'s", s("chain")?, net.name()));
    }
    let mut hex_key = Zeroizing::new(s("databaseKey")?);
    let mut key = Zeroizing::new([0u8; 32]);
    let decoded = hex::decode_to_slice(hex_key.as_bytes(), &mut key[..]);
    zeroize::Zeroize::zeroize(&mut *hex_key);
    decoded.map_err(|_| "open result: the database key is not 32 bytes of hex")?;
    let grant = OpenGrant {
        group: s("group")?,
        family,
        network: r["network"].as_str().map(str::to_string),
        external: s("external")?,
        internal: s("internal")?,
        fingerprint: s("fingerprint")?,
        database_key: key,
        origin: r["origin"].as_str().map(str::to_string),
        birthday: r["birthday"].as_str().map(str::to_string),
    };
    let expect = if family == Family::Bitcoin { "wpkh(" } else { "tr(" };
    if !grant.external.starts_with(expect) || !grant.internal.starts_with(expect) {
        return Err(format!("open result: descriptors are not {}", family.name()));
    }
    Ok(Some(grant))
}

/// A Bitcoin intent: the group and exactly one psbt leg.
pub fn approval_intent(group: &str, purpose: &str, network: BNetwork, psbt_base64: &str) -> String {
    json!({"group": group, "purpose": purpose, "legs": [{"kind": "psbt", "network": network.name(), "psbt": psbt_base64}]}).to_string()
}

pub fn signed_psbts(reply: &str) -> Result<Vec<String>, String> {
    let v = parse(reply)?;
    let arr = v["signed"].as_array().ok_or("signer manager: no signed PSBTs")?;
    arr.iter().map(|s| s.as_str().map(str::to_string).ok_or_else(|| "signer manager: a signed leg is not a string".to_string())).collect()
}

/// Wakes waiters when the manager announces a settlement, so they need not wait out a poll.
#[derive(Default)]
pub struct Settled {
    seen: Mutex<HashSet<String>>,
    cv: Condvar,
}

impl Settled {
    pub fn notify(&self, handle: &str) {
        self.seen.lock().unwrap().insert(handle.to_string());
        self.cv.notify_all();
    }

    /// True once `handle` was announced, or after `timeout` when it wasn't.
    pub fn wait(&self, handle: &str, timeout: Duration) -> bool {
        let guard = self.seen.lock().unwrap();
        let (mut guard, _) = self.cv.wait_timeout_while(guard, timeout, |s| !s.contains(handle)).unwrap();
        guard.remove(handle)
    }
}

/// Polls until the request settles and returns its reason. Gives up on `cancel` or after `limit`.
pub fn wait_settled(
    m: &dyn SignerManager,
    t: &Ticket,
    settled: &Settled,
    cancel: &AtomicBool,
    limit: Duration,
    mut on_state: impl FnMut(&str),
) -> Result<String, String> {
    let start = Instant::now();
    let mut failures = 0;
    loop {
        if cancel.load(Ordering::SeqCst) {
            let _ = m.cancel_approval(&t.handle, &t.receipt);
            return Err("cancelled".into());
        }
        match m.approval_status(&t.handle, &t.receipt).and_then(|r| status(&r)) {
            Ok((state, reason)) => {
                failures = 0;
                on_state(&state);
                if state == "settled" {
                    return Ok(reason.unwrap_or_else(|| "settled".into()));
                }
            }
            Err(e) => {
                failures += 1;
                if failures >= 10 {
                    return Err(format!("the signer manager stopped answering: {e}"));
                }
            }
        }
        if start.elapsed() > limit {
            let _ = m.cancel_approval(&t.handle, &t.receipt);
            return Err("gave up waiting for the decision".into());
        }
        settled.wait(&t.handle, Duration::from_millis(1000));
    }
}

/// Shared by both waits: what a settled reason means for the job.
pub fn require_approved(reason: &str) -> Result<(), String> {
    match reason {
        "approved" => Ok(()),
        "rejected" => Err("rejected: the person declined".into()),
        "cancelled" => Err("cancelled".into()),
        "expired_no_ack" => Err("expired_no_ack: nobody showed the request in time; ask again".into()),
        other => Err(format!("settled without approval: {other}")),
    }
}

pub type ManagerRef = Arc<dyn SignerManager>;

#[cfg(test)]
mod tests {
    use super::*;

    const EXT: &str = "wpkh([73c5da0a/84'/1'/0']tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/0/*)#2ag6nxcd";

    fn reply(extra: Value) -> String {
        let mut r = json!({"group": "g_1", "family": "bitcoin", "chain": "test", "network": "regtest",
            "external": EXT, "internal": EXT.replace("/0/*", "/1/*"), "fingerprint": "73c5da0a",
            "databaseKey": "ab".repeat(32), "unlocked": null});
        for (k, v) in extra.as_object().unwrap() {
            r[k] = v.clone();
        }
        json!({"ok": true, "result": r}).to_string()
    }

    #[test]
    fn an_open_grant_is_read_whole_and_checked() {
        crate::network::configure_regtest(Default::default());
        let g = open_grant(&reply(json!({})), BNetwork::Regtest).unwrap().unwrap();
        assert_eq!((g.group.as_str(), g.family), ("g_1", Family::Bitcoin));
        assert_eq!(*g.database_key, [0xab; 32]);
        assert_eq!((g.origin, g.birthday), (None, None), "older managers say neither");
        let g = open_grant(&reply(json!({"origin": "created", "birthday": "2026-10-01"})), BNetwork::Regtest).unwrap().unwrap();
        assert_eq!((g.origin.as_deref(), g.birthday.as_deref()), (Some("created"), Some("2026-10-01")));
        // A wallet on the main chain does not open on regtest, and keys must be 32 bytes.
        assert!(open_grant(&reply(json!({"chain": "main"})), BNetwork::Regtest).is_err());
        assert!(open_grant(&reply(json!({"databaseKey": "abcd"})), BNetwork::Regtest).is_err());
        assert!(open_grant(&reply(json!({"family": "bitcoin_taproot"})), BNetwork::Regtest).is_err(), "descriptor kind must match");
        let pending = json!({"ok": false, "error": "invalid parameters: no result for this handle"}).to_string();
        assert!(open_grant(&pending, BNetwork::Regtest).unwrap().is_none());
        let refused = json!({"ok": false, "error": "not authorized"}).to_string();
        assert_eq!(open_grant(&refused, BNetwork::Regtest).err().as_deref(), Some("not authorized"));
    }

    #[test]
    fn requests_are_shaped_as_the_manager_takes_them() {
        let p: Value = serde_json::from_str(&open_params(BNetwork::Signet, Some("g_1"), None).unwrap()).unwrap();
        assert_eq!((p["group"].clone(), p["network"].clone()), (json!("g_1"), json!("signet")));
        let p: Value = serde_json::from_str(&open_params(BNetwork::Mainnet, None, Some(Family::BitcoinTaproot)).unwrap()).unwrap();
        assert_eq!((p["family"].clone(), p.get("group")), (json!("bitcoin_taproot"), None));
        let i: Value = serde_json::from_str(&approval_intent("g_1", "Send", BNetwork::Signet, "cHNidP8=")).unwrap();
        assert_eq!(i["legs"].as_array().unwrap().len(), 1);
        assert_eq!(i["legs"][0]["kind"], "psbt");
        assert_eq!(signed_psbts(&json!({"ok": true, "signed": ["cHNidP8="]}).to_string()).unwrap(), vec!["cHNidP8="]);
        assert!(require_approved("approved").is_ok());
        assert!(require_approved("expired_no_ack").unwrap_err().starts_with("expired_no_ack"));
    }

    #[test]
    fn a_settlement_wakes_the_waiter() {
        let s = Arc::new(Settled::default());
        let s2 = s.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            s2.notify("smh_1");
        });
        let t0 = Instant::now();
        assert!(s.wait("smh_1", Duration::from_secs(5)));
        assert!(t0.elapsed() < Duration::from_secs(2));
        assert!(!s.wait("smh_2", Duration::from_millis(10)));
    }
}
