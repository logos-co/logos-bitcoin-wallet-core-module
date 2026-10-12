//! The history the restore tests build first, in a Core wallet holding the test phrase's keys, and
//! the checks that a restore shows what that wallet shows.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::network::RegtestConfig;
use bitcoin_wallet_core::routes::{Kind, Routes};
use serde_json::{json, Value};

use super::{collecting, ModuleRpc, T};

/// The test phrase's master key on test networks (abandon ×11 about).
pub const TPRV: &str = "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd";
/// The receive indices the segwit history pays, in that order: within the gap limit of each other,
/// but out of order, so a scan that watches too few, or widens only as it goes, misses some.
pub const PAID: [u32; 16] = [0, 40, 10, 20, 70, 30, 50, 60, 100, 80, 90, 130, 110, 120, 150, 140];
/// The taproot history's: all in the first window.
pub const PAID_TAPROOT: [u32; 4] = [0, 1, 2, 3];

/// What Core's wallet of the phrase shows once the history is built; `mid` is the tip halfway.
pub struct History {
    pub birthday: u32,
    pub mid: u32,
    pub heights: BTreeMap<String, u64>,
    pub confirmed: u64,
}

pub fn victim(t: &T, wallet: &str, method: &str, params: Value) -> Value {
    t.rpc_at(&format!("/wallet/{wallet}"), method, params)
}

pub fn sats(btc: &Value) -> u64 {
    (btc.as_f64().unwrap() * 1e8).round() as u64
}

/// Core's wallet `name` of the phrase's `script` keys pays `paid` in order; some coins are spent in
/// their own block, with change, others swept the block after, with none.
pub fn build_history(t: &T, name: &str, script: &str, purpose: u32, paid: &[u32]) -> History {
    let victim = |method: &str, params: Value| victim(t, name, method, params);
    let birthday = t.tip() as u32 + 1;
    t.rpc("createwallet", json!({"wallet_name": name, "blank": true, "descriptors": true}));
    let desc = |branch: u32| {
        let d = format!("{script}({TPRV}/{purpose}h/1h/0h/{branch}/*)");
        let checksum = t.rpc("getdescriptorinfo", json!([d]))["checksum"].as_str().unwrap().to_string();
        format!("{d}#{checksum}")
    };
    let (external, internal) = (desc(0), desc(1));
    let imported = victim("importdescriptors", json!([[
        {"desc": external, "active": true, "internal": false, "range": [0, 200], "timestamp": "now"},
        {"desc": internal, "active": true, "internal": true, "range": [0, 200], "timestamp": "now"},
    ]]));
    assert!(imported.as_array().unwrap().iter().all(|r| r["success"] == true), "{imported}");
    let address = |i: u32| t.rpc("deriveaddresses", json!([external, [i, i]]))[0].as_str().unwrap().to_string();
    let miner = t.wallet_rpc("getnewaddress", json!(["back"])).as_str().unwrap().to_string();
    let mut mid = 0;
    for (n, i) in paid.iter().enumerate() {
        let to = address(*i);
        // From whole satoshis: 0.5 + n * 0.01 would carry float noise past eight decimals.
        let funding = t.fund(&to, (50_000_000 + n as u64 * 1_000_000) as f64 / 1e8).to_string();
        // The victim's wallet hears of the payment once the validation queue drains.
        t.rpc("syncwithvalidationinterfacequeue", json!([]));
        let vout = || {
            let tx = victim("gettransaction", json!([funding]));
            tx["details"].as_array().unwrap().iter().find(|d| d["address"] == to.as_str()).unwrap()["vout"].clone()
        };
        match n % 4 {
            1 => {
                let mut back = serde_json::Map::new();
                back.insert(miner.clone(), json!(0.1));
                let sent = victim("send", json!({"outputs": [back], "options": {"inputs": [{"txid": funding, "vout": vout()}], "add_inputs": false, "include_unsafe": true, "fee_rate": 2}}));
                assert_eq!(sent["complete"], true, "{sent}");
            }
            2 => {
                t.mine(1);
                t.rpc("syncwithvalidationinterfacequeue", json!([]));
                let swept = victim("sendall", json!({"recipients": [miner], "fee_rate": 2, "options": {"inputs": [{"txid": funding, "vout": vout()}]}}));
                assert_eq!(swept["complete"], true, "{swept}");
            }
            _ => {}
        }
        t.mine(1);
        t.rpc("syncwithvalidationinterfacequeue", json!([]));
        if n == paid.len() / 2 {
            mid = t.tip() as u32;
        }
    }
    t.mine(1);
    t.rpc("syncwithvalidationinterfacequeue", json!([]));
    let mut heights = BTreeMap::new();
    for e in victim("listtransactions", json!(["*", 10000, 0, true])).as_array().unwrap() {
        assert!(e["confirmations"].as_i64().unwrap() > 0, "{e}");
        heights.insert(e["txid"].as_str().unwrap().to_string(), e["blockheight"].as_u64().unwrap());
    }
    let confirmed = sats(&victim("getbalances", json!([]))["mine"]["trusted"]);
    println!("RESTORE history {name}: {} transactions from {birthday} to {}, halfway at {mid}, {confirmed} sat", heights.len(), t.tip());
    History { birthday, mid, heights, confirmed }
}

/// A fresh engine and wallet directory on `routes`, the phrase's native segwit (or `taproot`) wallet
/// restored with `birthday`.
pub fn restore(t: &T, routes: Routes, birthday: u32, node: Option<Arc<ModuleRpc>>) -> (T, tempfile::TempDir) {
    restore_family(t, routes, birthday, node, "bitcoin")
}

pub fn restore_family(t: &T, routes: Routes, birthday: u32, node: Option<Arc<ModuleRpc>>, family: &str) -> (T, tempfile::TempDir) {
    restore_with(t, routes, birthday, node, family, false, None)
}

/// As `restore_family`; with `by_restart`, Kyoto widens a scan by a new client, the old way, and
/// `on_widen` is called as each wider scan is about to start.
pub fn restore_with(t: &T, routes: Routes, birthday: u32, node: Option<Arc<ModuleRpc>>, family: &str, by_restart: bool, on_widen: Option<Arc<dyn Fn() + Send + Sync>>) -> (T, tempfile::TempDir) {
    let (sink, events) = collecting();
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(root.path().join("wallets"), sink, t.manager.clone(), None);
    engine.set_widen_by_restart(by_restart);
    if let Some(f) = on_widen {
        engine.set_on_widen(f);
    }
    engine.set_regtest_routes(routes);
    if let Some(n) = node {
        engine.set_node_source(n);
    }
    let r = T { engine, rpc: t.rpc.clone(), cookie: t.cookie.clone(), events, manager: t.manager.clone() };
    r.job("open_wallet", json!({"network": "regtest", "family": family, "birthday": birthday}));
    (r, root)
}

/// Every history row by txid.
pub fn rows(r: &T) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    for page in 0.. {
        let h = r.engine.history(page);
        let got = h["rows"].as_array().unwrap();
        for row in got {
            out.insert(row["txid"].as_str().unwrap().to_string(), row.clone());
        }
        if got.is_empty() || out.len() as u64 >= h["total"].as_u64().unwrap() {
            break;
        }
    }
    out
}

/// The restore at the tip with nothing left to scan, then the same view as Core's, on a chain that
/// starts at `base`.
pub fn matches(name: &str, r: &T, h: &History, base: u32, started: Instant) {
    let tip = r.tip();
    r.wait(&format!("{name}: synced to {tip} with no scan left"), 600, || {
        let s = r.engine.status();
        s["synced"] == true && s["authority"]["height"].as_u64() == Some(tip) && s["rescanFrom"].is_null()
    });
    let got = rows(r);
    let mut wrong = vec![];
    for (txid, height) in &h.heights {
        match got.get(txid) {
            Some(row) if row["state"] == "confirmed" && row["height"].as_u64() == Some(*height) => {}
            Some(row) => wrong.push(format!("{txid} at {height}: {} at {}", row["state"], row["height"])),
            None => wrong.push(format!("{txid} at {height}: missing")),
        }
    }
    wrong.extend(got.keys().filter(|t| !h.heights.contains_key(*t)).map(|t| format!("{t}: not Core's")));
    let s = r.engine.status();
    println!("RESTORE {name}: {} of {} rows in {} ms; authority base {}, kyoto {}, node {}", got.len(), h.heights.len(), started.elapsed().as_millis(),
        s["authority"]["base"], s["kyoto"], s["node"]);
    assert!(wrong.is_empty(), "{name}: {} row(s) differ from Core's wallet:\n{}", wrong.len(), wrong.join("\n"));
    assert_eq!(r.sats("confirmed"), h.confirmed, "{name}: the confirmed balance");
    assert_eq!(s["authority"]["base"], base, "{name}: the chain starts at the checkpoint below the birthday");
}

pub fn esplora_routes(electrum: &str, esplora: &str) -> Routes {
    let mut r = Routes::regtest(&RegtestConfig { electrum: vec![electrum.into()], esplora: vec![esplora.into()], poll_secs: Some(1), ..Default::default() });
    let e = r.history.iter().find(|s| s.kind == Kind::Esplora).cloned().expect("the Esplora source");
    (r.history, r.pending, r.fees, r.broadcast, r.check) = (vec![e.clone()], vec![e.clone()], vec![e.clone()], vec![e.clone()], vec![e]);
    r
}

