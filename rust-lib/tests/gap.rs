//! The gap limit on regtest: payments to receive indices 0 to 10 and 70 to 72, restored with a gap
//! limit of 20 by a scan that watches past 72, under Kyoto, the node's filters and Electrum. 70 to
//! 72 count apart and a spend of them is warned; a gap limit of 60 takes them in and stays.
//! Needs `--features test-hooks` and a fresh chain; README, "Regtest", has the command.

mod common;

use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::network::{configure_regtest, RegtestConfig};
use bitcoin_wallet_core::routes::Routes;
use common::history::{rows, TPRV};
use common::{chain, collecting, MockManager, ModuleRpc, T};
use serde_json::json;

const NEAR: RangeInclusive<u32> = 0..=10;
const FAR: RangeInclusive<u32> = 70..=72;

fn sat(i: u32) -> u64 {
    100_000 * u64::from(i + 1)
}

fn total(r: RangeInclusive<u32>) -> u64 {
    r.map(sat).sum()
}

/// The phrase's native segwit receive address at `i`.
fn address(t: &T, i: u32) -> String {
    let d = format!("wpkh({TPRV}/84h/1h/0h/0/*)");
    let checksum = t.rpc("getdescriptorinfo", json!([d]))["checksum"].as_str().unwrap().to_string();
    t.rpc("deriveaddresses", json!([format!("{d}#{checksum}"), [i, i]]))[0].as_str().unwrap().to_string()
}

/// A fresh engine on `root`'s wallets, routed by `routes`.
fn engine(t: &T, root: &Path, routes: Routes, node: Option<Arc<ModuleRpc>>) -> T {
    let (sink, events) = collecting();
    let engine = Engine::new(root.join("wallets"), sink, t.manager.clone(), None);
    engine.set_regtest_routes(routes);
    if let Some(n) = node {
        engine.set_node_source(n);
    }
    T { engine, rpc: t.rpc.clone(), cookie: t.cookie.clone(), events, manager: t.manager.clone() }
}

fn settled(r: &T, what: &str) {
    let tip = r.tip();
    r.wait(what, 300, || {
        let s = r.engine.status();
        s["synced"] == true && s["authority"]["height"].as_u64() == Some(tip) && s["rescanFrom"].is_null()
    });
}

fn restore(t: &T, name: &str, routes: Routes, node: Option<Arc<ModuleRpc>>, birthday: u32, paid: &BTreeMap<u32, String>) {
    let started = Instant::now();
    let root = tempfile::tempdir().unwrap();
    // Opened first with no route and addresses to 80 handed out: the restore then watches past 72.
    let a = engine(t, root.path(), Routes::regtest(&RegtestConfig { poll_secs: Some(1), ..Default::default() }), None);
    let opened = a.job("open_wallet", json!({"network": "regtest", "family": "bitcoin", "birthday": birthday, "gapLimit": 20}));
    assert_eq!(opened["gapLimit"], 20, "{opened}");
    let group = opened["group"].as_str().unwrap().to_string();
    a.engine.reveal_for_test(80).unwrap();
    a.job("close_wallet", json!({}));
    a.engine.shutdown();

    let r = engine(t, root.path(), routes, node);
    assert_eq!(r.job("open_wallet", json!({"network": "regtest", "group": group}))["gapLimit"], 20, "{name}: kept");
    r.wait(&format!("{name}: every payment"), 300, || rows(&r).values().filter(|w| w["state"] == "confirmed").count() == paid.len());
    settled(&r, &format!("{name}: the scan done"));

    // 70 to 72 lie past index 10 plus a gap of 20: apart, and in no other figure.
    let b = r.engine.balance();
    assert_eq!(b["beyondGap"], json!({"count": 3, "sat": total(FAR).to_string(), "confirmedSat": total(FAR).to_string()}), "{name}: {b}");
    assert_eq!(r.sats("confirmed"), total(NEAR), "{name}: {b}");
    let got = rows(&r);
    for (i, txid) in paid {
        assert_eq!(got[txid]["beyondGap"], FAR.contains(i), "{name}: index {i}: {}", got[txid]);
    }

    // Send-max takes them too, and says so.
    let miner = t.wallet_rpc("getnewaddress", json!(["gap"])).as_str().unwrap().to_string();
    let p = r.job("build_send", json!({"recipients": [{"address": miner}], "sendMax": true, "feeRate": 2.0}));
    let w = p["warnings"].as_array().unwrap().iter().find(|w| w["kind"] == "beyond_gap_inputs").cloned().unwrap_or_else(|| panic!("{name}: no warning: {p}"));
    assert_eq!((w["count"].clone(), w["sat"].clone()), (json!(3), json!(total(FAR).to_string())), "{name}: {w}");
    assert!(w["message"].as_str().is_some_and(|m| !m.is_empty()));
    r.job("cancel_send", json!({"previewId": p["previewId"]}));

    // A gap limit of 60 reaches 70 from 10: the scans go again, and the coins count as any.
    let set = r.job("set_gap_limit", json!({"gapLimit": 60}));
    assert_eq!(set, json!({"gapLimit": 60, "rescanFrom": r.engine.status()["birthday"]}), "{name}");
    settled(&r, &format!("{name}: the wider scan done"));
    let b = r.engine.balance();
    assert_eq!((b["beyondGap"]["count"].clone(), r.sats("confirmed")), (json!(0), total(NEAR) + total(FAR)), "{name}: {b}");
    assert!(rows(&r).values().all(|w| w["beyondGap"] == false), "{name}");

    r.job("close_wallet", json!({}));
    assert_eq!(r.job("open_wallet", json!({"network": "regtest", "group": group}))["gapLimit"], 60, "{name}: kept on reopening");
    assert_eq!(r.engine.status()["gapLimit"], 60);
    println!("GAP {name}: 70 to 72 beyond a gap of 20, warned when spent, taken in at 60, kept; {} s", started.elapsed().as_secs());
    r.engine.shutdown();
}

#[test]
#[ignore]
fn coins_beyond_the_gap_limit() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    configure_regtest(RegtestConfig::default());
    let manager = Arc::new(MockManager::new(Duration::from_millis(300)));
    let (sink, events) = collecting();
    let root = tempfile::tempdir().unwrap();
    let t = T { engine: Engine::new(root.path().join("wallets"), sink, manager.clone(), None), rpc: rpc.clone(), cookie: cookie.clone(), events, manager };

    let birthday = t.tip() as u32 + 1;
    let mut paid = BTreeMap::new();
    for i in NEAR.chain(FAR) {
        paid.insert(i, t.fund(&address(&t, i), sat(i) as f64 / 1e8).to_string());
        if i % 4 == 3 {
            t.mine(1);
        }
    }
    t.mine(1);

    let peers: Vec<String> = chain(&["peers"]).trim().split(',').map(String::from).collect();
    restore(&t, "kyoto", Routes::regtest(&RegtestConfig { kyoto: peers, poll_secs: Some(1), kyoto_required: Some(2), ..Default::default() }), None, birthday, &paid);
    let node = Arc::new(ModuleRpc::new(rpc, cookie));
    restore(&t, "node", Routes::regtest(&RegtestConfig { local: true, poll_secs: Some(1), ..Default::default() }), Some(node), birthday, &paid);
    let electrum = format!("tcp://{}", std::env::var("REGTEST_ELECTRUM").expect("REGTEST_ELECTRUM").split(',').next().unwrap().trim().trim_start_matches("tcp://"));
    restore(&t, "electrum", Routes::regtest(&RegtestConfig { electrum: vec![electrum], poll_secs: Some(1), ..Default::default() }), None, birthday, &paid);
}
