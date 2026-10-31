//! Kyoto as the chain authority on tools/regtest/chain.sh's chain: three filter-serving Core
//! nodes behind proxies the test steers. Receive, send and confirm; a reorg; a restart after
//! NoReachablePeers; a rebuild past the lookahead; and a peer forging filter headers. Then a
//! matched block reorganized away before its fetch, and an update stream that ends.
//! Needs `--features test-hooks`; the run command is in the README.

mod common;
#[path = "../examples/p2p_proxy.rs"]
#[allow(dead_code)]
mod p2p_proxy;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin_wallet_core::engine::hooks::{END_KYOTO_UPDATES, SYNC_THREADS};
use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::network::{configure_regtest, RegtestConfig};
use common::{chain, collecting, MockManager, T};
use p2p_proxy::{Mode, Proxy};
use serde_json::{json, Value};

fn kyoto(t: &T) -> Value {
    t.engine.status()["kyoto"].clone()
}

fn delay(command: &str, ms: u64) -> Mode {
    Mode::Delay { ms: HashMap::from([(command.to_string(), ms)]) }
}

#[test]
#[ignore]
fn kyoto_is_the_authority_on_regtest() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    let nodes: Vec<SocketAddr> = chain(&["peers"]).trim().split(',').map(|s| s.parse().unwrap()).collect();
    assert_eq!(nodes.len(), 3, "three filter-serving peers");
    let proxies: Vec<Proxy> = nodes.iter().map(|n| Proxy::start("127.0.0.1:0", *n, Mode::Forward)).collect();
    let electrum = std::env::var("REGTEST_ELECTRUM").ok().and_then(|e| e.split(',').next().map(|s| format!("tcp://{}", s.trim().trim_start_matches("tcp://"))));
    configure_regtest(RegtestConfig {
        kyoto: proxies.iter().map(|p| p.addr.to_string()).collect(),
        // One electrs only to be checked against Kyoto's headers; Kyoto finds the payments.
        electrum: electrum.into_iter().collect(),
        check_only: true,
        poll_secs: Some(1),
        // All three peers connected, so the forging one is always asked.
        kyoto_required: Some(3),
        ..Default::default()
    });
    let (sink, events) = collecting();
    let manager = Arc::new(MockManager::new(Duration::from_millis(300)));
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(root.path().join("wallets"), sink, manager.clone(), None);
    let t = T { engine, rpc, cookie, events, manager };
    let started = Instant::now();

    // Open: a first sync from regtest's genesis through Kyoto.
    let opened = t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    assert_eq!(opened["family"], "bitcoin");
    t.synced();
    let st = t.engine.status();
    assert_eq!(st["authority"]["kind"], "kyoto", "{st}");
    assert_eq!(st["kyoto"]["phase"], "synced", "{st}");
    let tip = t.tip();
    t.wait("the filters' scan stored at the tip", 15, || kyoto(&t)["scanned"].as_u64() >= Some(tip));
    t.wait("a quorum of three peers", 15, || kyoto(&t)["connected"].as_u64().unwrap_or(0) >= 3);
    println!("KYOTO first sync to {} in {} ms", t.tip(), started.elapsed().as_millis());
    assert_eq!(t.engine.history(0)["total"], 0, "start from a fresh `chain.sh prepare`");

    // Receive and confirm: Kyoto's filters match the payment's block.
    let addr = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let funded = t.fund(&addr, 1.0).to_string();
    t.mine(1);
    t.synced();
    t.wait("the payment confirmed", 60, || t.sats("confirmed") == 100_000_000);
    let r = t.row(&funded);
    assert_eq!((r["state"].clone(), r["reportedBy"].clone()), (json!("confirmed"), Value::Null), "{r}");
    assert_eq!(t.engine.status()["historyServer"], "kyoto");

    // Send: broadcast through Kyoto's peers, confirmed through its filters.
    let theirs = t.wallet_rpc("getnewaddress", json!(["payee"])).as_str().unwrap().to_string();
    let p = t.job("build_send", json!({"recipients": [{"address": theirs, "amountSat": "10000000"}], "feeRate": 2.0}));
    let sent = t.sign(p["previewId"].as_str().unwrap());
    let txid = sent["txid"].as_str().unwrap().to_string();
    assert_eq!((sent["via"].clone(), sent["broadcast"].clone()), (json!("kyoto"), json!("requested")), "{sent}");
    t.wait("the send in the node's mempool", 30, || t.in_mempool(&txid));
    t.mine(1);
    t.synced();
    t.wait("the send confirmed", 60, || t.row(&txid)["state"] == "confirmed");
    assert_eq!(t.row(&txid)["intent"], "send");

    // The Electrum server is checked against Kyoto's headers, never asked for history.
    if let Some(row) = t.engine.sources_status()["sources"].as_array().unwrap().iter().find(|s| s["id"] == "electrum-0").cloned() {
        t.wait("the server's tip checked", 30, || {
            let s = t.engine.sources_status();
            s["sources"].as_array().unwrap().iter().any(|r| r["id"] == "electrum-0" && r["tip"].as_u64() == Some(t.tip()))
        });
        assert_eq!(t.engine.exposure()["servers"].as_array().unwrap().len(), 0, "no server learned an address: {row}");
    }

    // A reorg: the block holding a payment is replaced; Kyoto reorganizes and the anchor follows.
    let addr2 = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let reorged = t.fund(&addr2, 0.2).to_string();
    t.mine(1);
    t.synced();
    t.wait("the payment confirmed", 60, || t.row(&reorged)["state"] == "confirmed");
    let h = t.tip();
    let old_block = t.rpc("getblockhash", json!([h]));
    assert_eq!(t.row(&reorged)["blockHash"], old_block);
    chain(&["reorg", "1"]);
    let new_block = t.rpc("getblockhash", json!([h]));
    assert_ne!(old_block, new_block);
    t.synced();
    t.wait("the payment re-anchored in the new block", 90, || {
        let r = t.row(&reorged);
        r["state"] == "confirmed" && r["height"].as_u64() == Some(h) && r["confirmations"] == 2
    });
    assert_eq!(t.row(&reorged)["blockHash"], new_block, "the row names the new block");
    let lr = t.engine.status()["lastReorg"].clone();
    assert_eq!((lr["height"].as_u64(), lr["depth"].as_u64()), (Some(h), Some(1)), "{lr}");
    assert!(lr["moved"].as_array().unwrap().contains(&json!(reorged)), "{lr}");
    t.wait("walletStateChanged with the reorg", 10, || t.events.lock().unwrap().iter().any(|(n, v)| n == "walletStateChanged" && v["lastReorg"] == lr));
    println!("KYOTO reorg at {h}: {old_block} replaced by {new_block}");

    // A birthday: Kyoto starts again from it and scans its filters; every payment is still there.
    let first_height = t.row(&funded)["height"].as_u64().unwrap();
    assert!(t.job_err("set_birthday", json!({"height": first_height + 1})).contains("before a birthday"));
    let set = t.job("set_birthday", json!({"height": first_height}));
    t.wait("Kyoto's rescan", 90, || t.engine.status()["rescanFrom"].is_null());
    t.synced();
    assert!(t.events.lock().unwrap().iter().any(|(n, v)| n == "walletStateChanged" && v["rescanFrom"] == set["rescanFrom"]));
    for id in [&funded, &txid, &reorged] {
        assert_eq!(t.row(id)["state"], "confirmed", "{id} after the rescan");
    }

    // A burst of 100 blocks: the cross-checked electrs lags behind Kyoto for a moment, which
    // raises nothing; only a lag that lasts does.
    let stale = t.alerts("stale", "electrum-0");
    t.mine(100);
    t.synced();
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(t.alerts("stale", "electrum-0"), stale, "a burst raised a stale alert");

    // Addresses revealed past what the client watches: it is rebuilt, and finds a payment there.
    let rebuilds = kyoto(&t)["rebuilds"].as_u64().unwrap();
    let last = t.engine.reveal_for_test(30).unwrap();
    assert!(last >= 29, "{last}");
    t.wait("a rebuild", 30, || kyoto(&t)["rebuilds"].as_u64().unwrap() > rebuilds);
    let far = t.engine.addresses()["addresses"].as_array().unwrap().iter().find(|a| a["index"] == last).unwrap()["address"].as_str().unwrap().to_string();
    let far_tx = t.fund(&far, 0.03).to_string();
    t.mine(1);
    t.synced();
    t.wait("the payment to the far address", 90, || t.row(&far_tx)["state"] == "confirmed");
    println!("KYOTO rebuild: address {last} revealed past the lookahead, paid and found");

    // NoReachablePeers: every peer goes away; Kyoto runs out and restarts on a fresh subset.
    let restarts = kyoto(&t)["restarts"].as_u64().unwrap();
    for p in &proxies {
        p.set(Mode::Down);
    }
    t.wait("a stop for want of peers", 60, || kyoto(&t)["restarts"].as_u64().unwrap() > restarts);
    let addr3 = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let while_down = t.fund(&addr3, 0.04).to_string();
    t.mine(1);
    std::thread::sleep(Duration::from_secs(3));
    assert_ne!(t.row(&while_down)["state"], "confirmed", "no peer, no news");
    for p in &proxies {
        p.set(Mode::Forward);
    }
    t.synced();
    t.wait("the payment after the restart", 180, || t.row(&while_down)["state"] == "confirmed");
    let k = kyoto(&t);
    println!("KYOTO restarts: {} after NoReachablePeers; last stop: {}", k["restarts"], k["lastStop"]);
    assert!(k["lastStop"].as_str().unwrap_or("").contains("exhausted"), "{k}");

    // A peer forging filter headers: it answers first, five times over, enough for a quorum of
    // three without patch 1; the honest peers answer later. Patch 1 counts it once: no update
    // hides the payment.
    let addr4 = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let raw = t.wallet_rpc("createrawtransaction", json!([[], {addr4.clone(): 0.05}]));
    let funded_raw = t.wallet_rpc("fundrawtransaction", json!([raw]))["hex"].clone();
    let signed = t.wallet_rpc("signrawtransactionwithwallet", json!([funded_raw]))["hex"].as_str().unwrap().to_string();
    let hidden: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(&signed).unwrap();
    let hidden_id = hidden.compute_txid().to_string();
    let miner = t.wallet_rpc("getnewaddress", json!(["mine"]));
    let block = t.rpc("generateblock", json!([miner, [signed], false]));
    let target: bitcoin::BlockHash = block["hash"].as_str().unwrap().parse().unwrap();
    proxies[0].set(Mode::Forge { block: target, copies: 5 });
    proxies[1].set(delay("cfheaders", 2_000));
    proxies[2].set(delay("cfheaders", 2_000));
    let restarts = kyoto(&t)["restarts"].as_u64().unwrap();
    t.rpc("submitblock", json!([block["hex"]]));
    let target_height = t.tip();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(30) {
        let st = t.engine.status();
        let tip = st["authority"]["height"].as_u64().unwrap_or(0);
        let hides = st["synced"] == true && tip >= target_height && t.row(&hidden_id).is_null();
        assert!(!hides, "a forged filter header hid the payment: {st}");
        std::thread::sleep(Duration::from_millis(200));
    }
    let k = kyoto(&t);
    println!("KYOTO forged headers: {} batches forged, {} restarts since; last warning: {}", proxies[0].count("forged"), k["restarts"].as_u64().unwrap() - restarts, k["lastWarning"]);
    assert!(proxies[0].count("forged") > 0, "the attacker was asked: {k}");
    for p in &proxies {
        p.set(Mode::Forward);
    }
    t.synced();
    t.wait("the payment once the forger stops", 180, || t.row(&hidden_id)["state"] == "confirmed");
    assert_eq!(t.row(&hidden_id)["height"].as_u64(), Some(target_height));

    let t0 = Instant::now();
    t.engine.shutdown();
    let unload_ms = t0.elapsed().as_millis();
    println!("KYOTO shutdown in {unload_ms} ms; whole run {} s", started.elapsed().as_secs());
    assert!(unload_ms < 2000, "unload took {unload_ms} ms");
}

/// A first sync through Kyoto on a long regtest chain, for time and memory: run alone, with
/// KYOTO_BLOCKS blocks mined first (default 5,000), under /usr/bin/time for the peak.
#[test]
#[ignore]
fn kyoto_first_sync_on_a_long_chain() {
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    let nodes: Vec<String> = chain(&["peers"]).trim().split(',').map(str::to_string).collect();
    configure_regtest(RegtestConfig { kyoto: nodes, poll_secs: Some(1), kyoto_required: Some(2), ..Default::default() });
    let (sink, events) = collecting();
    let manager = Arc::new(MockManager::new(Duration::from_millis(100)));
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(root.path().join("wallets"), sink, manager.clone(), None);
    let t = T { engine, rpc, cookie, events, manager };
    let blocks: u32 = std::env::var("KYOTO_BLOCKS").ok().and_then(|b| b.parse().ok()).unwrap_or(5_000);
    let have = t.tip() as u32;
    let miner = t.wallet_rpc("getnewaddress", json!(["mine"]));
    let mut left = blocks.saturating_sub(have);
    while left > 0 {
        let n = left.min(200);
        t.rpc("generatetoaddress", json!([n, miner]));
        left -= n;
    }
    // A payment near the tip, for the filters to find.
    let started = Instant::now();
    t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    let addr = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let paid = t.fund(&addr, 0.5).to_string();
    t.mine(1);
    t.synced();
    t.wait("the payment found", 600, || t.row(&paid)["state"] == "confirmed");
    // Checkpoints every 144 filters on the way, the last one at the tip.
    let tip = t.tip();
    t.wait("the filters' scan stored at the tip", 30, || kyoto(&t)["scanned"].as_u64() >= Some(tip));
    println!("KYOTO first sync of {} blocks in {} ms", t.tip(), started.elapsed().as_millis());
    t.engine.shutdown();
}

/// Routes as bitcoin_node_module would give them: Kyoto only, through Tor, these peers.
struct KyotoOnly(String);

impl bitcoin_wallet_core::sync::RouteSource for KyotoOnly {
    fn route_table(&self, _network: &str) -> Result<String, String> {
        Ok(self.0.clone())
    }
}

/// The test phrase restored on a live network through Tor, compared with an explorer's list
/// (LIVE_EXPLORER). LIVE_NETWORK, LIVE_PEERS, LIVE_PROXY, LIVE_BIRTHDAY, LIVE_OUT: README, "Regtest".
#[test]
#[ignore]
fn kyoto_on_a_live_network() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let (Ok(peers), Ok(proxy)) = (std::env::var("LIVE_PEERS"), std::env::var("LIVE_PROXY")) else {
        eprintln!("skipped: LIVE_PEERS and LIVE_PROXY are not set");
        return;
    };
    let network = std::env::var("LIVE_NETWORK").unwrap_or_else(|_| "signet".into());
    let birthday: u32 = std::env::var("LIVE_BIRTHDAY").ok().and_then(|b| b.parse().ok()).unwrap_or(325_000);
    let peers: Vec<&str> = peers.split(',').map(str::trim).filter(|p| !p.is_empty()).collect();
    let kyoto = json!({"id": "kyoto", "kind": "kyoto", "url": "p2p://peer-list", "operator": "peers", "route": "onion"});
    let table = json!({"ok": true, "network": network, "proxy": proxy, "chain": [kyoto], "history": [kyoto], "broadcast": [kyoto],
        "pending": [], "fees": [], "check": [], "peers": peers, "crossCheck": false}).to_string();
    let (sink, _events) = collecting();
    let manager = Arc::new(MockManager::new(Duration::from_millis(100)));
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(root.path().join("wallets"), sink, manager, Some(Arc::new(KyotoOnly(table))));
    let started = Instant::now();
    let r = engine.start_job("open_wallet", &json!({"network": network, "family": "bitcoin", "birthday": birthday}).to_string());
    let (id, receipt) = (r["jobId"].as_str().unwrap().to_string(), r["receipt"].as_str().unwrap().to_string());
    while engine.jobs().status(&id, &receipt)["state"] != "done" {
        assert!(started.elapsed() < Duration::from_secs(60), "{}", engine.jobs().status(&id, &receipt));
        std::thread::sleep(Duration::from_millis(100));
    }
    let mut last = String::new();
    loop {
        let st = engine.status();
        let k = &st["kyoto"];
        let line = format!("{} kyoto {} headers {} progress {:.2} connected {} restarts {} rescans {} window {} conflict {} authority {} base {} rescanFrom {}",
            st["state"], k["phase"], k["headers"], k["progress"].as_f64().unwrap_or(0.0), k["connected"], k["restarts"], k["rescans"], k["window"],
            k["lastConflict"]["at"], st["authority"]["height"], st["authority"]["base"], st["rescanFrom"]);
        if line != last {
            println!("LIVE {:>5} s: {line}", started.elapsed().as_secs());
            last = line;
        }
        if st["synced"] == true && st["rescanFrom"].is_null() {
            println!("LIVE synced to {} in {} s", st["authority"]["height"], started.elapsed().as_secs());
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(6 * 3600), "no sync in 6 hours: {st}");
        std::thread::sleep(Duration::from_secs(2));
    }
    if let Ok(path) = std::env::var("LIVE_EXPLORER") {
        let ex: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let mut rows: HashMap<String, Value> = HashMap::new();
        for page in 0.. {
            let h = engine.history(page);
            let got = h["rows"].as_array().unwrap().clone();
            rows.extend(got.iter().map(|r| (r["txid"].as_str().unwrap().to_string(), r.clone())));
            if got.is_empty() || rows.len() as u64 >= h["total"].as_u64().unwrap() {
                break;
            }
        }
        let tip = engine.status()["authority"]["height"].as_u64().unwrap();
        let upto = ex["tipBefore"].as_u64().unwrap().min(tip);
        let mut diffs = vec![];
        let listed: Vec<&Value> = ex["txs"].as_array().unwrap().iter().filter(|e| e["confirmed"] == true && e["height"].as_u64().unwrap() <= upto).collect();
        for e in &listed {
            let (txid, height) = (e["txid"].as_str().unwrap(), e["height"].as_u64().unwrap());
            match rows.get(txid) {
                Some(r) if r["state"] == "confirmed" && r["height"].as_u64() == Some(height) => {}
                Some(r) => diffs.push(json!({"txid": txid, "explorer": height, "wallet": [r["state"], r["height"]]})),
                None => diffs.push(json!({"txid": txid, "explorer": height, "wallet": null})),
            }
        }
        // Rows the explorer lacks: a gap-limit explorer misses payments past 20 unused addresses that
        // a wider scan's window happens to hold. Listed for a look, not failed.
        let known: std::collections::HashSet<&str> = listed.iter().map(|e| e["txid"].as_str().unwrap()).collect();
        let extra: Vec<Value> = rows.iter().filter(|(t, r)| r["height"].as_u64().is_some_and(|h| h <= upto) && !known.contains(t.as_str()))
            .map(|(t, r)| json!({"txid": t, "wallet": [r["state"], r["height"]], "amountSat": r["amountSat"], "intent": r["intent"]})).collect();
        let after = rows.values().filter(|r| r["height"].as_u64().is_none_or(|h| h > upto)).count();
        let balance = engine.balance();
        let summary = json!({"network": network, "birthday": birthday, "seconds": started.elapsed().as_secs(), "tip": tip, "explorerTip": upto,
            "explorerTxs": listed.len(), "walletRows": rows.len(), "rowsAfterExplorerTip": after, "differences": diffs, "extra": extra,
            "walletConfirmed": balance["confirmed"], "explorerConfirmed": ex["balance"]["confirmed"], "status": engine.status()});
        if let Ok(out) = std::env::var("LIVE_OUT") {
            std::fs::write(out, serde_json::to_string_pretty(&summary).unwrap()).unwrap();
        }
        println!("LIVE compare: {} explorer transactions up to {upto}, {} wallet rows ({after} after), {} difference(s), {} the explorer lacks; confirmed {} vs the explorer's {}",
            listed.len(), rows.len(), diffs.len(), extra.len(), balance["confirmed"], ex["balance"]["confirmed"]);
        for d in diffs.iter().take(30) {
            println!("LIVE diff: {d}");
        }
        for e in extra.iter().take(30) {
            println!("LIVE extra: {e}");
        }
        assert!(diffs.is_empty(), "{} difference(s) from the explorer", diffs.len());
    }
    engine.shutdown();
}

/// Kyoto as the authority with an Electrum server enabled for history: pending payments come
/// from the server, its anchors checked against Kyoto's headers. Run alone, after the main test.
#[test]
#[ignore]
fn kyoto_with_a_history_server() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    let electrum = std::env::var("REGTEST_ELECTRUM").expect("REGTEST_ELECTRUM");
    let nodes: Vec<String> = chain(&["peers"]).trim().split(',').map(str::to_string).collect();
    configure_regtest(RegtestConfig {
        kyoto: nodes,
        electrum: vec![format!("tcp://{}", electrum.split(',').next().unwrap().trim().trim_start_matches("tcp://"))],
        poll_secs: Some(1),
        kyoto_required: Some(2),
        ..Default::default()
    });
    let (sink, events) = collecting();
    let manager = Arc::new(MockManager::new(Duration::from_millis(100)));
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(root.path().join("wallets"), sink, manager.clone(), None);
    let t = T { engine, rpc, cookie, events, manager };
    t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    t.synced();
    assert_eq!(t.engine.status()["authority"]["kind"], "kyoto");
    let addr = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let paid = t.fund(&addr, 0.07).to_string();
    t.wait("the payment as pending, from the server", 60, || t.row(&paid)["state"] == "pending");
    assert_eq!(t.row(&paid)["reportedBy"], "electrum-0");
    t.mine(1);
    t.synced();
    t.wait("the payment confirmed on Kyoto's chain", 90, || t.row(&paid)["state"] == "confirmed");
    assert_eq!(t.row(&paid)["height"].as_u64(), Some(t.tip()));
    let exposure = t.engine.exposure();
    assert!(exposure["servers"].as_array().unwrap().iter().any(|s| s["source"] == "electrum-0"), "{exposure}");
    println!("KYOTO with a history server: pending from electrum-0, confirmed at {}", t.tip());
    t.engine.shutdown();
}

/// An engine whose Kyoto dials `copies` proxies each in front of the main node and the follower,
/// quorum 2: a peer dropped for a held answer leaves spares to dial. The fork node is left out,
/// as it drops its connections while it builds a branch.
fn kyoto_behind_proxies(copies: usize) -> (T, Vec<Proxy>, tempfile::TempDir) {
    let Some((rpc, cookie)) = common::chain_env() else { panic!("REGTEST_RPC is not set (see tools/regtest/chain.sh)") };
    let nodes: Vec<SocketAddr> = chain(&["peers"]).trim().split(',').map(|s| s.parse().unwrap()).collect();
    let proxies: Vec<Proxy> = [nodes[0], nodes[2]].iter().flat_map(|n| (0..copies).map(|_| Proxy::start("127.0.0.1:0", *n, Mode::Forward))).collect();
    configure_regtest(RegtestConfig { kyoto: proxies.iter().map(|p| p.addr.to_string()).collect(), poll_secs: Some(1), kyoto_required: Some(2), ..Default::default() });
    let (sink, events) = collecting();
    let manager = Arc::new(MockManager::new(Duration::from_millis(100)));
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(root.path().join("wallets"), sink, manager.clone(), None);
    let t = T { engine, rpc, cookie, events, manager };
    t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    t.synced();
    t.wait("the scan from the birthday done", 120, || t.engine.status()["rescanFrom"].is_null());
    t.synced();
    assert_eq!(t.engine.status()["authority"]["kind"], "kyoto");
    (t, proxies, root)
}

fn sum(proxies: &[Proxy], command: &str) -> usize {
    proxies.iter().map(|p| p.count(command)).sum()
}

/// What the engine logs, kept for the test to read.
#[derive(Clone, Default)]
struct Logs(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        std::io::Write::write(&mut std::io::stderr(), b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Logs {
    /// Captures the process's logs, or None when another subscriber took them first.
    fn capture() -> Option<Logs> {
        let logs = Logs::default();
        let w = logs.clone();
        tracing_subscriber::fmt().with_writer(move || w.clone()).with_max_level(tracing::Level::INFO).try_init().ok().map(|_| logs)
    }

    fn count(&self, text: &str) -> usize {
        String::from_utf8_lossy(&self.0.lock().unwrap()).matches(text).count()
    }
}

/// A matched block reorganized away while the proxies hold its fetch: the node drops the request,
/// bdk_kyoto patch 4 skips the block, and the payment comes in its replacement from the same
/// client. Then one replaced before its fetch, fetched from the old branch as bip157 keeps stale
/// headers. Run alone.
#[test]
#[ignore]
fn kyoto_skips_a_matched_block_reorganized_away() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    if common::chain_env().is_none() {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    }
    let (t, proxies, _root) = kyoto_behind_proxies(4);
    let hold = || proxies.iter().for_each(|p| p.set(delay("block", 15_000)));
    let release = || proxies.iter().for_each(|p| p.set(Mode::Forward));
    let restarts = kyoto(&t)["restarts"].clone();

    // The node drops the queued request as the block leaves the chain: RecvError.
    let paid = t.fund(&t.engine.next_address()["address"].as_str().unwrap().to_string(), 0.11).to_string();
    hold();
    let asked = sum(&proxies, "block");
    t.mine(1);
    let h = t.tip();
    let old = t.rpc("getblockhash", json!([h]));
    t.wait("the matched block's fetch held at a proxy", 60, || sum(&proxies, "block") > asked);
    chain(&["reorg", "1"]);
    let new = t.rpc("getblockhash", json!([h]));
    assert_ne!(old, new);
    t.wait("Kyoto on the new branch", 30, || kyoto(&t)["headers"].as_u64() > Some(h));
    release();
    t.synced();
    t.wait("the payment in the block that replaced its first", 90, || {
        let r = t.row(&paid);
        r["state"] == "confirmed" && r["blockHash"] == new
    });
    assert_eq!(kyoto(&t)["restarts"], restarts, "the same client throughout: {}", kyoto(&t));
    println!("KYOTO skipped {old} at {h}, reorganized away while its fetch was held; the payment came in {new}");

    // Replaced before its fetch: the node still knows the block, and fetches it from the old branch.
    let first = t.fund(&t.engine.next_address()["address"].as_str().unwrap().to_string(), 0.12).to_string();
    hold();
    let asked = sum(&proxies, "block");
    t.mine(1);
    let h1 = t.tip();
    let kept = t.rpc("getblockhash", json!([h1]));
    t.wait("the first block's fetch held at a proxy", 60, || sum(&proxies, "block") > asked);
    let second = t.fund(&t.engine.next_address()["address"].as_str().unwrap().to_string(), 0.13).to_string();
    let filters = sum(&proxies, "cfilter");
    t.mine(1);
    let h2 = t.tip();
    let old = t.rpc("getblockhash", json!([h2]));
    t.wait("the second block's filter at Kyoto", 30, || sum(&proxies, "cfilter") > filters);
    std::thread::sleep(Duration::from_secs(1));
    chain(&["reorg", "1"]);
    let new = t.rpc("getblockhash", json!([h2]));
    assert_ne!(old, new);
    t.wait("Kyoto on the new branch", 30, || kyoto(&t)["headers"].as_u64() > Some(h2));
    release();
    t.synced();
    t.wait("both payments", 90, || {
        let (a, b) = (t.row(&first), t.row(&second));
        a["state"] == "confirmed" && b["state"] == "confirmed" && b["blockHash"] == new
    });
    assert_eq!(t.row(&first)["blockHash"], kept);
    assert_eq!(kyoto(&t)["restarts"], restarts, "the same client throughout: {}", kyoto(&t));
    println!("KYOTO {old} at {h2}, matched while {kept} was held, replaced before its fetch; the payment came in {new}");
    t.engine.shutdown();
}

/// The update stream ends while the node runs on (a test hook ends it after an update): the core
/// reports it in `lastStop` and the log, and a new client takes over, from the wallet's chain,
/// with no reopen. A close afterwards stops everything within seconds and starts nothing. Run alone.
#[test]
#[ignore]
fn kyoto_restarts_a_client_whose_updates_ended() {
    let logs = Logs::capture();
    if common::chain_env().is_none() {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    }
    let (t, proxies, _root) = kyoto_behind_proxies(1);
    let restarts = kyoto(&t)["restarts"].as_u64().unwrap();

    END_KYOTO_UPDATES.store(true, Ordering::SeqCst);
    t.mine(1);
    t.wait("the end reported and a new client", 60, || {
        let k = kyoto(&t);
        k["restarts"].as_u64().unwrap() > restarts && k["running"] == true
    });
    let k = kyoto(&t);
    assert_eq!((k["restarts"].as_u64(), k["lastStop"].as_str()), (Some(restarts + 1), Some("updates ended: ended by a test hook")), "{k}");
    if let Some(l) = &logs {
        assert_eq!(l.count("the updates ended while the node ran"), 1);
    }

    // Updates again, with no reopen.
    let paid = t.fund(&t.engine.next_address()["address"].as_str().unwrap().to_string(), 0.14).to_string();
    t.mine(1);
    t.synced();
    t.wait("the payment through the new client", 90, || t.row(&paid)["state"] == "confirmed");
    assert_eq!(kyoto(&t)["restarts"].as_u64(), Some(restarts + 1), "{}", kyoto(&t));
    println!("KYOTO updates ended; restarted once, and the payment came through the new client");

    // A close is no end of the updates: everything stops, and no client dials again.
    let dials = sum(&proxies, "version");
    let t0 = Instant::now();
    t.job("close_wallet", json!({}));
    t.wait("the sync thread to end", 10, || SYNC_THREADS.load(Ordering::SeqCst) == 0);
    let stopped = t0.elapsed();
    assert!(stopped < Duration::from_secs(3), "the sync ran on {stopped:?} after close");
    std::thread::sleep(Duration::from_secs(10));
    assert_eq!(sum(&proxies, "version"), dials, "a client dialled after the close");
    if let Some(l) = &logs {
        assert_eq!(l.count("the updates ended while the node ran"), 1, "the close read as an end of the updates");
    }
    println!("KYOTO closed in {} ms; nothing dialled in the 10 s after", stopped.as_millis());
    t.engine.shutdown();
}
