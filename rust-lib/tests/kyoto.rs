//! Kyoto as the chain authority on tools/regtest/chain.sh's chain: three filter-serving Core
//! nodes behind proxies the test steers. Receive, send and confirm; a reorg; a restart after
//! NoReachablePeers; a rebuild past the lookahead; and a peer forging filter headers.
//! Needs `--features test-hooks`; the run command is in the README.

mod common;
#[path = "../examples/p2p_proxy.rs"]
#[allow(dead_code)]
mod p2p_proxy;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    chain(&["reorg", "1"]);
    let new_block = t.rpc("getblockhash", json!([h]));
    assert_ne!(old_block, new_block);
    t.synced();
    t.wait("the payment re-anchored in the new block", 90, || {
        let r = t.row(&reorged);
        r["state"] == "confirmed" && r["height"].as_u64() == Some(h) && r["confirmations"] == 2
    });
    println!("KYOTO reorg at {h}: {old_block} replaced by {new_block}");

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
        let n = left.min(1_000);
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
    println!("KYOTO first sync of {} blocks in {} ms", t.tip(), started.elapsed().as_millis());
    t.engine.shutdown();
}
