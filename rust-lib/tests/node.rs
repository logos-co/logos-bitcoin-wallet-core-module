//! The local node as the chain authority, through bitcoind_module's allowlist, on a pruned node
//! (`chain.sh pruned`: -prune=550 -fastprune with a filter index). A restore scans its filters;
//! pruned blocks that match come from its peers, or, with the peers gone, from a history server
//! or Kyoto, and with neither the status says so. Then a reorg and a new birthday.
//! Needs `--features test-hooks`; the run command is in the README.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::network::{configure_regtest, RegtestConfig};
use bitcoin_wallet_core::routes::Routes;
use common::{chain, collecting, MockManager, ModuleRpc, T};
use serde_json::{json, Value};

fn pruned_rpc() -> Arc<ModuleRpc> {
    let dir = std::env::var("CHAIN_DIR").expect("CHAIN_DIR");
    let cookie = std::fs::read_to_string(format!("{dir}/bitcoind-pruned/regtest/.cookie")).expect("the pruned node's cookie: run `chain.sh pruned`");
    let port = std::env::var("PRUNED_RPC_PORT").unwrap_or_else(|_| "18573".into());
    Arc::new(ModuleRpc::new(format!("http://127.0.0.1:{port}/"), cookie))
}

/// The pruned node's own RPC, past the allowlist: the test prunes it and cuts its peers.
fn pruned(method: &str, params: Value) -> Value {
    let v: Value = serde_json::from_str(&chain(&["pruned-rpc", method, &params.to_string()])).unwrap();
    assert!(v["error"].is_null(), "{method}: {v}");
    v["result"].clone()
}

/// An engine for one restore: a fresh wallet directory, these routes, the pruned node as its node.
fn restore(t: &T, routes: RegtestConfig) -> (T, Arc<ModuleRpc>, tempfile::TempDir) {
    let (sink, events) = collecting();
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(root.path().join("wallets"), sink, t.manager.clone(), None);
    engine.set_regtest_routes(Routes::regtest(&routes));
    let rpc = pruned_rpc();
    engine.set_node_source(rpc.clone());
    let r = T { engine, rpc: t.rpc.clone(), cookie: t.cookie.clone(), events, manager: t.manager.clone() };
    r.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    (r, rpc, root)
}

fn node(t: &T) -> Value {
    t.engine.status()["node"].clone()
}

fn local() -> RegtestConfig {
    RegtestConfig { local: true, poll_secs: Some(1), ..Default::default() }
}

#[test]
#[ignore]
fn restore_from_a_pruned_node() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    configure_regtest(RegtestConfig::default());
    chain(&["pruned"]);
    let manager = Arc::new(MockManager::new(Duration::from_millis(300)));
    let (sink, events) = collecting();
    let root = tempfile::tempdir().unwrap();
    let t = T { engine: Engine::new(root.path().join("wallets"), sink, manager.clone(), None), rpc, cookie, events, manager };
    t.engine.set_regtest_routes(Routes::regtest(&local()));
    t.engine.set_node_source(pruned_rpc());

    // The wallet, with the node as its authority: two payments and a send, in three blocks.
    t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    t.synced();
    assert_eq!(t.engine.status()["authority"]["kind"], "local_node");
    assert_eq!(t.engine.history(0)["total"], 0, "start from a fresh `chain.sh prepare`");
    let mut ids = vec![];
    for btc in [0.5, 0.25] {
        let addr = t.engine.next_address()["address"].as_str().unwrap().to_string();
        ids.push(t.fund(&addr, btc).to_string());
        t.mine(1);
        t.synced();
    }
    let theirs = t.wallet_rpc("getnewaddress", json!(["payee"])).as_str().unwrap().to_string();
    let p = t.job("build_send", json!({"recipients": [{"address": theirs, "amountSat": "10000000"}], "feeRate": 2.0}));
    let sent = t.sign(p["previewId"].as_str().unwrap());
    assert_eq!((sent["via"].as_str(), sent["broadcast"].as_str()), (Some("local"), Some("seen")), "{sent}");
    ids.push(sent["txid"].as_str().unwrap().to_string());
    // Sent through the pruned node: the miner has it once the node relayed it.
    t.wait("the send relayed to the miner", 30, || t.in_mempool(&ids[2]));
    t.mine(1);
    t.synced();
    let t0 = Instant::now();
    while !ids.iter().all(|id| t.row(id)["state"] == "confirmed") {
        let rows: Vec<Value> = ids.iter().map(|id| t.row(id)).collect();
        assert!(t0.elapsed() < Duration::from_secs(60), "all three confirmed: {rows:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
    let heights: Vec<u64> = ids.iter().map(|id| t.row(id)["height"].as_u64().unwrap()).collect();
    let balance = t.sats("confirmed");
    t.engine.shutdown();

    // A block over the 64 KiB block file of -fastprune closes the file the wallet's blocks are in;
    // 288 blocks later the node may prune it.
    let raw = t.wallet_rpc("createrawtransaction", json!([[], [{"data": "00".repeat(70_000)}]]));
    let funded = t.wallet_rpc("fundrawtransaction", json!([raw]))["hex"].clone();
    let signed = t.wallet_rpc("signrawtransactionwithwallet", json!([funded]))["hex"].clone();
    t.rpc("sendrawtransaction", json!([signed, 0]));
    t.mine(1);
    for _ in 0..6 {
        t.mine(50);
    }
    let below: u64 = chain(&["prune", &(heights[2] + 2).to_string()]).trim().parse().unwrap();
    assert!(below > heights[2], "the wallet's blocks pruned: the node keeps blocks from {below} up");
    let hash = t.rpc("getblockhash", json!([heights[0]]));
    let gone = chain(&["pruned-rpc", "getblock", &json!([hash, 0]).to_string()]);
    assert!(gone.contains("pruned"), "{gone}");
    println!("NODE wallet blocks {heights:?}, pruned below {below}, tip {}", t.tip());

    // With the node's peers gone and nothing else to ask, the status names the gap.
    pruned("setnetworkactive", json!([false]));
    t.wait("the node without peers", 30, || pruned("getconnectioncount", json!([])) == 0);
    {
        let (r, _rpc, _dir) = restore(&t, local());
        t.wait("the node's scan to the tip", 120, || node(&r)["prunedGap"]["heights"].as_array().is_some_and(|h| h.len() == 3) && r.engine.status()["synced"] == true);
        let gap = node(&r)["prunedGap"].clone();
        assert_eq!((gap["via"].clone(), gap["resolved"].clone()), (Value::Null, json!(false)), "{gap}");
        assert_eq!(gap["heights"], json!(heights), "{gap}");
        assert_eq!(r.sats("confirmed"), 0, "the pruned blocks hold every payment");
        r.engine.shutdown();
    }

    // A history server enabled: its full scan covers the gap.
    let electrum = std::env::var("REGTEST_ELECTRUM").expect("REGTEST_ELECTRUM").split(',').next().unwrap().trim().trim_start_matches("tcp://").to_string();
    {
        let (r, _rpc, _dir) = restore(&t, RegtestConfig { electrum: vec![format!("tcp://{electrum}")], ..local() });
        t.wait("the gap covered by the server", 120, || node(&r)["prunedGap"]["resolved"] == true && r.sats("confirmed") == balance);
        let gap = node(&r)["prunedGap"].clone();
        assert_eq!((gap["via"].as_str(), gap["heights"].clone()), (Some("electrum-0"), json!(heights)), "{gap}");
        assert_eq!(r.engine.status()["authority"]["kind"], "local_node");
        r.engine.shutdown();
    }

    // Kyoto enabled instead: it holds the chain while it scans the gap, then hands it back.
    let peers: Vec<String> = chain(&["peers"]).trim().split(',').map(str::to_string).collect();
    {
        let (r, _rpc, _dir) = restore(&t, RegtestConfig { kyoto: peers.clone(), kyoto_required: Some(2), ..local() });
        t.wait("Kyoto on the gap", 120, || node(&r)["prunedGap"]["via"] == "kyoto");
        t.wait("the gap covered by Kyoto", 180, || {
            let st = r.engine.status();
            st["node"]["prunedGap"]["resolved"] == true && st["authority"]["kind"] == "local_node" && r.sats("confirmed") == balance
        });
        assert!(r.events.lock().unwrap().iter().any(|(n, v)| n == "walletStateChanged" && v["authority"]["kind"] == "kyoto"), "Kyoto held the chain meanwhile");
        r.engine.shutdown();
    }

    // The node's peers back: the matched blocks come from them, and only those are read.
    pruned("setnetworkactive", json!([true]));
    t.wait("the node's peer back", 60, || pruned("getconnectioncount", json!([])).as_u64().unwrap_or(0) > 0);
    let (r, rpc_b, _dir) = restore(&t, local());
    let started = Instant::now();
    t.wait("the restore from the pruned node", 180, || r.sats("confirmed") == balance && r.engine.status()["synced"] == true);
    let n = node(&r);
    println!("NODE restore in {} ms: {} filters, {} blocks read, {} matched, {} from peers", started.elapsed().as_millis(),
        rpc_b.count("getblockfilter"), rpc_b.count("getblock"), n["matched"], n["fromPeers"]);
    assert_eq!((n["filters"].clone(), n["pruned"].clone(), n["prunedGap"].clone()), (json!(true), json!(true), Value::Null), "{n}");
    assert!(n["fromPeers"].as_u64().unwrap() >= 3 && rpc_b.count("getblockfrompeer") >= 3, "{n}");
    assert!(rpc_b.count("getblockfilter") as u64 >= t.tip() - 10, "the backlog went by filters");
    assert!(rpc_b.count("getblock") < 60, "only matched blocks were read: {}", rpc_b.count("getblock"));
    for id in &ids {
        assert_eq!(r.row(id)["state"], "confirmed", "{id}");
    }

    // A reorg under a payment, followed through the node.
    let addr = r.engine.next_address()["address"].as_str().unwrap().to_string();
    let reorged = r.fund(&addr, 0.2).to_string();
    r.mine(1);
    r.synced();
    r.wait("the payment confirmed", 60, || r.row(&reorged)["state"] == "confirmed");
    let h = r.tip();
    let old_block = r.rpc("getblockhash", json!([h]));
    assert_eq!(r.row(&reorged)["blockHash"], old_block);
    chain(&["reorg", "1"]);
    let new_block = r.rpc("getblockhash", json!([h]));
    assert_ne!(old_block, new_block);
    r.synced();
    r.wait("the payment re-anchored in the new block", 90, || r.row(&reorged)["blockHash"] == new_block && r.row(&reorged)["state"] == "confirmed");
    let lr = r.engine.status()["lastReorg"].clone();
    assert_eq!((lr["height"].as_u64(), lr["depth"].as_u64()), (Some(h), Some(1)), "{lr}");
    assert!(lr["moved"].as_array().unwrap().contains(&json!(reorged)), "{lr}");
    r.wait("walletStateChanged with the reorg", 10, || r.events.lock().unwrap().iter().any(|(n, v)| n == "walletStateChanged" && v["lastReorg"] == lr));
    println!("NODE reorg at {h}: {old_block} replaced by {new_block}");

    // A birthday: the node's filters are scanned again from it.
    let before = rpc_b.count("getblockfilter");
    let set = r.job("set_birthday", json!({"height": heights[0]}));
    r.wait("the rescan", 120, || r.engine.status()["rescanFrom"].is_null());
    r.synced();
    assert!(r.events.lock().unwrap().iter().any(|(n, v)| n == "walletStateChanged" && v["rescanFrom"] == set["rescanFrom"]));
    assert!(rpc_b.count("getblockfilter") > before, "the filters were read again");
    assert_eq!(r.sats("confirmed"), balance + 20_000_000);
    r.engine.shutdown();
}
