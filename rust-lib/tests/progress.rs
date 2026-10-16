//! A first sync of a long header chain from a slow server shows its progress in status and in
//! walletStateChanged: the height reached and the server's tip, the server counted as answering
//! and agreeing. Then what new blocks and a reorg cost in headers. The run command is in the
//! README.

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::network::{configure_regtest, RegtestConfig};
use common::{collecting, electrum_proxy, MockManager, T};
use serde_json::{json, Value};

/// The address of the generator point's key: no wallet of the chain's holds it.
const ELSEWHERE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

#[test]
#[ignore]
fn a_long_header_download_shows_its_progress() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    let server: SocketAddr = std::env::var("REGTEST_ELECTRUM").expect("REGTEST_ELECTRUM").split(',').next().unwrap().trim().trim_start_matches("tcp://").parse().unwrap();
    // Each answer of more than one header takes 1.5 s, as 320 kB do over a slow link.
    let slow: Arc<Mutex<Option<Duration>>> = Arc::new(Mutex::new(Some(Duration::from_millis(1_500))));
    // Header answers by method: calls, headers and bytes sent on to the wallet.
    let fetched: Arc<Mutex<BTreeMap<String, (u64, u64, u64)>>> = Arc::default();
    let (s, f) = (slow.clone(), fetched.clone());
    let proxy = electrum_proxy(
        server,
        Arc::new(move |m, p, v| {
            if let (Some(d), "blockchain.block.headers") = (*s.lock().unwrap(), m) {
                if p[1].as_u64().is_some_and(|n| n > 1) {
                    std::thread::sleep(d);
                }
            }
            let n = match m {
                "blockchain.block.headers" => v["result"]["count"].as_u64().unwrap_or(0),
                "blockchain.block.header" => u64::from(v["result"].is_string()),
                _ => return Some(v),
            };
            let mut f = f.lock().unwrap();
            let e = f.entry(m.to_string()).or_default();
            (e.0, e.1, e.2) = (e.0 + 1, e.1 + n, e.2 + v.to_string().len() as u64 + 1);
            Some(v)
        }),
    );
    configure_regtest(RegtestConfig { electrum: vec![format!("tcp://{proxy}")], poll_secs: Some(1), ..Default::default() });
    let (sink, events) = collecting();
    let manager = Arc::new(MockManager::new(Duration::from_millis(200)));
    let root = tempfile::tempdir().unwrap();
    let t = T { engine: Engine::new(root.path().join("wallets"), sink, manager.clone(), None), rpc, cookie, events, manager };
    // 8,000 blocks, four answers of up to 2,016 headers, paid outside the miner's wallet.
    while t.tip() < 8_000 {
        t.rpc("generatetoaddress", json!([1_000, ELSEWHERE]));
    }
    let tip = t.tip();

    let started = Instant::now();
    t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    let mut seen: Vec<Value> = vec![];
    while !(t.engine.status()["synced"] == true && t.engine.status()["authority"]["height"].as_u64() == Some(tip)) {
        assert!(started.elapsed() < Duration::from_secs(120), "no sync: {}", t.engine.status());
        let a = t.engine.status()["authority"].clone();
        if a["headers"].is_object() && seen.last() != Some(&a) {
            seen.push(a);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("synced {tip} headers in {} ms; progress seen: {}", started.elapsed().as_millis(),
             seen.iter().map(|a| format!("{}/{}", a["headers"]["have"], a["headers"]["target"])).collect::<Vec<_>>().join(", "));
    let haves: Vec<u64> = seen.iter().map(|a| a["headers"]["have"].as_u64().unwrap()).collect();
    assert!(haves.len() >= 3 && haves.windows(2).all(|w| w[0] < w[1]), "progress chunk by chunk: {haves:?}");
    for a in &seen {
        // Taken as it comes: the height is the progress, the source has answered and agrees.
        assert_eq!(a["headers"]["target"].as_u64(), Some(tip), "{a}");
        assert!(a["headers"]["have"].as_u64() < Some(tip) && a["height"] == a["headers"]["have"], "{a}");
        assert!(a["asked"] == true && a["peers"].as_u64() >= Some(1), "{a}");
    }
    assert!(t.engine.status()["authority"]["headers"].is_null(), "nothing left to read at the tip");
    let evented: Vec<u64> = t.events.lock().unwrap().iter()
        .filter(|(n, v)| n == "walletStateChanged" && v["authority"]["headers"].is_object())
        .map(|(_, v)| v["authority"]["headers"]["have"].as_u64().unwrap())
        .collect();
    assert!(evented.len() >= 3, "the app hears of each step: {evented:?}");

    // A reopen with the chain stored reads no headers: nothing to show.
    let group = t.engine.status()["group"].as_str().unwrap().to_string();
    t.job("close_wallet", json!({}));
    t.job("open_wallet", json!({"network": "regtest", "group": group}));
    t.synced();
    t.events.lock().unwrap().clear();
    t.rpc("generatetoaddress", json!([3, ELSEWHERE]));
    t.synced();
    assert!(t.events.lock().unwrap().iter().all(|(_, v)| v["authority"]["headers"].is_null()), "three new blocks are no download");
    *slow.lock().unwrap() = None;

    // What new blocks cost in headers, a few rounds at each tip: one comes with the tip, a few
    // are read from above ours, and a reorg searches a few below it, not 2,016.
    let best = || t.rpc("getbestblockhash", json!([])).as_str().unwrap().to_string();
    let cost = |what: &str, f: &dyn Fn()| -> BTreeMap<String, (u64, u64, u64)> {
        fetched.lock().unwrap().clear();
        f();
        let want = best();
        t.wait(what, 60, || t.engine.status()["authority"]["hash"] == want.as_str());
        t.synced();
        std::thread::sleep(Duration::from_secs(3));
        let got = fetched.lock().unwrap().clone();
        println!("{what}: {}", got.iter().map(|(m, (c, n, b))| format!("{m} {c} call(s) {n} header(s) {b} bytes")).collect::<Vec<_>>().join(", "));
        got
    };
    let headers = |c: &BTreeMap<String, (u64, u64, u64)>| c.get("blockchain.block.headers").map_or(0, |e| e.1);
    let mut costs = vec![];
    for _ in 0..3 {
        costs.push(cost("a new block", &|| { t.rpc("generatetoaddress", json!([1, ELSEWHERE])); }));
    }
    costs.push(cost("three new blocks", &|| { t.rpc("generatetoaddress", json!([3, ELSEWHERE])); }));
    let replaced = t.tip();
    let reorg = cost("a reorg of the tip", &|| { common::chain(&["reorg", "1"]); });
    assert_eq!(t.engine.status()["authority"]["height"].as_u64(), Some(replaced + 1));
    assert!(costs[..3].iter().all(|c| headers(c) == 0) && headers(&costs[3]) <= 3, "{costs:?}");
    assert!(headers(&reorg) <= 18, "{reorg:?}");
    t.engine.shutdown();
}
