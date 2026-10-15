//! Closing a wallet during a long header download over a slow server: the sync stops within
//! seconds, and a reopen finishes from what was stored. The run command is in the README.
#![cfg(feature = "test-hooks")]

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin_wallet_core::engine::{hooks::SYNC_THREADS, Engine};
use bitcoin_wallet_core::network::{configure_regtest, RegtestConfig};
use common::{collecting, electrum_proxy, MockManager, T};
use serde_json::json;

/// The address of the generator point's key: no wallet of the chain's holds it.
const ELSEWHERE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// Holds `blockchain.block.headers` answers from `from` up for `hold`, as a slow link would.
#[derive(Default)]
struct Slow {
    hold: Mutex<Option<(u64, Duration)>>,
    held: AtomicUsize,
    in_flight: AtomicUsize,
}

#[test]
#[ignore]
fn closing_stops_a_slow_header_download_within_seconds() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    let server: SocketAddr = std::env::var("REGTEST_ELECTRUM").expect("REGTEST_ELECTRUM").split(',').next().unwrap().trim().trim_start_matches("tcp://").parse().unwrap();
    let slow: Arc<Slow> = Arc::default();
    let s = slow.clone();
    let proxy = electrum_proxy(
        server,
        Arc::new(move |m, p, v| {
            let hold = *s.hold.lock().unwrap();
            if let (Some((from, d)), "blockchain.block.headers") = (hold, m) {
                if p[0].as_u64().is_some_and(|start| start >= from) && p[1].as_u64().is_some_and(|n| n > 1) {
                    s.held.fetch_add(1, Ordering::SeqCst);
                    s.in_flight.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(d);
                    s.in_flight.fetch_sub(1, Ordering::SeqCst);
                }
            }
            Some(v)
        }),
    );
    configure_regtest(RegtestConfig { electrum: vec![format!("tcp://{proxy}")], poll_secs: Some(1), ..Default::default() });
    let (sink, events) = collecting();
    let manager = Arc::new(MockManager::new(Duration::from_millis(200)));
    let root = tempfile::tempdir().unwrap();
    let t = T { engine: Engine::new(root.path().join("wallets"), sink, manager.clone(), None), rpc, cookie, events, manager };
    // Thousands of blocks, the header chain three calls of 2,016; paid to a key outside the
    // miner's wallet, which writes every coinbase it owns.
    while t.tip() < 5_000 {
        t.rpc("generatetoaddress", json!([1_000, ELSEWHERE]));
    }
    let tip = t.tip();

    // The second call hangs, as a 320 kB answer over a slow link does: close while it is in flight.
    *slow.hold.lock().unwrap() = Some((2_017, Duration::from_secs(60)));
    let opened = t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    let group = opened["group"].as_str().unwrap().to_string();
    t.wait("a header call in flight", 60, || slow.in_flight.load(Ordering::SeqCst) > 0);
    std::thread::sleep(Duration::from_millis(500));
    let t0 = Instant::now();
    t.job("close_wallet", json!({}));
    let closed = t0.elapsed();
    t.wait("the sync thread to end", 10, || SYNC_THREADS.load(Ordering::SeqCst) == 0);
    let stopped = t0.elapsed();
    println!("closed in {} ms, the sync ended {} ms after close; the server still held its answer", closed.as_millis(), stopped.as_millis());
    assert!(stopped < Duration::from_secs(3), "the sync ran on {stopped:?} after close");
    assert!(slow.in_flight.load(Ordering::SeqCst) > 0, "the server was still holding the answer");

    // Reopened at once on a fast server: the chain completes, and what was stored holds.
    *slow.hold.lock().unwrap() = None;
    t.job("open_wallet", json!({"network": "regtest", "group": group}));
    t.synced();
    assert_eq!(t.engine.status()["authority"]["height"].as_u64(), Some(tip));

    // Again on the open wallet: new blocks have the next round search for the fork with a long
    // call, which the server holds. Each close ends the sync; each reopen runs one.
    for round in 0..3 {
        *slow.hold.lock().unwrap() = Some((0, Duration::from_secs(60)));
        let before = slow.held.load(Ordering::SeqCst);
        t.rpc("generatetoaddress", json!([2, ELSEWHERE]));
        t.wait("a call held", 60, || slow.held.load(Ordering::SeqCst) > before);
        let t0 = Instant::now();
        t.job("close_wallet", json!({}));
        t.wait("the sync thread to end", 10, || SYNC_THREADS.load(Ordering::SeqCst) == 0);
        assert!(t0.elapsed() < Duration::from_secs(3), "round {round}: {:?}", t0.elapsed());
        *slow.hold.lock().unwrap() = None;
        t.job("open_wallet", json!({"network": "regtest", "group": group}));
        t.synced();
        assert_eq!(SYNC_THREADS.load(Ordering::SeqCst), 1, "round {round}: only the open wallet's sync runs");
    }

    let t0 = Instant::now();
    t.engine.shutdown();
    assert!(t0.elapsed() < Duration::from_secs(2), "shutdown took {:?}", t0.elapsed());
    t.wait("the last sync thread to end", 10, || SYNC_THREADS.load(Ordering::SeqCst) == 0);
}
