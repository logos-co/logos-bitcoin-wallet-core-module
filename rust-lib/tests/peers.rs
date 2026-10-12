//! Kyoto's peers with a stand-in for the node module, on tools/regtest/chain.sh's chain: the core
//! reports how each peer it tried did (two good, one without filters, one refusing, one silent)
//! and the peers they gossiped. A filter-serving node gossips its address book's onion peers
//! (`addpeeraddress`), which the node module keeps on public networks only; its front adds peers
//! on loopback, kept on regtest, and three no network keeps. Needs `--features test-hooks`; the
//! run command is in the README.

mod common;
#[path = "../examples/p2p_proxy.rs"]
#[allow(dead_code)]
mod p2p_proxy;

use std::collections::BTreeSet;
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::kyoto::onion_name;
use bitcoin_wallet_core::network::{configure_regtest, RegtestConfig};
use bitcoin_wallet_core::sync::RouteSource;
use common::{chain, collecting, MockManager, T};
use p2p_proxy::{Gossiped, Mode, Proxy};
use serde_json::{json, Value};

/// The node module as the core sees it: a fixed table, and the reports it gets.
struct Stub {
    table: String,
    reports: Mutex<Vec<(Instant, String, Value)>>,
}

impl RouteSource for Stub {
    fn route_table(&self, _network: &str) -> Result<String, String> {
        Ok(self.table.clone())
    }

    fn report_peers(&self, network: &str, report: &str) {
        let v = serde_json::from_str(report).unwrap_or(Value::Null);
        self.reports.lock().unwrap().push((Instant::now(), network.to_string(), v));
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn list(v: &Value, key: &str) -> Vec<Value> {
    v[key].as_array().cloned().unwrap_or_default()
}

#[test]
#[ignore]
fn the_core_reports_the_peers_it_tried_and_the_peers_they_gossiped() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    let nodes: Vec<SocketAddr> = chain(&["peers"]).trim().split(',').map(|s| s.parse().unwrap()).collect();
    let (main, follower) = (nodes[0], nodes[2]);
    // The follower's address book: onion peers as addpeeraddress adds them, bits 0 and 3 only,
    // each in a netgroup of its own (the first 4 bits) so none collides in the new table.
    let book: Vec<String> = (0..16u8).map(|i| onion_name(&std::array::from_fn(|j| if j == 0 { i << 4 } else { i + 1 }))).collect();
    let added = book.iter().filter(|o| chain(&["peer-rpc", "addpeeraddress", &json!([o, 8333]).to_string()]).contains("\"success\":true")).count();
    assert!(added >= 12, "{added} of 16 onion peers in the follower's book");
    // Its front adds bit 6, which addpeeraddress can't set, and gossips more beside: 601 on
    // loopback, and three that must not be kept.
    let mut extra: Vec<Gossiped> = (0..=600).map(|i| Gossiped { host: "127.0.0.1".into(), port: 20_000 + i, services: 0x49, age: 3600 }).collect();
    let (stale, no_witness) = (onion_name(&[0xaa; 32]), onion_name(&[0xbb; 32]));
    extra.push(Gossiped { host: stale.clone(), port: 8333, services: 0x49, age: 4 * 86_400 });
    extra.push(Gossiped { host: no_witness.clone(), port: 8333, services: 0x41, age: 60 });
    extra.push(Gossiped { host: "203.0.113.7".into(), port: 8333, services: 0x49, age: 60 });
    let good_front = Proxy::start("127.0.0.1:0", main, Mode::Forward);
    let gossip_front = Proxy::start("127.0.0.1:0", follower, Mode::Gossip { services: 0x40, extra });
    let no_filters_front = Proxy::start("127.0.0.1:0", main, Mode::Services { clear: 0x40 });
    let refusing = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    // Connections complete in the backlog, and nothing ever answers.
    let silent_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let [good, gossip, no_filters, refusing, silent] =
        [good_front.addr, gossip_front.addr, no_filters_front.addr, refusing, silent_listener.local_addr().unwrap()].map(|a| a.to_string());
    let kyoto = json!({"id": "kyoto", "kind": "kyoto", "url": "", "operator": "peers", "route": "direct"});
    // The silent peer worked before, so it is dialled first and its timeout always comes: one
    // still dialling when the others are spent is cut off with the start, and not reported.
    let peers: Vec<Value> = [&good, &gossip, &no_filters, &refusing, &silent].iter().map(|p| json!({"peer": p, "source": "list", "ok": *p == &silent})).collect();
    let table = json!({"ok": true, "proxy": null, "chain": [kyoto], "broadcast": [kyoto], "history": [], "pending": [], "fees": [],
        "check": [], "crossCheck": false, "peers": peers});
    let stub = Arc::new(Stub { table: table.to_string(), reports: Mutex::default() });
    // A quorum of four that three peers can't meet: each start dials all five, then stops.
    configure_regtest(RegtestConfig { kyoto_required: Some(4), poll_secs: Some(1), ..Default::default() });
    let (sink, events) = collecting();
    let manager = Arc::new(MockManager::new(Duration::from_millis(300)));
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(root.path().join("wallets"), sink, manager.clone(), Some(stub.clone() as Arc<dyn RouteSource>));
    let t = T { engine, rpc, cookie, events, manager };
    let started = (Instant::now(), unix_now());
    t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    let reports = || stub.reports.lock().unwrap().clone();
    let outcome = |peer: &str| reports().iter().flat_map(|(_, _, v)| list(v, "outcomes")).find(|o| o["peer"] == peer);
    let all = [&good, &gossip, &no_filters, &refusing, &silent];
    t.wait("an outcome for each peer", 60, || all.iter().all(|p| outcome(p).is_some()));
    let first = reports().into_iter().find(|(_, _, v)| !list(v, "outcomes").is_empty()).unwrap().2;
    assert_eq!(list(&first, "outcomes").len(), 5, "one start tried all five: {first}");
    assert_eq!(list(&first, "outcomes")[0]["peer"], silent, "the peer that worked before, first");
    assert_eq!(outcome(&good), Some(json!({"peer": good, "ok": true})));
    assert_eq!(outcome(&gossip), Some(json!({"peer": gossip, "ok": true})));
    assert_eq!(outcome(&no_filters), Some(json!({"peer": no_filters, "ok": false, "reason": "services"})));
    assert_eq!(outcome(&refusing), Some(json!({"peer": refusing, "ok": false, "reason": "refused"})));
    assert_eq!(outcome(&silent), Some(json!({"peer": silent, "ok": false, "reason": "timeout"})));
    println!("PEERS outcomes for all five in {} ms", started.0.elapsed().as_millis());

    // The core skips nobody by itself now: the refusing peer is dialled start after start.
    let refused_in = || reports().iter().filter(|(_, _, v)| list(v, "outcomes").iter().any(|o| o["peer"] == refusing)).count();
    t.wait("four starts that tried the refusing peer", 120, || refused_in() >= 4);
    // Learned peers: 500 at a time, at most once a minute.
    let learned_reports = || reports().into_iter().filter(|(_, _, v)| !list(v, "learned").is_empty()).collect::<Vec<_>>();
    t.wait("a second report of learned peers", 150, || learned_reports().len() >= 2);
    let lr = learned_reports();
    assert_eq!(list(&lr[0].2, "learned").len(), 500, "500 a report");
    assert!(lr[1].0.duration_since(lr[0].0) >= Duration::from_secs(60), "once a minute: {:?}", lr[1].0.duration_since(lr[0].0));
    assert!(reports().iter().all(|(_, n, v)| n == "regtest" && list(v, "learned").len() <= 500));
    let learned: Vec<Value> = lr.iter().flat_map(|(_, _, v)| list(v, "learned")).collect();
    let keys: BTreeSet<(String, u64)> = learned.iter().map(|l| (l["addr"].as_str().unwrap().to_string(), l["port"].as_u64().unwrap())).collect();
    for l in &learned {
        let seen = l["seenAt"].as_u64().unwrap();
        assert_eq!(l["from"], gossip, "credited to the peer that gossiped it: {l}");
        assert_eq!(l["services"].as_u64().unwrap() & 0x49, 0x49, "{l}");
        assert!(seen + 3 * 86_400 >= started.1 && seen <= unix_now() + 600, "{l}");
    }
    let all_loopback: BTreeSet<(String, u64)> = (20_000..=20_600).map(|p| ("127.0.0.1".to_string(), p)).collect();
    assert_eq!(keys, all_loopback, "every loopback peer over two reports, and nothing else");
    // The follower's onions came through Kyoto and were left out: regtest keeps none.
    assert!(gossip_front.count("addrv2") >= 1, "the follower answered getaddr");
    assert!(!keys.iter().any(|(a, _)| book.contains(a) || *a == stale || *a == no_witness || a == "203.0.113.7"));
    let k = t.engine.status()["kyoto"].clone();
    assert!(k["gossiped"].as_u64().unwrap() > k["learned"].as_u64().unwrap() && k["learned"].as_u64().unwrap() >= 601, "{k}");
    println!("PEERS {} learned of {} gossiped in {} ms; {} reports", keys.len(), k["gossiped"], started.0.elapsed().as_millis(), reports().len());
}
