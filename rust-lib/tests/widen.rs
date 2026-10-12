//! Kyoto widening a scan in place, against the way before: a new client from the birthday. The
//! same history is restored twice through counting proxies, 3,000 empty blocks past the birthday,
//! and each widening pass's time and traffic is compared. README, "Regtest".
//! Needs `--features test-hooks` and a fresh chain; the run command is in the README.

mod common;
#[path = "../examples/p2p_proxy.rs"]
#[allow(dead_code)]
mod p2p_proxy;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::network::{configure_regtest, RegtestConfig};
use bitcoin_wallet_core::routes::Routes;
use common::history::*;
use common::{chain, collecting, MockManager, T};
use p2p_proxy::{Mode, Proxy};
use serde_json::json;

const EMPTY_BLOCKS: u32 = 3_000;

type Traffic = HashMap<String, (usize, usize)>;

/// One pass of a scan: how long it took, and the messages and bytes Kyoto received meanwhile.
struct Pass {
    seconds: f64,
    traffic: Traffic,
}

impl Pass {
    fn of(&self, command: &str) -> (usize, usize) {
        self.traffic.get(command).copied().unwrap_or((0, 0))
    }

    fn bytes(&self) -> usize {
        self.traffic.values().map(|(_, b)| b).sum()
    }
}

fn traffic(proxies: &[Proxy]) -> Traffic {
    let mut out = Traffic::new();
    for p in proxies {
        for (c, (n, b)) in p.traffic() {
            let e = out.entry(c).or_insert((0, 0));
            (e.0, e.1) = (e.0 + n, e.1 + b);
        }
    }
    out
}

fn since(before: &Traffic, now: &Traffic) -> Traffic {
    now.iter().map(|(c, (n, b))| {
        let (n0, b0) = before.get(c).copied().unwrap_or((0, 0));
        (c.clone(), (n - n0, b - b0))
    }).collect()
}

/// Empty blocks to a script no wallet holds, in batches the RPC timeout allows.
fn mine_empty(t: &T, n: u32) {
    let checksum = t.rpc("getdescriptorinfo", json!(["raw(51)"]))["checksum"].as_str().unwrap().to_string();
    let mut left = n;
    while left > 0 {
        let k = left.min(500);
        t.rpc("generatetodescriptor", json!([k, format!("raw(51)#{checksum}")]));
        left -= k;
    }
}

/// Restores the history through the proxies and cuts the scan into passes where the engine
/// widens it: there Kyoto is idle at the tip, so each pass's traffic is its own.
fn passes(t: &T, routes: Routes, birthday: u32, by_restart: bool, proxies: &Arc<Vec<Proxy>>, h: &History) -> Vec<Pass> {
    let started = Instant::now();
    let marks: Arc<Mutex<Vec<(Instant, Traffic)>>> = Arc::default();
    let (m, ps) = (marks.clone(), proxies.clone());
    let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || m.lock().unwrap().push((Instant::now(), traffic(&ps))));
    let first = (Instant::now(), traffic(proxies));
    let (r, _dir) = restore_with(t, routes, birthday, None, "bitcoin", by_restart, Some(hook));
    let tip = r.tip();
    r.wait("the restore", 900, || {
        let s = r.engine.status();
        s["synced"] == true && s["authority"]["height"].as_u64() == Some(tip) && s["rescanFrom"].is_null()
    });
    let last = (Instant::now(), traffic(proxies));
    matches(if by_restart { "kyoto by a new client" } else { "kyoto in place" }, &r, h, 0, started);
    r.engine.shutdown();
    let mut bounds = vec![first];
    bounds.extend(marks.lock().unwrap().drain(..));
    bounds.push(last);
    bounds.windows(2).map(|w| Pass { seconds: (w[1].0 - w[0].0).as_secs_f64(), traffic: since(&w[0].1, &w[1].1) }).collect()
}

fn report(name: &str, passes: &[Pass]) {
    for (i, p) in passes.iter().enumerate() {
        let [h, cfh, cf, b] = ["headers", "cfheaders", "cfilter", "block"].map(|c| p.of(c));
        println!("WIDEN {name}, pass {}: {:.2} s, {} B: headers {} ({} B), cfheaders {} ({} B), cfilter {} ({} B), block {} ({} B)",
            i + 1, p.seconds, p.bytes(), h.0, h.1, cfh.0, cfh.1, cf.0, cf.1, b.0, b.1);
    }
}

#[test]
#[ignore]
fn kyoto_widens_its_scan_in_place() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    configure_regtest(RegtestConfig::default());
    let manager = Arc::new(MockManager::new(Duration::from_millis(300)));
    let (sink, events) = collecting();
    let root = tempfile::tempdir().unwrap();
    let t = T { engine: Engine::new(root.path().join("wallets"), sink, manager.clone(), None), rpc, cookie, events, manager };
    let birthday = t.tip() as u32 + 1;
    mine_empty(&t, EMPTY_BLOCKS);
    let h = build_history(&t, "victim", "wpkh", 84, &PAID);
    let nodes: Vec<SocketAddr> = chain(&["peers"]).trim().split(',').map(|s| s.parse().unwrap()).collect();
    let proxies: Arc<Vec<Proxy>> = Arc::new(nodes.iter().map(|n| Proxy::start("127.0.0.1:0", *n, Mode::Forward)).collect());
    let routes = Routes::regtest(&RegtestConfig { kyoto: proxies.iter().map(|p| p.addr.to_string()).collect(), poll_secs: Some(1), kyoto_required: Some(2), ..Default::default() });
    let old = passes(&t, routes.clone(), birthday, true, &proxies, &h);
    let new = passes(&t, routes, birthday, false, &proxies, &h);
    report("by a new client", &old);
    report("in place", &new);
    assert_eq!(old.len(), new.len(), "the same passes either way");
    assert!(new.len() >= 2, "the history takes a wider scan");
    for (o, n) in old.iter().zip(&new).skip(1) {
        assert!(o.of("headers").1 >= EMPTY_BLOCKS as usize * 80, "a new client downloads the headers again");
        assert_eq!(n.of("cfheaders"), (0, 0), "the agreed filter headers stay");
        assert!(n.of("headers").1 < o.of("headers").1 / 100, "in place, no headers again");
        assert!(n.of("cfilter").0 >= EMPTY_BLOCKS as usize, "the filters are checked again");
    }
    let widened = |ps: &[Pass]| ps[1..].iter().map(Pass::bytes).sum::<usize>();
    println!("WIDEN widening passes: {} B by a new client, {} B in place", widened(&old), widened(&new));
}
