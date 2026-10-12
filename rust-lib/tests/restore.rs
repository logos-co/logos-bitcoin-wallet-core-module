//! Restores of a history built first by a Core wallet holding the test phrase's keys, each matched
//! against that wallet: under Kyoto, the node's filters, Electrum, and Esplora (with `ESPLORA`);
//! then Esplora above a checkpoint, linking what lies below it through its headers, else unchecked.
//! Needs `--features test-hooks` and a fresh chain; README, "Regtest", has the run command.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::network::{configure_regtest, RegtestCheckpoint, RegtestConfig};
use bitcoin_wallet_core::routes::Routes;
use common::history::*;
use common::{chain, collecting, MockManager, ModuleRpc, T};
use serde_json::json;

#[test]
#[ignore]
fn restores_match_cores_wallet() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    let manager = Arc::new(MockManager::new(Duration::from_millis(300)));
    let (sink, events) = collecting();
    let root = tempfile::tempdir().unwrap();
    let t = T { engine: Engine::new(root.path().join("wallets"), sink, manager.clone(), None), rpc: rpc.clone(), cookie: cookie.clone(), events, manager };
    let h = build_history(&t, "victim", "wpkh", 84, &PAID);
    let tap = build_history(&t, "victim_tr", "tr", 86, &PAID_TAPROOT);
    let checkpoint = h.mid;
    let at = t.rpc("getblockhash", json!([checkpoint]));
    let header = t.rpc("getblockheader", json!([at, false])).as_str().unwrap().to_string();
    configure_regtest(RegtestConfig { checkpoint: Some(RegtestCheckpoint { height: checkpoint, header }), ..Default::default() });
    let electrum = format!("tcp://{}", std::env::var("REGTEST_ELECTRUM").expect("REGTEST_ELECTRUM").split(',').next().unwrap().trim().trim_start_matches("tcp://"));

    // Kyoto alone: filters, the matched blocks oldest first, and scans again from the birthday
    // until the window holds every used address.
    let started = Instant::now();
    let peers: Vec<String> = chain(&["peers"]).trim().split(',').map(String::from).collect();
    let kyoto = Routes::regtest(&RegtestConfig { kyoto: peers, poll_secs: Some(1), kyoto_required: Some(2), ..Default::default() });
    let (k, _dir) = restore(&t, kyoto.clone(), h.birthday, None);
    matches("kyoto", &k, &h, 0, started);
    assert!(k.engine.status()["kyoto"]["rescans"].as_u64().unwrap() >= 1, "indices past the first window take a scan again");
    k.engine.shutdown();
    // One pass: the spends in the window that funds them are found the first time.
    let started = Instant::now();
    let (k, _dir) = restore_family(&t, kyoto, tap.birthday, None, "bitcoin_taproot");
    matches("kyoto taproot", &k, &tap, checkpoint, started);
    assert_eq!(k.engine.status()["kyoto"]["rescans"], 0, "all in the first window: no scan again");
    k.engine.shutdown();

    // The node's filters, through bitcoind_module's allowlist.
    let started = Instant::now();
    let node = Arc::new(ModuleRpc::new(rpc.clone(), cookie.clone()));
    let (n, _dir) = restore(&t, Routes::regtest(&RegtestConfig { local: true, poll_secs: Some(1), ..Default::default() }), h.birthday, Some(node));
    matches("node", &n, &h, 0, started);
    assert!(n.engine.status()["node"]["rescans"].as_u64().unwrap() >= 1, "{}", n.engine.status()["node"]);
    n.engine.shutdown();

    // Electrum: its header chain and its history.
    let started = Instant::now();
    let (e, _dir) = restore(&t, Routes::regtest(&RegtestConfig { electrum: vec![electrum.clone()], poll_secs: Some(1), ..Default::default() }), h.birthday, None);
    matches("electrum", &e, &h, 0, started);
    e.engine.shutdown();

    if std::env::var("ESPLORA").is_err() {
        println!("RESTORE esplora: skipped, ESPLORA is not set");
        return;
    }
    let esplora_port: u16 = std::env::var("ESPLORA_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3002);
    chain(&["esplora"]);
    let esplora = format!("http://127.0.0.1:{esplora_port}");

    // Esplora alone for history, the chain from Electrum's headers.
    let started = Instant::now();
    let (s, _dir) = restore(&t, esplora_routes(&electrum, &esplora), h.birthday, None);
    matches("esplora", &s, &h, 0, started);
    s.engine.shutdown();

    // A birthday above the checkpoint: the chain starts there, and what Esplora reports below it
    // links to it header by header from Esplora's header endpoint, then shows confirmed.
    let (l, _dir) = restore(&t, esplora_routes(&electrum, &esplora), checkpoint + 1, None);
    above_the_checkpoint(&l, &h, checkpoint, "confirmed");
    assert_eq!(l.alerts("unchecked_anchor", "esplora-0"), 0, "every old anchor linked");
    assert_eq!((l.engine.balance()["unchecked"].as_str(), l.sats("confirmed")), (Some("0"), h.confirmed));
    l.engine.shutdown();

    // Through a front that serves no headers nothing links them: unchecked, at their own height,
    // named by the server that reported them, and an alert says so.
    let front = headerless_front(esplora_port);
    let (u, _dir) = restore(&t, esplora_routes(&electrum, &format!("http://127.0.0.1:{front}")), checkpoint + 1, None);
    above_the_checkpoint(&u, &h, checkpoint, "unchecked");
    assert!(u.alerts("unchecked_anchor", "esplora-0") >= 1, "an alert names the unchecked transactions");
    assert!(u.engine.balance()["unchecked"].as_str().unwrap() != "0");
    // The checkpoint names the block below it, but only that block's header proves a transaction
    // in it: when the chain moves on, that row stays unchecked too.
    t.mine(1);
    above_the_checkpoint(&u, &h, checkpoint, "unchecked");
    u.engine.shutdown();
}

/// Synced on a chain from `checkpoint`: rows below it in state `below`, the rest confirmed, each
/// at its own height.
fn above_the_checkpoint(r: &T, h: &History, checkpoint: u32, below: &str) {
    let tip = r.tip();
    r.wait("synced", 300, || {
        let s = r.engine.status();
        s["synced"] == true && s["authority"]["height"].as_u64() == Some(tip) && rows(r).len() == h.heights.len()
    });
    assert_eq!(r.engine.status()["authority"]["base"], checkpoint);
    let got = rows(r);
    for (txid, height) in &h.heights {
        let row = &got[txid];
        let want = if *height < checkpoint as u64 { below } else { "confirmed" };
        assert_eq!((row["state"].as_str(), row["height"].as_u64()), (Some(want), Some(*height)), "{txid}: {row}");
        if want == "unchecked" {
            assert_eq!(row["reportedBy"], "esplora-0", "the server that reported it: {row}");
        }
    }
    println!("RESTORE esplora above the checkpoint: {} {below} below {checkpoint}", got.values().filter(|r| r["height"].as_u64().is_some_and(|x| x < checkpoint as u64)).count());
}

/// Esplora's HTTP API on loopback, but every `/block/<hash>/header` answered 404: one request a
/// connection, forwarded with `Connection: close`.
fn headerless_front(upstream: u16) -> u16 {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut reader = BufReader::new(client.try_clone().unwrap());
                let (mut head, mut line, mut length) = (String::new(), String::new(), 0usize);
                while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap_or(0);
                    }
                    if !line.to_ascii_lowercase().starts_with("connection:") {
                        head.push_str(&line);
                    }
                    line.clear();
                }
                let mut body = vec![0u8; length];
                if reader.read_exact(&mut body).is_err() {
                    return;
                }
                let mut out = client;
                let path = head.split_whitespace().nth(1).unwrap_or_default();
                if path.starts_with("/block/") && path.ends_with("/header") {
                    let _ = out.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    return;
                }
                let Ok(mut up) = std::net::TcpStream::connect(("127.0.0.1", upstream)) else { return };
                let mut request = head.into_bytes();
                request.extend_from_slice(b"Connection: close\r\n\r\n");
                request.extend_from_slice(&body);
                let mut reply = vec![];
                if up.write_all(&request).is_ok() && up.read_to_end(&mut reply).is_ok() {
                    let _ = out.write_all(&reply);
                }
            });
        }
    });
    port
}
