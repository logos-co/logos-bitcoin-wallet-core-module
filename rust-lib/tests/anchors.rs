//! A server's confirmation counts once proved against the chain's headers: a real block's hash for
//! a transaction not in it never confirms, above the chain's tip or below its start, from a lying
//! Esplora front or Electrum proxy; honest payments confirm. Needs `--features test-hooks`, a fresh
//! chain and `ESPLORA`; README, "Regtest", has the command.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::Transaction;
use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::network::{configure_regtest, RegtestCheckpoint, RegtestConfig};
use bitcoin_wallet_core::routes::Routes;
use common::history::{restore, TPRV};
use common::{chain, collecting, electrum_proxy, http_front, MockManager, T};
use serde_json::{json, Value};

/// A confirmation a server makes up: `txid` in a block it isn't in.
#[derive(Clone)]
struct Lie {
    txid: String,
    height: u64,
    hash: String,
    time: u64,
}

/// The chain from `chain`'s headers only; history, pending payments, fees and broadcast from
/// `history`, an Esplora URL or a second Electrum server.
fn routes(chain: &str, history: &str) -> Routes {
    let esplora = history.starts_with("http");
    let (electrum, esploras) = if esplora { (vec![chain.into()], vec![history.into()]) } else { (vec![chain.into(), history.into()], vec![]) };
    let mut r = Routes::regtest(&RegtestConfig { electrum, esplora: esploras, poll_secs: Some(1), ..Default::default() });
    let id = if esplora { "esplora-0" } else { "electrum-1" };
    let (c, h) = (r.chain[0].clone(), r.history.iter().find(|s| s.id == id).cloned().unwrap());
    (r.chain, r.history, r.pending, r.fees, r.broadcast) = (vec![c], vec![h.clone()], vec![h.clone()], vec![h.clone()], vec![h]);
    (r.check, r.cross_check) = (vec![], false);
    r
}

/// The phrase's native segwit receive address at `i`.
fn address(t: &T, i: u32) -> String {
    let d = format!("wpkh({TPRV}/84h/1h/0h/0/*)");
    let checksum = t.rpc("getdescriptorinfo", json!([d]))["checksum"].as_str().unwrap().to_string();
    t.rpc("deriveaddresses", json!([format!("{d}#{checksum}"), [i, i]]))[0].as_str().unwrap().to_string()
}

/// A payment from Core's wallet to `to`, signed but not sent: its txid and bytes.
fn payment(t: &T, to: &str, btc: f64) -> (String, String) {
    let raw = t.wallet_rpc("createrawtransaction", json!([[], {to: btc}]));
    let funded = t.wallet_rpc("fundrawtransaction", json!([raw]))["hex"].clone();
    let signed = t.wallet_rpc("signrawtransactionwithwallet", json!([funded]))["hex"].as_str().unwrap().to_string();
    let tx: Transaction = deserialize_hex(&signed).unwrap();
    (tx.compute_txid().to_string(), signed)
}

/// A block with nothing from the mempool in it: its height, hash and time.
fn empty_block(t: &T) -> (u64, String, u64) {
    let to = t.wallet_rpc("getnewaddress", json!(["empty"]));
    let hash = t.rpc("generateblock", json!([to, []]))["hash"].as_str().unwrap().to_string();
    let header = t.rpc("getblockheader", json!([hash]));
    (header["height"].as_u64().unwrap(), hash, header["time"].as_u64().unwrap())
}

/// Where Core's wallet confirmed a payment it made.
fn height_of(t: &T, txid: &str) -> u64 {
    t.wallet_rpc("gettransaction", json!([txid]))["blockheight"].as_u64().unwrap()
}

/// Waits for `what`, failing the moment `txid` shows confirmed.
fn never_confirmed(r: &T, txid: &str, what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    r.wait(what, secs, || {
        assert_ne!(r.row(txid)["state"], "confirmed", "{txid} confirmed on a lie: {}", r.row(txid));
        f()
    });
}

/// A few more syncs, `txid` never confirmed.
fn still_not_confirmed(r: &T, txid: &str) {
    let until = Instant::now() + Duration::from_secs(5);
    never_confirmed(r, txid, "more syncs", 10, || Instant::now() >= until);
}

fn suspect(r: &T, id: &str) -> bool {
    r.engine.sources_status()["sources"].as_array().unwrap().iter().any(|s| s["id"] == id && s["suspect"] == true)
}

/// Gives `txid` the lie's status wherever an Esplora answer lists it.
fn restate(v: &mut Value, txid: &str, status: &Value) -> bool {
    match v {
        Value::Array(a) => {
            let mut hit = false;
            for x in a {
                hit |= restate(x, txid, status);
            }
            hit
        }
        Value::Object(o) if o.get("txid").and_then(Value::as_str) == Some(txid) && o.contains_key("status") => {
            o.insert("status".into(), status.clone());
            true
        }
        _ => false,
    }
}

#[test]
#[ignore]
fn confirmations_count_once_proved() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    if std::env::var("ESPLORA").is_err() {
        eprintln!("skipped: ESPLORA is not set");
        return;
    }
    let esplora_port: u16 = std::env::var("ESPLORA_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3002);
    chain(&["esplora"]);
    let electrs: SocketAddr = std::env::var("REGTEST_ELECTRUM").expect("REGTEST_ELECTRUM").split(',').next().unwrap().trim().trim_start_matches("tcp://").parse().unwrap();
    let manager = Arc::new(MockManager::new(Duration::from_millis(300)));
    let (sink, events) = collecting();
    let root = tempfile::tempdir().unwrap();
    let t = T { engine: Engine::new(root.path().join("wallets"), sink, manager.clone(), None), rpc, cookie, events, manager };
    let started = Instant::now();

    // Below the checkpoint, built first, as regtest takes its checkpoint once a process: two
    // payments, then an empty block.
    let early: Vec<(String, u64)> = [(4, 0.5), (5, 0.6)]
        .iter()
        .map(|(i, btc)| {
            let txid = t.fund(&address(&t, *i), *btc).to_string();
            t.mine(1);
            let h = height_of(&t, &txid);
            (txid, h)
        })
        .collect();
    let empty = empty_block(&t);
    t.mine(1);
    let checkpoint = t.tip() as u32;
    let at = t.rpc("getblockhash", json!([checkpoint]));
    let header = t.rpc("getblockheader", json!([at, false])).as_str().unwrap().to_string();
    configure_regtest(RegtestConfig { checkpoint: Some(RegtestCheckpoint { height: checkpoint, header }), ..Default::default() });
    t.mine(1);

    // The chain server, held at a height on demand: its tip is that one, new tips are dropped.
    let held: Arc<Mutex<Option<Value>>> = Arc::default();
    let h = held.clone();
    let chain_at = electrum_proxy(electrs, Arc::new(move |m, _, mut v| match h.lock().unwrap().clone() {
        Some(tip) if m == "blockchain.headers.subscribe" => v.get("id").is_some().then(|| {
            v["result"] = tip;
            v
        }),
        _ => Some(v),
    }));
    let hold = || {
        let height = t.tip();
        let hash = t.rpc("getblockhash", json!([height]));
        *held.lock().unwrap() = Some(json!({"height": height, "hex": t.rpc("getblockheader", json!([hash, false]))}));
    };
    let release = || *held.lock().unwrap() = None;

    // Both kinds of server tell the same lie: confirmed in an empty block, with the empty branch of
    // its coinbase for a proof, which gives back the txid and no merkle root.
    let lie: Arc<Mutex<Option<Lie>>> = Arc::default();
    let (front_lies, electrum_lies) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (l, n) = (lie.clone(), front_lies.clone());
    let front = http_front(esplora_port, Arc::new(move |path, body| {
        let lie = l.lock().unwrap().clone()?;
        let status = json!({"confirmed": true, "block_height": lie.height, "block_hash": lie.hash, "block_time": lie.time});
        let tx = format!("/tx/{}", lie.txid);
        match body {
            None if path == format!("{tx}/merkle-proof") => {
                n.fetch_add(1, Ordering::SeqCst);
                Some((200, json!({"block_height": lie.height, "merkle": [], "pos": 0}).to_string().into_bytes()))
            }
            Some(_) if path == format!("{tx}/status") => Some((200, status.to_string().into_bytes())),
            Some(b) if path.starts_with("/scripthash/") || path == tx => {
                let mut v: Value = serde_json::from_slice(b).ok()?;
                restate(&mut v, &lie.txid, &status).then(|| (200, v.to_string().into_bytes()))
            }
            _ => None,
        }
    }));
    let (l, n) = (lie.clone(), electrum_lies.clone());
    let history_at = electrum_proxy(electrs, Arc::new(move |m, p, mut v| {
        let Some(lie) = l.lock().unwrap().clone() else { return Some(v) };
        match m {
            "blockchain.scripthash.get_history" => {
                for e in v["result"].as_array_mut().into_iter().flatten() {
                    if e["tx_hash"] == lie.txid.as_str() {
                        e["height"] = json!(lie.height);
                    }
                }
            }
            "blockchain.transaction.get_merkle" if p[0] == lie.txid.as_str() => {
                n.fetch_add(1, Ordering::SeqCst);
                v["result"] = json!({"block_height": lie.height, "merkle": [], "pos": 0});
                if let Some(o) = v.as_object_mut() {
                    o.remove("error");
                }
            }
            _ => {}
        }
        Some(v)
    }));
    let (chain_url, esplora, electrum) = (format!("tcp://{chain_at}"), format!("http://127.0.0.1:{front}"), format!("tcp://{history_at}"));

    // Above the chain's tip, the chain held a block behind: an honest payment waits, then confirms
    // on its proof against the chain's header once the chain reaches it. One made up in an empty
    // block waits too from Esplora, and is refused there; Electrum's client drops it at once. These
    // wallets' chains start at genesis.
    let (e1, _d1) = restore(&t, routes(&chain_url, &esplora), 1, None);
    let (e3, _d3) = restore(&t, routes(&chain_url, &electrum), 1, None);
    for r in [&e1, &e3] {
        r.synced();
        r.wait("the early payments", 60, || r.sats("confirmed") == 110_000_000);
        r.engine.reveal_for_test(10).unwrap();
    }
    hold();
    let paid = t.fund(&address(&t, 1), 0.4).to_string();
    t.mine(1);
    for r in [&e1, &e3] {
        r.wait("the payment held above the chain's tip", 60, || r.sats("waiting") == 40_000_000);
    }
    let (lied, signed) = payment(&t, &address(&t, 2), 0.3);
    let (height, hash, time) = empty_block(&t);
    *lie.lock().unwrap() = Some(Lie { txid: lied.clone(), height, hash, time });
    t.rpc("sendrawtransaction", json!([signed]));
    e1.wait("the made-up confirmation held as well", 60, || e1.sats("waiting") == 70_000_000);
    e3.wait("Electrum's made-up proof asked for", 60, || electrum_lies.load(Ordering::SeqCst) > 0);
    let before = e1.alerts("anchor_mismatch", "esplora-0");
    release();
    for r in [&e1, &e3] {
        never_confirmed(r, &lied, "the honest payment confirmed on its proof", 60, || r.row(&paid)["state"] == "confirmed");
    }
    never_confirmed(&e1, &lied, "Esplora's made-up proof refused", 60, || e1.alerts("anchor_mismatch", "esplora-0") > before);
    for r in [&e1, &e3] {
        still_not_confirmed(r, &lied);
        assert_eq!((r.sats("confirmed"), r.sats("waiting")), (150_000_000, 0), "only the honest payments, nothing held");
    }
    assert!(front_lies.load(Ordering::SeqCst) > 0 && suspect(&e1, "esplora-0"));
    assert_eq!(e3.row(&lied), Value::Null, "Electrum's client never took the made-up confirmation");
    println!("ANCHORS above the tip: {paid} confirmed on its proof; {lied} in empty block {height} refused (Esplora) and dropped (Electrum)");
    // The made-up payment, mined for real, confirms in its own block.
    *lie.lock().unwrap() = None;
    e1.engine.clear_suspect("esplora-0");
    t.mine(1);
    for r in [&e1, &e3] {
        r.wait("the payment confirmed in its own block", 60, || r.row(&lied)["state"] == "confirmed" && r.row(&lied)["height"].as_u64() == Some(t.tip()));
        r.engine.shutdown();
    }

    // Below the chain's start, wallets with a birthday above the checkpoint: the early payments
    // link to it and confirm on their proofs against the linked headers. One made up in the empty
    // block below it shows unchecked from Esplora and never comes from Electrum.
    let (height, hash, time) = empty;
    let (lied, signed) = payment(&t, &address(&t, 3), 0.2);
    *lie.lock().unwrap() = Some(Lie { txid: lied.clone(), height, hash, time });
    t.rpc("sendrawtransaction", json!([signed]));
    let below = |r: &T, name: &str| {
        r.synced();
        assert_eq!(r.engine.status()["authority"]["base"], checkpoint);
        for (txid, h) in &early {
            never_confirmed(r, &lied, &format!("{name}: {txid} confirmed at {h}"), 60, || r.row(txid)["state"] == "confirmed" && r.row(txid)["height"].as_u64() == Some(*h));
        }
    };
    let (e2, _d2) = restore(&t, routes(&chain_url, &esplora), checkpoint + 1, None);
    below(&e2, "esplora");
    never_confirmed(&e2, &lied, "Esplora's made-up confirmation unchecked", 60, || e2.row(&lied)["state"] == "unchecked");
    still_not_confirmed(&e2, &lied);
    assert_eq!(e2.row(&lied)["reportedBy"], "esplora-0");
    assert!(e2.alerts("anchor_mismatch", "esplora-0") >= 1 && suspect(&e2, "esplora-0"), "the lie marks the server");
    e2.engine.shutdown();
    let asked = electrum_lies.load(Ordering::SeqCst);
    let (e4, _d4) = restore(&t, routes(&chain_url, &electrum), checkpoint + 1, None);
    below(&e4, "electrum");
    never_confirmed(&e4, &lied, "Electrum's made-up proof asked for", 60, || electrum_lies.load(Ordering::SeqCst) > asked);
    still_not_confirmed(&e4, &lied);
    assert_eq!(e4.row(&lied), Value::Null, "Electrum's client never took the made-up confirmation");
    e4.engine.shutdown();
    *lie.lock().unwrap() = None;
    println!("ANCHORS below the start at {checkpoint}: {} payments linked and proved; {lied} in empty block {height} unchecked (Esplora) and dropped (Electrum); whole run {} s",
        early.len(), started.elapsed().as_secs());
}
