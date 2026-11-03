//! A server's confirmation counts once proved against the chain's headers: a real block's hash for
//! a transaction not in it never confirms, above the chain's tip or below its start, from a lying
//! Electrum proxy; honest payments confirm. Needs `--features test-hooks` and a fresh chain; README,
//! "Regtest", has the command.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::Transaction;
use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::network::{configure_regtest, RegtestCheckpoint, RegtestConfig};
use bitcoin_wallet_core::routes::Routes;
use common::history::{restore, TPRV};
use common::{collecting, electrum_proxy, MockManager, T};
use serde_json::{json, Value};

/// A confirmation a server makes up: `txid` in a block it isn't in.
#[derive(Clone)]
struct Lie {
    txid: String,
    height: u64,
}

/// The chain from `chain`'s headers only; history, pending payments, fees and broadcast from a
/// second Electrum server, `history`.
fn routes(chain: &str, history: &str) -> Routes {
    let mut r = Routes::regtest(&RegtestConfig { electrum: vec![chain.into(), history.into()], poll_secs: Some(1), ..Default::default() });
    let (c, h) = (r.chain[0].clone(), r.history[1].clone());
    (r.chain, r.history, r.pending, r.fees, r.broadcast, r.check) = (vec![c], vec![h.clone()], vec![h.clone()], vec![h.clone()], vec![h], vec![]);
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

/// A block with nothing from the mempool in it: its height.
fn empty_block(t: &T) -> u64 {
    let to = t.wallet_rpc("getnewaddress", json!(["empty"]));
    let hash = t.rpc("generateblock", json!([to, []]))["hash"].as_str().unwrap().to_string();
    t.rpc("getblockheader", json!([hash]))["height"].as_u64().unwrap()
}

/// Where Core's wallet confirmed a payment it made.
fn height_of(t: &T, txid: &str) -> u64 {
    t.wallet_rpc("gettransaction", json!([txid]))["blockheight"].as_u64().unwrap()
}

/// Waits until electrs indexes the node's tip, so a wallet's first scan sees it.
fn indexed(t: &T, electrs: SocketAddr) {
    let electrum = || -> Option<u64> {
        let mut s = TcpStream::connect(electrs).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        s.write_all(b"{\"id\":1,\"method\":\"blockchain.headers.subscribe\",\"params\":[]}\n").ok()?;
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).ok()?;
        serde_json::from_str::<Value>(&line).ok()?["result"]["height"].as_u64()
    };
    let tip = t.tip();
    t.wait("electrs at the node's tip", 60, || electrum() == Some(tip));
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

#[test]
#[ignore]
fn confirmations_count_once_proved() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
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

    // The history server lies: confirmed in an empty block, with the empty branch of its coinbase
    // for a proof, which gives back the txid and no merkle root.
    let lie: Arc<Mutex<Option<Lie>>> = Arc::default();
    let electrum_lies = Arc::new(AtomicUsize::new(0));
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
    let (chain_url, electrum) = (format!("tcp://{chain_at}"), format!("tcp://{history_at}"));

    // Above the chain's tip, the chain held a block behind: an honest payment waits, then confirms
    // on its proof against the chain's header once the chain reaches it. Electrum's client drops one
    // made up in an empty block at once. This wallet's chain starts at genesis.
    indexed(&t, electrs);
    let (e1, _d1) = restore(&t, routes(&chain_url, &electrum), 1, None);
    e1.engine.reveal_for_test(10).unwrap();
    e1.synced();
    e1.wait("the early payments", 60, || e1.sats("confirmed") == 110_000_000);
    hold();
    let paid = t.fund(&address(&t, 1), 0.4).to_string();
    t.mine(1);
    e1.wait("the payment held above the chain's tip", 60, || e1.sats("waiting") == 40_000_000);
    let (lied, signed) = payment(&t, &address(&t, 2), 0.3);
    let height = empty_block(&t);
    *lie.lock().unwrap() = Some(Lie { txid: lied.clone(), height });
    t.rpc("sendrawtransaction", json!([signed]));
    e1.wait("Electrum's made-up proof asked for", 60, || electrum_lies.load(Ordering::SeqCst) > 0);
    release();
    never_confirmed(&e1, &lied, "the honest payment confirmed on its proof", 60, || e1.row(&paid)["state"] == "confirmed");
    still_not_confirmed(&e1, &lied);
    assert_eq!((e1.sats("confirmed"), e1.sats("waiting")), (150_000_000, 0), "only the honest payments, nothing held");
    assert_eq!(e1.row(&lied), Value::Null, "Electrum's client never took the made-up confirmation");
    println!("ANCHORS above the tip: {paid} confirmed on its proof; {lied} in empty block {height} dropped");
    // The made-up payment, mined for real, confirms in its own block.
    *lie.lock().unwrap() = None;
    t.mine(1);
    e1.wait("the payment confirmed in its own block", 60, || e1.row(&lied)["state"] == "confirmed" && e1.row(&lied)["height"].as_u64() == Some(t.tip()));
    e1.engine.shutdown();

    // Below the chain's start, a wallet with a birthday above the checkpoint: the early payments
    // link to it and confirm on their proofs against the linked headers. One made up in the empty
    // block below it never comes from Electrum.
    let height = empty;
    let (lied, signed) = payment(&t, &address(&t, 3), 0.2);
    *lie.lock().unwrap() = Some(Lie { txid: lied.clone(), height });
    t.rpc("sendrawtransaction", json!([signed]));
    indexed(&t, electrs);
    let asked = electrum_lies.load(Ordering::SeqCst);
    let (e2, _d2) = restore(&t, routes(&chain_url, &electrum), checkpoint + 1, None);
    e2.engine.reveal_for_test(10).unwrap();
    e2.synced();
    assert_eq!(e2.engine.status()["authority"]["base"], checkpoint);
    for (txid, h) in &early {
        never_confirmed(&e2, &lied, &format!("{txid} confirmed at {h}"), 60, || e2.row(txid)["state"] == "confirmed" && e2.row(txid)["height"].as_u64() == Some(*h));
    }
    never_confirmed(&e2, &lied, "Electrum's made-up proof asked for", 60, || electrum_lies.load(Ordering::SeqCst) > asked);
    still_not_confirmed(&e2, &lied);
    assert_eq!(e2.row(&lied), Value::Null, "Electrum's client never took the made-up confirmation");
    e2.engine.shutdown();
    *lie.lock().unwrap() = None;
    println!("ANCHORS below the start at {checkpoint}: {} payments linked and proved; {lied} in empty block {height} dropped; whole run {} s",
        early.len(), started.elapsed().as_secs());
}
