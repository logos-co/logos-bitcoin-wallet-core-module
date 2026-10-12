//! The engine on tools/regtest/chain.sh's chain, no Logos runtime: a doctoring proxy, and a manager
//! over the interface's MockSigner. The run command and its environment are in the README.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::Transaction;
use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::network::{configure_regtest, RegtestConfig};
use common::{chain, collecting, electrum_proxy, MockManager, T};
use serde_json::{json, Value};

// ── A doctoring proxy in front of electrs ────────────────────────────────

#[derive(Default)]
struct Doctor {
    /// Rewrite `blockchain.block.header` at this height: same merkle root, another hash.
    header_at: Option<u64>,
    /// Rewrite `blockchain.transaction.get` for this txid: bytes that hash to something else.
    tx: Option<String>,
    hits: Vec<String>,
}

fn doctor_line(doctor: &Mutex<Doctor>, method: &str, params: &Value, mut reply: Value) -> Value {
    let mut d = doctor.lock().unwrap();
    match method {
        "blockchain.block.header" if params[0].as_u64().is_some() && params[0].as_u64() == d.header_at => {
            if let Some(hexs) = reply["result"].as_str() {
                let mut bytes = hex::decode(hexs).unwrap();
                bytes[79] ^= 0x5a;
                reply["result"] = json!(hex::encode(bytes));
                d.hits.push(format!("header {}", params[0]));
            }
        }
        "blockchain.transaction.get" if params[0].as_str().is_some() && params[0].as_str().map(str::to_string) == d.tx => {
            if let Some(hexs) = reply["result"].as_str() {
                let mut tx: Transaction = deserialize_hex(hexs).unwrap();
                tx.output[0].value = bitcoin::Amount::from_sat(tx.output[0].value.to_sat() + 1);
                reply["result"] = json!(serialize_hex(&tx));
                d.hits.push(format!("tx {}", params[0]));
            }
        }
        _ => {}
    }
    reply
}

#[test]
#[ignore]
fn bitcoin_wallet_on_regtest() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    let servers: Vec<SocketAddr> = std::env::var("REGTEST_ELECTRUM").expect("REGTEST_ELECTRUM").split(',').map(|s| s.trim().trim_start_matches("tcp://").parse().unwrap()).collect();
    let doctor: Arc<Mutex<Doctor>> = Arc::default();
    let d = doctor.clone();
    let via_proxy = electrum_proxy(servers[0], Arc::new(move |m, p, v| Some(doctor_line(&d, m, p, v))));
    // The proxy is first: it holds the history until it lies, then the honest electrs takes over.
    configure_regtest(RegtestConfig { electrum: vec![format!("tcp://{via_proxy}"), format!("tcp://{}", servers[1])], poll_secs: Some(1), ..Default::default() });
    let (sink, events) = collecting();
    let manager = Arc::new(MockManager::new(Duration::from_millis(1500)));
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(root.path().join("wallets"), sink, manager.clone(), None);
    let t = T { engine, rpc, cookie, events, manager };
    let started = Instant::now();

    // Open: the core asks the manager, shows the open handle while the person decides, then opens.
    let opened = t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    assert_eq!(opened["family"], "bitcoin");
    assert_eq!(opened["needsBirthday"], true, "a restored wallet without a day asks for one: {opened}");
    assert!(t.events.lock().unwrap().iter().any(|(n, v)| n == "walletStateChanged" && v["state"] == "awaiting_open" && v["openHandle"].as_str().is_some_and(|h| h.starts_with("sma_"))));
    t.synced();
    let sync_ms = started.elapsed().as_millis();
    println!("opened and synced to {} in {sync_ms} ms", t.tip());
    let st = t.engine.status();
    assert_eq!((st["state"].clone(), st["authority"]["kind"].clone()), (json!("ready"), json!("electrum_headers")));
    assert_eq!(t.engine.history(0)["total"], 0, "the test phrase's wallet must be empty: start from a fresh `chain.sh prepare`");
    assert!(t.engine.descriptors()["external"].as_str().unwrap().starts_with("wpkh([73c5da0a/84'/1'/0']tpub"));

    // Receive, pending, then confirmed.
    let addr = t.engine.next_address()["address"].as_str().unwrap().to_string();
    assert!(addr.starts_with("bcrt1q"));
    let funded = t.fund(&addr, 1.0);
    t.wait("the payment as pending", 60, || t.sats("pending") == 100_000_000);
    assert_eq!(t.row(&funded.to_string())["state"], "pending");
    assert_eq!(t.row(&funded.to_string())["reportedBy"], "electrum-0");
    t.mine(1);
    t.synced();
    t.wait("the payment confirmed", 60, || t.sats("confirmed") == 100_000_000);
    assert_eq!(t.row(&funded.to_string())["intent"], "receive");

    // A birthday for the restore: refused past the first payment, then set; the full scan runs again.
    let first_height = t.row(&funded.to_string())["height"].as_u64().unwrap();
    let (code, e) = t.job_fail("set_birthday", json!({"height": first_height + 1}));
    assert!(code == "invalid" && e.contains("before a birthday"), "{code}: {e}");
    let (code, e) = t.job_fail("set_birthday", json!({"date": "2999-01-01"}));
    assert!(code == "invalid" && e.contains("still to come"), "{code}: {e}");
    let malformed = t.engine.start_job("set_birthday", r#"{"day":"2024-01-01"}"#);
    assert_eq!((malformed["ok"].clone(), malformed["code"].clone()), (json!(false), json!("invalid")), "{malformed}");
    let set = t.job("set_birthday", json!({"height": first_height}));
    assert_eq!(set["birthday"]["source"], "set", "{set}");
    t.wait("the rescan", 60, || t.engine.status()["rescanFrom"].is_null());
    t.synced();
    let st = t.engine.status();
    assert_eq!((st["needsBirthday"].clone(), st["birthdaySource"].clone()), (json!(false), json!("set")), "{st}");
    assert!(t.events.lock().unwrap().iter().any(|(n, v)| n == "walletStateChanged" && v["rescanFrom"] == set["rescanFrom"]), "the app sees the rescan");
    assert_eq!(t.sats("confirmed"), 100_000_000, "the rescan keeps the payment");

    // Send from native segwit: approval through the manager, BDK finalizes, the node accepts it.
    let theirs = t.wallet_rpc("getnewaddress", json!(["payee"])).as_str().unwrap().to_string();
    let (preview, sent) = t.send(&theirs, 10_000_000, None);
    let txid = sent["txid"].as_str().unwrap().to_string();
    assert!(["seen", "requested"].contains(&sent["broadcast"].as_str().unwrap()), "{sent}");
    assert!(t.in_mempool(&txid));
    let fee: u64 = preview["feeSat"].as_str().unwrap().parse().unwrap();
    t.mine(1);
    t.synced();
    t.wait("the send confirmed", 60, || t.row(&txid)["state"] == "confirmed");
    assert_eq!(t.row(&txid)["intent"], "send");
    assert_eq!(t.sats("confirmed"), 100_000_000 - 10_000_000 - fee);
    // A rebroadcast of a transaction the node already holds is seen, not an error.
    assert_eq!(t.job("rebroadcast", json!({"txid": txid}))["broadcast"], "seen");
    println!("segwit send {txid}: fee {fee} sat, vsize {}", preview["vsize"]);

    // A declined approval fails the job with the reason; the preview and its locks stay until cancelled.
    let balance_before = t.sats("confirmed");
    for reason in ["rejected", "expired_no_ack"] {
        *t.manager.next_reason.lock().unwrap() = Some(reason);
        let p = t.job("build_send", json!({"recipients": [{"address": theirs, "amountSat": "1000000"}]}));
        let id = p["previewId"].as_str().unwrap().to_string();
        let e = t.job_err("sign_and_broadcast", json!({"previewId": id}));
        assert!(e.starts_with(reason), "{e}");
        assert!(t.engine.preview(&id)["state"].as_str().unwrap().starts_with("failed"));
        assert!(t.engine.utxos()["utxos"].as_array().unwrap().iter().any(|u| u["locked"] == true), "inputs stay locked");
        let c = t.job("cancel_send", json!({"previewId": id}));
        assert!(!c["unlocked"].as_array().unwrap().is_empty(), "{c}");
        assert!(t.engine.utxos()["utxos"].as_array().unwrap().iter().all(|u| u["locked"] == false));
    }
    assert_eq!(t.sats("confirmed"), balance_before, "nothing left the wallet");

    // Bump a low-fee send through build_fee_bump; the replacement confirms, the original doesn't.
    let (_, slow) = t.send(&theirs, 5_000_000, Some(1.0));
    let slow_id = slow["txid"].as_str().unwrap().to_string();
    assert!(t.in_mempool(&slow_id));
    let bump = t.job("bump_fee", json!({"txid": slow_id, "feeRate": 6.0}));
    assert_eq!((bump["kind"].clone(), bump["replaces"].clone()), (json!("fee_bump"), json!(slow_id)));
    let bumped = t.sign(bump["previewId"].as_str().unwrap());
    let bump_id = bumped["txid"].as_str().unwrap().to_string();
    t.wait("the replacement in the mempool", 30, || t.in_mempool(&bump_id) && !t.in_mempool(&slow_id));
    t.mine(1);
    t.synced();
    t.wait("the bump confirmed", 60, || t.row(&bump_id)["state"] == "confirmed");
    assert_eq!(t.row(&bump_id)["intent"], "fee_bump");
    assert_eq!(t.row(&slow_id)["state"], "replaced");

    // A lost broadcast: the store after a broadcast that went out answers busy, five times over.
    // The job still answers the txid; the write-ahead record keeps the send through a reopen.
    #[cfg(feature = "test-hooks")]
    {
        use bitcoin_wallet_core::engine::hooks::BUSY_AFTER_BROADCAST;
        use std::sync::atomic::Ordering;
        let p = t.job("build_send", json!({"recipients": [{"address": theirs, "amountSat": "2000000"}], "feeRate": 2.0}));
        let inputs: Vec<String> = p["inputs"].as_array().unwrap().iter().map(|i| i["outpoint"].as_str().unwrap().to_string()).collect();
        BUSY_AFTER_BROADCAST.store(true, Ordering::SeqCst);
        let lost = t.sign(p["previewId"].as_str().unwrap());
        BUSY_AFTER_BROADCAST.store(false, Ordering::SeqCst);
        let lost_id = lost["txid"].as_str().unwrap().to_string();
        assert_eq!(lost_id, p["txid"].as_str().unwrap());
        assert!(["unknown", "seen", "requested"].contains(&lost["broadcast"].as_str().unwrap()), "{lost}");
        assert!(t.in_mempool(&lost_id), "it went out");
        let group = t.engine.status()["group"].as_str().unwrap().to_string();
        t.job("close_wallet", json!({}));
        t.job("open_wallet", json!({"network": "regtest", "group": group}));
        t.synced();
        let row = t.row(&lost_id);
        assert_eq!((row["sendState"].clone(), row["state"].clone()), (json!("broadcasting"), json!("sent")), "{row}");
        let spendable: Vec<String> = t.engine.utxos()["utxos"].as_array().unwrap().iter().filter(|u| u["locked"] == false).map(|u| u["outpoint"].as_str().unwrap().to_string()).collect();
        assert!(inputs.iter().all(|i| !spendable.contains(i)), "its coins stay out of reach: {inputs:?} {spendable:?}");
        assert_eq!(t.job("rebroadcast", json!({"txid": lost_id}))["broadcast"], "seen");
        let bump = t.job("bump_fee", json!({"txid": lost_id, "feeRate": 8.0}));
        assert_eq!(bump["replaces"], json!(lost_id), "{bump}");
        t.job("cancel_send", json!({"previewId": bump["previewId"]}));
        t.mine(1);
        t.synced();
        t.wait("the lost broadcast confirmed", 60, || t.row(&lost_id)["state"] == "confirmed");
        println!("lost broadcast {lost_id}: answered {}, kept through a reopen, rebroadcast and bumpable", lost["broadcast"]);
    }

    // A doctored anchor: the proxy serves another header for the block confirming a payment.
    t.wait("history on the proxy", 30, || t.engine.status()["historyServer"] == "electrum-0");
    let addr3 = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let anchored = t.fund(&addr3, 0.05).to_string();
    t.wait("the payment as pending", 60, || t.row(&anchored)["state"] == "pending");
    let before = t.alerts("anchor_mismatch", "electrum-0");
    doctor.lock().unwrap().header_at = Some(t.tip() + 1);
    t.mine(1);
    t.wait("the anchor refused", 60, || t.alerts("anchor_mismatch", "electrum-0") > before);
    assert!(doctor.lock().unwrap().hits.iter().any(|h| h.starts_with("header ")));
    t.synced();
    t.wait("the payment confirmed through the honest server", 60, || t.row(&anchored)["state"] == "confirmed");
    assert_eq!(t.row(&anchored)["height"].as_u64(), Some(t.tip()));
    let sources = t.engine.sources_status();
    let proxy_row = sources["sources"].as_array().unwrap().iter().find(|s| s["id"] == "electrum-0").unwrap().clone();
    assert_eq!(proxy_row["suspect"], true, "{sources}");
    assert_eq!(t.engine.status()["historyServer"], "electrum-1");
    doctor.lock().unwrap().header_at = None;

    // A doctored transaction: bytes that don't hash to the txid are refused.
    assert_eq!(t.engine.clear_suspect("electrum-0")["cleared"], true);
    let addr4 = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let raw = t.wallet_rpc("createrawtransaction", json!([[], {addr4.clone(): 0.03}]));
    let funded_raw = t.wallet_rpc("fundrawtransaction", json!([raw]))["hex"].clone();
    let signed = t.wallet_rpc("signrawtransactionwithwallet", json!([funded_raw]))["hex"].as_str().unwrap().to_string();
    let doctored_tx: Transaction = deserialize_hex(&signed).unwrap();
    let doctored_id = doctored_tx.compute_txid().to_string();
    doctor.lock().unwrap().tx = Some(doctored_id.clone());
    // Back on the proxy for history before the payment goes out.
    t.wait("history back on the proxy", 30, || t.engine.status()["historyServer"] == "electrum-0");
    let alerts_before = t.alerts("suspect", "electrum-0");
    t.rpc("sendrawtransaction", json!([signed]));
    t.wait("the doctored bytes refused", 60, || t.alerts("suspect", "electrum-0") > alerts_before);
    t.wait("the payment through the honest server", 60, || t.row(&doctored_id)["state"] == "pending");
    assert_eq!(t.row(&doctored_id)["amountSat"], "3000000", "the wallet holds the real transaction");
    assert!(doctor.lock().unwrap().hits.iter().any(|h| h.starts_with("tx ")));
    doctor.lock().unwrap().tx = None;
    t.mine(1);
    t.synced();

    // A reorg under server anchors: the block holding a payment is replaced; the anchor follows.
    let addr2 = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let reorged = t.fund(&addr2, 0.2).to_string();
    t.mine(1);
    t.synced();
    t.wait("the payment confirmed", 60, || t.row(&reorged)["state"] == "confirmed");
    let old_block = t.rpc("getbestblockhash", json!([]));
    let h = t.tip();
    assert_eq!(t.row(&reorged)["blockHash"], old_block);
    let suspects_before = t.alerts("suspect", "electrum-0") + t.alerts("suspect", "electrum-1");
    // The fork node replaces the block offline and reconnects: the node electrs follows reorgs as
    // on a live network, keeping the old block as a valid stale fork.
    chain(&["reorg", "1"]);
    let new_block = t.rpc("getblockhash", json!([h]));
    assert_ne!(old_block, new_block);
    t.synced();
    t.wait("the payment re-anchored in the new block", 60, || {
        let r = t.row(&reorged);
        r["state"] == "confirmed" && r["height"].as_u64() == Some(h) && r["confirmations"] == 2
    });
    assert_eq!(t.row(&reorged)["blockHash"], new_block, "the row names the new block");
    let lr = t.engine.status()["lastReorg"].clone();
    assert_eq!((lr["height"].as_u64(), lr["depth"].as_u64()), (Some(h), Some(1)), "{lr}");
    assert!(lr["moved"].as_array().unwrap().contains(&json!(reorged)), "{lr}");
    t.wait("walletStateChanged with the reorg", 10, || t.events.lock().unwrap().iter().any(|(n, v)| n == "walletStateChanged" && v["lastReorg"] == lr));
    println!("reorg at {h}: {} replaced by {}", old_block, new_block);
    // A server that is only behind the reorg is not blamed for it.
    assert_eq!(t.alerts("suspect", "electrum-0") + t.alerts("suspect", "electrum-1"), suspects_before, "a lagging server was blamed");

    // Exposure: both servers learned the addresses, the first since the wallet opened.
    let exposure = t.engine.exposure();
    assert_eq!(exposure["servers"].as_array().unwrap().len(), 2, "{exposure}");

    // Taproot: a second wallet, same flow.
    t.job("close_wallet", json!({}));
    assert_eq!(t.engine.status()["state"], "no_wallet");
    assert!(t.manager.log.lock().unwrap().iter().any(|l| l.starts_with("close ") && l.contains("g_seg")));
    let tr = t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin_taproot"}));
    assert_eq!(tr["family"], "bitcoin_taproot");
    t.synced();
    let taddr = t.engine.next_address()["address"].as_str().unwrap().to_string();
    assert!(taddr.starts_with("bcrt1p"));
    t.fund(&taddr, 0.5);
    t.mine(1);
    t.synced();
    t.wait("taproot funds confirmed", 60, || t.sats("confirmed") == 50_000_000);
    let (tpreview, tsent) = t.send(&theirs, 20_000_000, None);
    let ttxid = tsent["txid"].as_str().unwrap().to_string();
    t.mine(1);
    t.synced();
    t.wait("the taproot send confirmed", 60, || t.row(&ttxid)["state"] == "confirmed");
    println!("taproot send {ttxid}: fee {} sat, vsize {}", tpreview["feeSat"], tpreview["vsize"]);

    // Change too small to spend goes to the fee when asked; the node takes the transaction. One
    // coin, so the probe's fee is the send's: 450 sat of change, under the 580 a taproot input costs.
    let coin = t.sats("confirmed");
    let probe = t.job("build_send", json!({"recipients": [{"address": theirs, "amountSat": (coin / 2).to_string()}], "feeRate": 10.0}));
    let probe_fee: u64 = probe["feeSat"].as_str().unwrap().parse().unwrap();
    t.job("cancel_send", json!({"previewId": probe["previewId"]}));
    let amount = coin - probe_fee - 450;
    let p = t.job("build_send", json!({"recipients": [{"address": theirs, "amountSat": amount.to_string()}], "feeRate": 10.0, "smallChangeToFee": true}));
    assert_eq!(p["outputs"].as_array().unwrap().len(), 1, "{p}");
    assert_eq!((p["warnings"][0]["kind"].as_str(), p["warnings"][0]["amountSat"].as_str()), (Some("change_to_fee"), Some("450")), "{p}");
    assert_eq!(p["feeSat"], (probe_fee + 450).to_string());
    let no_change = t.sign(p["previewId"].as_str().unwrap())["txid"].as_str().unwrap().to_string();
    assert!(t.in_mempool(&no_change));
    t.mine(1);
    t.synced();
    t.wait("the send without change confirmed", 60, || t.row(&no_change)["state"] == "confirmed");
    assert_eq!(t.sats("confirmed"), 0);

    // Reopen by group: the key and descriptors come from the manager again, the history from disk.
    let group = t.engine.status()["group"].as_str().unwrap().to_string();
    t.job("close_wallet", json!({}));
    let again = t.job("open_wallet", json!({"network": "regtest", "group": group}));
    assert_eq!(again["created"], false);
    t.synced();
    assert_eq!(t.row(&ttxid)["state"], "confirmed");

    let t0 = Instant::now();
    t.engine.shutdown();
    let unload_ms = t0.elapsed().as_millis();
    println!("shutdown in {unload_ms} ms; whole run {} s", started.elapsed().as_secs());
    assert!(unload_ms < 2000, "unload took {unload_ms} ms");
}
