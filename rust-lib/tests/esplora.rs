//! The Esplora path on regtest, against Blockstream's electrs in its esplora flavour (`nix build
//! .#esplora-electrs`, `chain.sh esplora`): history, broadcast and fee rates through Esplora
//! while the Electrum header chain holds the chain. Then the same server over HTTPS with a
//! self-signed certificate, reached by its pin. The run command is in the README.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::network::{configure_regtest, RegtestConfig};
use bitcoin_wallet_core::routes::{Kind, Routes};
use common::{chain, collecting, MockManager, T};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::json;
use sha2::{Digest, Sha256};

const CERT: &[u8] = include_bytes!("data/pin/v1.der");
const KEY: &[u8] = include_bytes!("data/pin/v1.key.der");

/// Electrum's header chain for the chain; Esplora for everything else.
fn routes(electrum: &str, esplora: &str, pin: Option<[u8; 32]>) -> Routes {
    let mut r = Routes::regtest(&RegtestConfig { electrum: vec![electrum.into()], esplora: vec![esplora.into()], poll_secs: Some(1), ..Default::default() });
    let mut e = r.history.iter().find(|s| s.kind == Kind::Esplora).cloned().expect("the Esplora source");
    e.pin = pin;
    (r.history, r.pending, r.fees, r.broadcast, r.check) = (vec![e.clone()], vec![e.clone()], vec![e.clone()], vec![e.clone()], vec![e]);
    r
}

/// HTTPS in front of Esplora's HTTP, with a self-signed version 1 certificate: one request per
/// connection, answered once the server closes its side.
fn tls_front(upstream: u16) -> u16 {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = provider.key_provider.load_private_key(PrivateKeyDer::try_from(KEY).unwrap()).unwrap();
    let certified = Arc::new(rustls::sign::CertifiedKey::new(vec![CertificateDer::from(CERT)], key));
    #[derive(Debug)]
    struct One(Arc<rustls::sign::CertifiedKey>);
    impl rustls::server::ResolvesServerCert for One {
        fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }
    let config = Arc::new(rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_cert_resolver(Arc::new(One(certified))));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let config = config.clone();
            std::thread::spawn(move || {
                let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), tcp);
                let mut reader = BufReader::new(&mut tls);
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
                let Ok(mut up) = TcpStream::connect(("127.0.0.1", upstream)) else { return };
                let mut request = head.into_bytes();
                request.extend_from_slice(b"Connection: close\r\n\r\n");
                request.extend_from_slice(&body);
                let mut reply = vec![];
                if up.write_all(&request).is_err() || up.read_to_end(&mut reply).is_err() {
                    return;
                }
                let tls = reader.into_inner();
                let _ = tls.write_all(&reply).and_then(|_| tls.flush());
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    port
}

fn open(t: &T, routes: Routes) -> (T, tempfile::TempDir) {
    let (sink, events) = collecting();
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(root.path().join("wallets"), sink, t.manager.clone(), None);
    engine.set_regtest_routes(routes);
    let r = T { engine, rpc: t.rpc.clone(), cookie: t.cookie.clone(), events, manager: t.manager.clone() };
    r.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    (r, root)
}

#[test]
#[ignore]
fn esplora_history_broadcast_and_fees() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    configure_regtest(RegtestConfig::default());
    let esplora_port: u16 = std::env::var("ESPLORA_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3002);
    chain(&["esplora"]);
    let electrum = format!("tcp://{}", std::env::var("REGTEST_ELECTRUM").expect("REGTEST_ELECTRUM").split(',').next().unwrap().trim().trim_start_matches("tcp://"));
    let esplora = format!("http://127.0.0.1:{esplora_port}");
    let manager = Arc::new(MockManager::new(Duration::from_millis(300)));
    let (sink, events) = collecting();
    let root = tempfile::tempdir().unwrap();
    let t = T { engine: Engine::new(root.path().join("wallets"), sink, manager.clone(), None), rpc, cookie, events, manager };
    t.engine.set_regtest_routes(routes(&electrum, &esplora, None));
    t.job("open_wallet", json!({"network": "regtest", "family": "bitcoin"}));
    t.synced();
    let st = t.engine.status();
    assert_eq!((st["authority"]["kind"].as_str(), st["historyServer"].as_str()), (Some("electrum_headers"), Some("esplora-0")), "{st}");
    assert_eq!(t.engine.history(0)["total"], 0, "start from a fresh `chain.sh prepare`");

    // History: a payment pending, then confirmed, its anchor checked by Esplora's merkle proof.
    let addr = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let paid = t.fund(&addr, 1.0).to_string();
    t.wait("the payment as pending", 60, || t.row(&paid)["state"] == "pending");
    assert_eq!(t.row(&paid)["reportedBy"], "esplora-0");
    t.mine(1);
    t.synced();
    t.wait("the payment confirmed", 60, || t.row(&paid)["state"] == "confirmed");
    assert_eq!(t.sats("confirmed"), 100_000_000);

    // Broadcast through Esplora.
    let theirs = t.wallet_rpc("getnewaddress", json!(["payee"])).as_str().unwrap().to_string();
    let p = t.job("build_send", json!({"recipients": [{"address": theirs, "amountSat": "10000000"}], "feeRate": 2.0}));
    let sent = t.sign(p["previewId"].as_str().unwrap());
    let txid = sent["txid"].as_str().unwrap().to_string();
    assert_eq!(sent["via"], "esplora-0", "{sent}");
    assert!(["seen", "requested"].contains(&sent["broadcast"].as_str().unwrap()), "{sent}");
    t.wait("the send in the node's mempool", 30, || t.in_mempool(&txid));
    t.mine(1);
    t.synced();
    t.wait("the send confirmed", 60, || t.row(&txid)["state"] == "confirmed");

    // Fee rates: Esplora answered (regtest's node has no estimates, so they are the floor).
    t.wait("Esplora's fee estimates", 30, || t.engine.fee_rates_json()["sources"].as_array().is_some_and(|s| s.contains(&json!("esplora-0"))));
    let fees = t.engine.fee_rates_json();
    assert!(fees["normal"].as_f64().unwrap() >= fees["minimum"].as_f64().unwrap(), "{fees}");
    let src = t.engine.sources_status();
    let row = src["sources"].as_array().unwrap().iter().find(|s| s["id"] == "esplora-0").cloned().unwrap();
    assert_eq!((row["encrypted"].clone(), row["suspect"].clone()), (json!(false), json!(false)), "{row}");
    println!("ESPLORA history, broadcast {txid} via esplora-0, fees {fees}");
    let total = t.engine.history(0)["total"].clone();
    t.engine.shutdown();

    // The same server over HTTPS with a self-signed certificate: its pin opens it, another doesn't.
    let front = tls_front(esplora_port);
    let pin: [u8; 32] = Sha256::digest(CERT).into();
    let (r, _dir) = open(&t, routes(&electrum, &format!("https://127.0.0.1:{front}"), Some(pin)));
    r.synced();
    r.wait("the history over the pinned server", 60, || r.engine.history(0)["total"] == total);
    let row = r.engine.sources_status()["sources"].as_array().unwrap().iter().find(|s| s["id"] == "esplora-0").cloned().unwrap();
    assert_eq!((row["encrypted"].clone(), row["error"].clone()), (json!(true), json!(null)), "{row}");
    r.engine.shutdown();
    let (wrong, _dir2) = open(&t, routes(&electrum, &format!("https://127.0.0.1:{front}"), Some([7; 32])));
    wrong.wait("the wrong pin refused", 60, || wrong.engine.status()["lastError"].as_str().is_some_and(|e| e.contains("esplora-0")));
    assert_eq!(wrong.engine.history(0)["total"], 0);
    println!("ESPLORA pinned: {} rows over https://127.0.0.1:{front}; another pin: {}", total, wrong.engine.status()["lastError"]);
    wrong.engine.shutdown();
}
