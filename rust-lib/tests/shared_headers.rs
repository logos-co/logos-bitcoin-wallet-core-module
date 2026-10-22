//! One header store per network: a second wallet, and a wallet reopened under a new database key,
//! read the chain's headers there, not from the server. A store whose headers fail the checks,
//! one that isn't a database, and one holding a chain the server doesn't are found and rebuilt.
//! The run command is in the README.

mod common;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::TxMerkleNode;
use bitcoin_wallet_core::engine::Engine;
use bitcoin_wallet_core::headers::HeaderChain;
use bitcoin_wallet_core::headerstore::SharedHeaders;
use bitcoin_wallet_core::network::{configure_regtest, BNetwork, RegtestConfig};
use common::{collecting, electrum_proxy, MockManager, T};
use serde_json::json;

/// The address of the generator point's key: no wallet of the chain's holds it.
const ELSEWHERE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// A regtest header on `prev`, its merkle root `salt`, mined to its trivial target.
fn mine(prev: &Header, time: u32, salt: u8) -> Header {
    let mut h = Header { version: Version::from_consensus(0x2000_0000), prev_blockhash: prev.block_hash(), merkle_root: TxMerkleNode::from_byte_array([salt; 32]), time, bits: prev.bits, nonce: 0 };
    while h.validate_pow(h.target()).is_err() {
        h.nonce += 1;
    }
    h
}

#[test]
#[ignore]
fn wallets_share_the_networks_headers() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let Some((rpc, cookie)) = common::chain_env() else {
        eprintln!("skipped: REGTEST_RPC is not set (see tools/regtest/chain.sh)");
        return;
    };
    let server: SocketAddr = std::env::var("REGTEST_ELECTRUM").expect("REGTEST_ELECTRUM").split(',').next().unwrap().trim().trim_start_matches("tcp://").parse().unwrap();
    // Counts the headers the server's `blockchain.block.headers` answers carry.
    let served = Arc::new(AtomicU64::new(0));
    let s = served.clone();
    let proxy = electrum_proxy(
        server,
        Arc::new(move |m, _, v| {
            if m == "blockchain.block.headers" {
                s.fetch_add(v["result"]["count"].as_u64().unwrap_or(0), Ordering::SeqCst);
            }
            Some(v)
        }),
    );
    configure_regtest(RegtestConfig { electrum: vec![format!("tcp://{proxy}")], poll_secs: Some(1), ..Default::default() });
    let (sink, events) = collecting();
    let manager = Arc::new(MockManager::new(Duration::from_millis(200)));
    let root = tempfile::tempdir().unwrap();
    let t = T { engine: Engine::new(root.path().join("wallets"), sink, manager.clone(), None), rpc, cookie, events, manager };
    while t.tip() < 8_000 {
        t.rpc("generatetoaddress", json!([1_000, ELSEWHERE]));
    }
    let tip = t.tip() as u32;
    let store = root.path().join("headers");
    let stored = || SharedHeaders::open(&store, BNetwork::Regtest).unwrap().load(2_000_000_000).map(|c| (c.tip_height(), c.tip_hash()));
    let real = || bitcoin::BlockHash::from_str(t.rpc("getbestblockhash", json!([])).as_str().unwrap()).unwrap();
    // Opens a wallet, waits for its sync, and closes it: the headers the server sent meanwhile.
    let sync = |params: serde_json::Value, what: &str| -> (serde_json::Value, u64, u128) {
        served.store(0, Ordering::SeqCst);
        let t0 = Instant::now();
        let opened = t.job("open_wallet", params);
        t.synced();
        let (n, ms) = (served.load(Ordering::SeqCst), t0.elapsed().as_millis());
        t.job("close_wallet", json!({}));
        println!("{what}: {n} headers from the server, synced in {ms} ms");
        (opened, n, ms)
    };

    // The first wallet on the network reads every header from the server, and the store keeps them.
    let (_, first, _) = sync(json!({"network": "regtest", "family": "bitcoin"}), "the first wallet");
    assert!(first >= u64::from(tip), "{first} of {tip}");
    assert_eq!(stored(), Some((tip, real())));

    // A second wallet, its own encrypted database, reads none: the store has them, and the server
    // vouches for them with one header.
    let (_, second, _) = sync(json!({"network": "regtest", "family": "bitcoin_taproot"}), "a second wallet");
    assert_eq!(second, 0);
    let wallets = std::fs::read_dir(root.path().join("wallets/regtest")).unwrap().flatten().filter(|e| e.path().join("wallet.db").exists()).count();
    assert_eq!(wallets, 2);

    // The first wallet under a new database key: its database is set aside, the headers aren't.
    t.manager.forget_key("g_seg00000000000000000000000000000000");
    let (opened, reset, _) = sync(json!({"network": "regtest", "group": "g_seg00000000000000000000000000000000"}), "the first wallet, its key changed");
    assert_eq!((opened["reset"].clone(), reset), (json!(true), 0), "{opened}");

    // A header in the store that no longer links: those from it up are read again, the rest not.
    {
        let c = rusqlite::Connection::open(store.join("regtest.db")).unwrap();
        let raw: Vec<u8> = c.query_row("SELECT header FROM headers WHERE height = 5000", [], |r| r.get(0)).unwrap();
        let mut h: Header = bitcoin::consensus::encode::deserialize(&raw).unwrap();
        h.prev_blockhash = bitcoin::BlockHash::all_zeros();
        c.execute("UPDATE headers SET header = ?1 WHERE height = 5000", [bitcoin::consensus::encode::serialize(&h)]).unwrap();
    }
    let (_, again, _) = sync(json!({"network": "regtest", "group": "shell-73c5da0a-84-1-0"}), "a wallet on a damaged store");
    // From 5,000 up: the first of them names the wallet's tip, 4,999, so nothing more is read.
    assert_eq!(again, u64::from(tip - 4_999));
    assert_eq!(stored(), Some((tip, real())), "rebuilt");

    // A store that isn't a database: started again, and filled again.
    for ext in ["db", "db-wal", "db-shm"] {
        let _ = std::fs::remove_file(store.join(format!("regtest.{ext}")));
    }
    std::fs::write(store.join("regtest.db"), vec![0x5a; 64 * 1024]).unwrap();
    let (_, whole, _) = sync(json!({"network": "regtest", "group": "shell-73c5da0a-84-1-1"}), "a wallet on a store that isn't one");
    assert!(whole >= u64::from(tip), "{whole}");
    assert_eq!(stored(), Some((tip, real())));

    // A store holding another chain, longer, so more work, as a regtest chain started over would
    // leave: it passes every check, but the server holds another block at 1, and it goes.
    let genesis = BNetwork::Regtest.checkpoint().header;
    let mut other = vec![mine(&genesis, genesis.time + 1, 0xee)];
    while other.len() < tip as usize + 500 {
        let prev = *other.last().unwrap();
        other.push(mine(&prev, prev.time + 1, 0xee));
    }
    let mut fake = HeaderChain::new(BNetwork::Regtest);
    fake.try_extend(0, &other, 2_000_000_000);
    SharedHeaders::open(&store, BNetwork::Regtest).unwrap().write(&fake).unwrap();
    assert_eq!(stored().map(|(h, _)| h), Some(tip + 500));
    let (_, disowned, _) = sync(json!({"network": "regtest", "group": "shell-73c5da0a-84-1-2"}), "a wallet on another chain's store");
    assert!(disowned >= u64::from(tip), "{disowned}");
    assert_eq!(stored(), Some((tip, real())), "the server's chain replaced it");
    assert!(t.alerts("suspect", "electrum-0") == 0, "the server was not blamed for the store");

    // The wallets that kept no headers of their own still open on the store, with nothing read.
    let (_, last, _) = sync(json!({"network": "regtest", "family": "bitcoin_taproot"}), "the second wallet again");
    assert_eq!(last, 0);
    t.engine.shutdown();
}
