//! Full engine integration over HTTP Core RPC, with credentials and no Electrum server.
mod common;
use bitcoin_wallet_core::{
    engine::Engine,
    network::{configure_regtest, RegtestConfig},
    routes::Routes,
    sync::RouteSource,
};
use common::{collecting, MockManager, T};
use serde_json::json;
use std::{sync::Arc, time::Duration};
struct Config {
    table: String,
    credentials: (String, String),
}
impl RouteSource for Config {
    fn route_table(&self, _: &str) -> Result<String, String> {
        Ok(self.table.clone())
    }
    fn source_credentials(&self, _: &str, _: &str) -> Result<Option<(String, String)>, String> {
        Ok(Some(self.credentials.clone()))
    }
}
#[test]
#[ignore]
fn remote_core_receives_restores_and_broadcasts() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::INFO)
        .try_init();
    let (rpc, cookie) = common::chain_env().expect("isolated regtest node required");
    configure_regtest(RegtestConfig::default());
    let creds = cookie.trim().split_once(':').unwrap();
    let entry = json!({"id":"remote-core","kind":"rpc","url":rpc,"route":"direct","credentials":true,"userAdded":true});
    let table=json!({"chain":[entry],"history":[entry],"pending":[entry],"fees":[entry],"broadcast":[entry]}).to_string();
    let config = Arc::new(Config {
        table: table.clone(),
        credentials: (creds.0.into(), creds.1.into()),
    });
    let manager = Arc::new(MockManager::new(Duration::from_millis(20)));
    let root = tempfile::tempdir().unwrap();
    let make = |folder: &str| {
        let (sink, events) = collecting();
        let engine = Engine::new(
            root.path().join(folder),
            sink,
            manager.clone(),
            Some(config.clone()),
        );
        let mut routes = Routes::from_table(&table).unwrap();
        routes.poll_secs = 1;
        engine.set_regtest_routes(routes);
        T {
            engine,
            rpc: rpc.clone(),
            cookie: cookie.clone(),
            events,
            manager: manager.clone(),
        }
    };
    let t = make("first");
    t.job(
        "open_wallet",
        json!({"network":"regtest","family":"bitcoin"}),
    );
    t.synced();
    assert_eq!(t.engine.status()["authority"]["kind"], "rpc_node");
    let address = t.engine.next_address()["address"]
        .as_str()
        .unwrap()
        .to_string();
    let incoming = t.fund(&address, 0.5);
    t.wait("unconfirmed RPC payment", 30, || {
        t.row(&incoming.to_string()) != serde_json::Value::Null
    });
    t.mine(1);
    t.synced();
    let expected_filters = std::env::var("RPC_TEST_FILTERS").unwrap_or_else(|_| "1".into()) != "0";
    assert_eq!(t.engine.status()["node"]["filters"], expected_filters);
    assert_eq!(t.engine.history(0)["total"], 1);
    t.job("close_wallet", json!({}));
    let restored = make("restored");
    restored.job(
        "open_wallet",
        json!({"network":"regtest","family":"bitcoin","birthday":0}),
    );
    restored.synced();
    assert_eq!(
        restored.engine.history(0)["total"],
        1,
        "restore discovers the payment"
    );
    let dest = restored
        .wallet_rpc("getnewaddress", json!(["recipient"]))
        .as_str()
        .unwrap()
        .to_string();
    let preview = restored.job(
        "build_send",
        json!({"recipients":[{"address":dest,"amountSat":"10000000"}],"feeRate":2.0}),
    );
    let sent = restored.sign(preview["previewId"].as_str().unwrap());
    assert_eq!(sent["via"], "remote-core");
    assert_eq!(sent["broadcast"], "seen");
    restored.mine(1);
    restored.synced();
    assert_eq!(restored.engine.history(0)["total"], 2);
    restored.job("close_wallet", json!({}));
}

/// Your node at an address, with an Electrum server listed beside it in every role as an older
/// node module did: the server is never dialled, for fees, tips, headers or history.
#[test]
#[ignore]
fn your_node_alone_dials_no_electrum_server() {
    let _ = tracing_subscriber::fmt().with_test_writer().with_max_level(tracing::Level::INFO).try_init();
    let (rpc, cookie) = common::chain_env().expect("isolated regtest node required");
    configure_regtest(RegtestConfig::default());
    let creds = cookie.trim().split_once(':').unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let node = json!({"id":"remote-core","kind":"rpc","url":rpc,"route":"direct","credentials":true,"userAdded":true});
    let server = json!({"id":"home","kind":"electrum","url":format!("tcp://{}", listener.local_addr().unwrap()),"route":"direct","userAdded":true});
    let both = json!([node, server]);
    let table = json!({"chain":both,"history":both,"pending":both,"fees":both,"broadcast":both,"check":[server]}).to_string();
    let config = Arc::new(Config { table: table.clone(), credentials: (creds.0.into(), creds.1.into()) });
    let manager = Arc::new(MockManager::new(Duration::from_millis(20)));
    let root = tempfile::tempdir().unwrap();
    let (sink, events) = collecting();
    let engine = Engine::new(root.path().join("alone"), sink, manager.clone(), Some(config));
    let mut routes = Routes::from_table(&table).unwrap();
    routes.poll_secs = 1;
    engine.set_regtest_routes(routes);
    let t = T { engine, rpc, cookie, events, manager };
    t.job("open_wallet", json!({"network":"regtest","family":"bitcoin"}));
    t.synced();
    assert_eq!(t.engine.status()["authority"]["kind"], "rpc_node");
    let address = t.engine.next_address()["address"].as_str().unwrap().to_string();
    let incoming = t.fund(&address, 0.5);
    t.wait("unconfirmed payment from the node", 30, || t.row(&incoming.to_string()) != serde_json::Value::Null);
    t.mine(1);
    t.synced();
    // Fees ran at open and the tip watch on each new block; give a few more rounds.
    std::thread::sleep(Duration::from_secs(5));
    let dialled = listener.accept().map(|(_, from)| from.to_string());
    assert!(matches!(&dialled, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock), "the Electrum server was dialled: {dialled:?}");
    let fees = t.engine.fee_rates_json();
    assert!(!fees.to_string().contains("\"home\""), "fees from the server: {fees}");
    // The seed is the mock's, so earlier tests on this chain may have paid it too.
    assert_ne!(t.row(&incoming.to_string()), serde_json::Value::Null);
    t.job("close_wallet", json!({}));
}
