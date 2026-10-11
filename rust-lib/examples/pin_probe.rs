//! Reads an Electrum server's certificate pin over Tor, then connects with it and asks the tip:
//!   pin_probe <socks5h://proxy:port> <ssl://host:port>
use std::time::Duration;

use bdk_electrum::electrum_client::ElectrumApi;
use bitcoin_wallet_core::pin;
use bitcoin_wallet_core::routes::{Isolation, Proxy};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, proxy, url] = args.as_slice() else {
        eprintln!("usage: pin_probe <socks5h://proxy:port> <ssl://host:port>");
        std::process::exit(2);
    };
    let proxy = Proxy::parse(proxy).expect("proxy");
    let t = Duration::from_secs(60);
    let pin = pin::certificate_sha256(url, Some((&proxy, &Isolation::fresh())), t).unwrap_or_else(|e| panic!("{url}: {e}"));
    println!("{url}: certSha256 {}", hex::encode(pin));
    let c = pin::connect(url, pin, Some((&proxy, &Isolation::fresh())), t).unwrap_or_else(|e| panic!("{url}: pinned: {e}"));
    let tip = c.block_headers_subscribe().expect("tip");
    println!("{url}: pinned connection, tip {} {}", tip.height, tip.header.block_hash());
    let wrong = pin::connect(url, [0u8; 32], Some((&proxy, &Isolation::fresh())), t).err().unwrap_or_default();
    println!("{url}: another pin: {wrong}");
}
