//! The server-only authority from the checkpoint to the tip against live Electrum servers, headers only:
//! `--example authority -- mainnet socks5h://127.0.0.1:9050 ssl://electrum.blockstream.info:50002`

use std::time::Instant;

use bitcoin_wallet_core::authority::{Authority, ElectrumHeaders, HeaderSource, ServerAuthority};
use bitcoin_wallet_core::checks::ChainView;
use bitcoin_wallet_core::net;
use bitcoin_wallet_core::network::BNetwork;
use bitcoin_wallet_core::routes::{Isolation, Kind, Proxy, Route, Source};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert!(args.len() >= 3, "usage: authority <network> <socks5h://host:port|direct> <server>...");
    let net = BNetwork::parse(&args[0]).expect("mainnet, testnet4 or signet");
    let proxy = (args[1] != "direct").then(|| Proxy::parse(&args[1]).expect("proxy"));
    let route = if proxy.is_some() { Route::Tor } else { Route::Direct };
    let t0 = Instant::now();
    let mut clients = vec![];
    for (i, url) in args[2..].iter().enumerate() {
        let s = Source { id: format!("s{i}:{url}"), url: url.clone(), operator: String::new(), route, kind: Kind::Electrum, down: None, credentials: false };
        match net::electrum(&s, proxy.as_ref(), &Isolation::fresh()) {
            Ok(c) => clients.push((s.id, c)),
            Err(e) => println!("{e}"),
        }
    }
    println!("{} ms: connected to {} of {}", t0.elapsed().as_millis(), clients.len(), args.len() - 2);
    let mut a = ServerAuthority::new(net);
    let base = a.base_height();
    let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
    loop {
        let adapters: Vec<ElectrumHeaders<'_, _>> = clients.iter().map(|(id, c)| ElectrumHeaders { id: id.as_str(), client: c }).collect();
        let dyns: Vec<&dyn HeaderSource> = adapters.iter().map(|x| x as &dyn HeaderSource).collect();
        let c = a.refresh(&dyns, now());
        println!(
            "{} ms: tip {:?}, moved {}, agreeing {:?}, suspects {:?}, failures {:?}",
            t0.elapsed().as_millis(), a.tip_height(), c.tip_moved, c.agreeing, c.suspects, c.failures
        );
        if !c.tip_moved || !c.suspects.is_empty() {
            break;
        }
    }
    let s = a.summary(now() as u64);
    println!(
        "{}: {} headers from checkpoint {base} to {:?} ({}), tip {}s old, in {} ms",
        net.name(), s.height.unwrap_or(base) - base, s.height, s.hash.unwrap_or_default(), s.tip_age_secs.unwrap_or(0), t0.elapsed().as_millis()
    );
}
