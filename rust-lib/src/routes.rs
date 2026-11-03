//! Sources by role, from `bitcoin_node_module`'s `route_table(network)` or, on regtest, from
//! `regtest.json`. A source routed through Tor without a proxy is down, never reached directly.
//! The local node and Kyoto are chain authorities; servers serve the other roles.

use std::collections::BTreeMap;
use std::time::Duration;

use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;

use crate::network::RegtestConfig;
use crate::peers::{Listed, PeerSource};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Route {
    Tor,
    Direct,
    Onion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Electrum,
    Rpc,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub operator: String,
    pub route: Route,
    /// kyoto, electrum, rpc or local; read from the URL when absent.
    #[serde(default)]
    pub kind: Option<String>,
    /// The source needs credentials, fetched with the node module's source_credentials.
    #[serde(default)]
    pub credentials: bool,
    /// SHA-256 of an Electrum server's end-entity certificate, pinned in place of the CAs.
    #[serde(default)]
    pub cert_sha256: Option<String>,
    /// The person added this server; only such a server on their own network may be plain text.
    #[serde(default)]
    pub user_added: bool,
}

/// One reachable source with how to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub id: String,
    pub url: String,
    pub operator: String,
    pub route: Route,
    pub kind: Kind,
    /// Why it can't be used, if it can't: a Tor route with no proxy, a bad URL.
    pub down: Option<String>,
    pub credentials: bool,
    /// The pinned certificate's SHA-256, for an `ssl://` Electrum server.
    pub pin: Option<[u8; 32]>,
    /// False for plain text outside Tor: the app marks such a server as not encrypted.
    pub encrypted: bool,
}

/// Kyoto's peers and the one connection type its client uses for all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KyotoRoute {
    pub id: String,
    pub route: Route,
    /// `host:port` as the node module lists them: the curated subset, or the user's own peers.
    pub peers: Vec<String>,
    /// The same with where each came from and whether it connected before, when the node module
    /// keeps each peer's record and takes reports; `None` for plain `host:port` (regtest.json).
    pub listed: Option<Vec<Listed>>,
    /// Each peer's services as the table gives them: BIP324 to those with bit 11.
    pub services: BTreeMap<String, u64>,
    /// In `identifying`: the peers above serve headers and filters only, directly, and matched
    /// blocks and broadcasts go to these onion peers, one errand each.
    pub errands: Option<ErrandRoute>,
    pub down: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrandRoute {
    pub peers: Vec<String>,
    /// The longest random wait before a block's errand.
    pub max_delay: Duration,
}

/// The errands' wait at most: a direct peer and an onion peer seeing both sides can't easily
/// match a scan past a block with its fetch.
pub const ERRAND_MAX_DELAY: Duration = Duration::from_secs(60);

/// What goes through Tor, as the node module's `set_tor_use` stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TorUse {
    All,
    Identifying,
    None,
}

impl TorUse {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "all" => Some(TorUse::All),
            "identifying" => Some(TorUse::Identifying),
            "none" => Some(TorUse::None),
            _ => None,
        }
    }
}

/// A chain authority that can take a broadcast, in the order the route table gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    Local,
    Rpc,
    Kyoto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub host: String,
    pub port: u16,
}

impl Proxy {
    /// Only `socks5h://`: names resolve at the proxy.
    pub fn parse(url: &str) -> Result<Self, String> {
        let rest = url.trim().strip_prefix("socks5h://").ok_or("the proxy must be socks5h://host:port")?;
        let rest = rest.trim_end_matches('/');
        let (host, port) = rest.rsplit_once(':').ok_or("the proxy needs a port")?;
        let port = port.parse::<u16>().ok().filter(|p| *p != 0).ok_or("bad proxy port")?;
        if host.is_empty() {
            return Err("the proxy needs a host".into());
        }
        Ok(Self { host: host.trim_matches(['[', ']']).to_string(), port })
    }

    pub fn addr(&self) -> String {
        if self.host.contains(':') { format!("[{}]:{}", self.host, self.port) } else { format!("{}:{}", self.host, self.port) }
    }
}

/// SOCKS credentials per source, so Tor gives each its own circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Isolation {
    pub user: String,
    pub pass: String,
}

impl Isolation {
    pub fn fresh() -> Self {
        let mut b = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut b);
        Self { user: hex::encode(&b[..12]), pass: hex::encode(&b[12..]) }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Routes {
    pub proxy: Option<Proxy>,
    /// The local node enabled for the chain (`bitcoind_module`): the authority while it is synced.
    pub local: Option<String>,
    /// Remote Bitcoin Core, independent of the bundled node.
    pub rpc: Option<Source>,
    /// Kyoto enabled for the chain: the authority when the local node isn't.
    pub kyoto: Option<KyotoRoute>,
    /// Electrum servers for the header chain, used only when neither authority is enabled.
    pub chain: Vec<Source>,
    pub history: Vec<Source>,
    pub pending: Vec<Source>,
    /// The local node's estimatesmartfee is asked first.
    pub fees_local: bool,
    pub fees: Vec<Source>,
    /// The authorities enabled for broadcast, tried before `broadcast`'s servers.
    pub broadcast_by: Vec<Authority>,
    pub broadcast: Vec<Source>,
    pub check: Vec<Source>,
    /// Seconds between chain polls.
    pub poll_secs: u64,
    /// Kyoto's quorum on a test chain; the network's own elsewhere.
    pub kyoto_required: Option<u8>,
    /// As the table says; `none` drops the proxy, so nothing goes through Tor.
    pub tor_use: Option<TorUse>,
}

pub fn host_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?']).next()?;
    let host = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.ends_with(':') => h,
        _ => authority,
    };
    Some(host.trim_matches(['[', ']']))
}

pub fn is_onion(host: &str) -> bool {
    host.strip_suffix(".onion").is_some_and(|n| n.len() == 56 && n.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')))
}

pub(crate) fn is_loopback_or_lan(host: &str) -> bool {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            let [a, b, ..] = ip.octets();
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80,
        Err(_) => {
            let h = host.trim_end_matches('.').to_ascii_lowercase();
            h == "localhost" || [".local", ".lan", ".home.arpa", ".internal"].iter().any(|s| h.len() > s.len() && h.ends_with(s))
        }
    }
}

fn kind_of(url: &str) -> Option<Kind> {
    match url.split_once("://")?.0 {
        "tcp" | "ssl" => Some(Kind::Electrum),
        _ => None,
    }
}

/// TLS servers take a pin: `ssl://` Electrum, `https://` RPC.
fn pinnable(kind: Kind, url: &str) -> bool {
    matches!((kind, url.split_once("://").map(|(s, _)| s)), (Kind::Electrum, Some("ssl")) | (Kind::Rpc, Some("https")))
}

fn plaintext(url: &str) -> bool {
    url.starts_with("tcp://") || url.starts_with("http://")
}

/// A certificate pin as the node module stores it: 64 hex digits, colons allowed.
pub fn parse_pin(text: &str) -> Result<[u8; 32], String> {
    let digits: String = text.chars().filter(|c| *c != ':').collect();
    let mut pin = [0u8; 32];
    hex::decode_to_slice(digits.trim(), &mut pin).map_err(|_| "certSha256 must be the certificate's SHA-256 in hex".to_string())?;
    Ok(pin)
}

/// Decides whether and how an entry is reachable. Plain text crosses only Tor to an onion service
/// or the user's own network; everything else is TLS, checked against the CAs or a pinned certificate.
pub fn resolve(e: &Entry, proxy: Option<&Proxy>) -> Option<Source> {
    let kind = match e.kind.as_deref() {
        Some("electrum") => Kind::Electrum,
        Some("rpc") => Kind::Rpc,
        // Kyoto and the local node are authorities, read apart; an older node module's Esplora is gone.
        Some(_) => return None,
        None => kind_of(&e.url)?,
    };
    let host = host_of(&e.url).unwrap_or_default().to_string();
    let onion = is_onion(&host);
    let pin = e.cert_sha256.as_deref().filter(|p| !p.trim().is_empty()).map(parse_pin);
    let down = match e.route {
        Route::Tor | Route::Onion if proxy.is_none() => Some("routed through Tor, and no proxy is set".to_string()),
        Route::Onion if !onion => Some("an onion route needs an onion address".to_string()),
        Route::Direct if onion => Some("an onion service is reached through Tor only".to_string()),
        Route::Tor if plaintext(&e.url) && !onion => Some("a server reached through Tor must use TLS".to_string()),
        Route::Direct if plaintext(&e.url) && !is_loopback_or_lan(&host) => {
            Some("a server reached directly must use TLS unless it is on your own network".to_string())
        }
        Route::Direct if plaintext(&e.url) && !e.user_added => Some("plain text only to a server you added on your own network".to_string()),
        _ if host.is_empty() => Some("no host in the URL".to_string()),
        _ => match &pin {
            Some(Err(why)) => Some(why.clone()),
            Some(Ok(_)) if !pinnable(kind, &e.url) => Some("a pinned certificate is for an ssl:// Electrum or https:// RPC server".to_string()),
            _ => None,
        },
    };
    let pin = pin.and_then(Result::ok);
    let encrypted = !plaintext(&e.url) || onion;
    Some(Source { id: e.id.clone(), url: e.url.clone(), operator: e.operator.clone(), route: e.route, kind, down, credentials: e.credentials, pin, encrypted })
}

/// Kyoto's route: peers dialled directly, or all through Tor, never a mix (one connection type per client).
pub fn resolve_kyoto(id: &str, route: Route, peers: Vec<String>, proxy: Option<&Proxy>) -> KyotoRoute {
    let down = match route {
        Route::Tor | Route::Onion if proxy.is_none() => Some("routed through Tor, and no proxy is set".to_string()),
        _ if peers.is_empty() => Some("no peer to dial: the peer list is empty".to_string()),
        _ => None,
    };
    KyotoRoute { id: id.to_string(), route, peers, listed: None, services: BTreeMap::new(), errands: None, down }
}

/// Kyoto split for `identifying`: its route for headers and filters, and errands through Tor,
/// never direct, for the rest.
pub fn with_errands(mut k: KyotoRoute, errands: ErrandRoute, proxy: Option<&Proxy>) -> KyotoRoute {
    if k.down.is_none() {
        k.down = match () {
            _ if proxy.is_none() => Some("matched blocks go through Tor, and no proxy is set".to_string()),
            _ if errands.peers.is_empty() => Some("no onion peer for matched blocks".to_string()),
            _ => None,
        };
    }
    k.errands = Some(errands);
    k
}

/// Peers as dialled, with their records when the table has them, and their services.
type Peers = (Vec<String>, Option<Vec<Listed>>, BTreeMap<String, u64>);

/// The table's `peers`: `host:port`, or `{ peer, source, ok, services }` from a node module that
/// keeps each peer's record; services a decimal string or a number. A bad entry is skipped.
fn parse_peers(v: Option<&Value>) -> Peers {
    let Some(Value::Array(items)) = v else { return (vec![], None, BTreeMap::new()) };
    let mut listed = Vec::with_capacity(items.len());
    let mut services = BTreeMap::new();
    let mut records = false;
    for item in items {
        let entry = match item {
            Value::String(peer) => Some(Listed { peer: peer.clone(), source: PeerSource::List, ok: false, from: None }),
            Value::Object(o) => {
                records = true;
                o.get("peer").and_then(Value::as_str).map(|peer| {
                    let bits = match o.get("services") {
                        Some(Value::String(s)) => s.parse::<u64>().ok(),
                        Some(n) => n.as_u64(),
                        None => None,
                    };
                    if let Some(b) = bits {
                        services.insert(peer.to_string(), b);
                    }
                    Listed {
                        peer: peer.to_string(),
                        source: PeerSource::parse(o.get("source").and_then(Value::as_str).unwrap_or("list")),
                        ok: o.get("ok").and_then(Value::as_bool).unwrap_or(false),
                        from: None,
                    }
                })
            }
            _ => None,
        };
        match entry {
            Some(e) => listed.push(e),
            None => tracing::warn!(target: "bitcoin", "route_table.peers: skipped {item}"),
        }
    }
    (listed.iter().map(|l| l.peer.clone()).collect(), records.then_some(listed), services)
}

/// `kyotoSplit`: `{ chain: { route, peers }, tor: { route: onion, peers } }`, beside the all-Tor
/// entry an older core reads.
fn parse_split(v: &Value) -> Option<(Route, Peers, Vec<String>)> {
    let route: Route = serde_json::from_value(v["chain"]["route"].clone()).ok()?;
    let chain = parse_peers(v["chain"].get("peers"));
    let (tor, _, _) = parse_peers(v["tor"].get("peers"));
    Some((route, chain, tor))
}

impl Routes {
    /// Parses a `route_table` reply: the local node and Kyoto by kind, servers by URL.
    pub fn from_table(reply: &str) -> Result<Self, String> {
        let v: Value = serde_json::from_str(reply).map_err(|e| format!("route_table: {e}"))?;
        if v.get("ok").is_some_and(|ok| ok == false) {
            return Err(v["error"].as_str().unwrap_or("route_table refused").to_string());
        }
        let tor_use = v["torUse"].as_str().and_then(TorUse::parse);
        let proxy = match v["proxy"].as_str().map(str::trim).filter(|s| !s.is_empty() && *s != "direct" && tor_use != Some(TorUse::None)) {
            Some(p) => Some(Proxy::parse(p)?),
            None => None,
        };
        let entries = |name: &str| -> Result<Vec<Entry>, String> {
            match v.get(name) {
                Some(Value::Array(_)) => serde_json::from_value(v[name].clone()).map_err(|e| format!("route_table.{name}: {e}")),
                _ => Ok(vec![]),
            }
        };
        let servers = |name: &str| -> Result<Vec<Source>, String> { Ok(entries(name)?.iter().filter_map(|e| resolve(e, proxy.as_ref())).filter(|s| s.kind != Kind::Rpc).collect()) };
        let kind = |e: &Entry, k: &str| e.kind.as_deref() == Some(k);
        let chain = entries("chain")?;
        let (peers, listed, services) = parse_peers(v.get("peers"));
        let split = v.get("kyotoSplit").filter(|_| tor_use != Some(TorUse::None)).and_then(parse_split);
        let kyoto = chain.iter().find(|e| kind(e, "kyoto")).map(|e| match &split {
            Some((route, (peers, listed, services), tor)) => {
                let k = KyotoRoute { listed: listed.clone(), services: services.clone(), ..resolve_kyoto(&e.id, *route, peers.clone(), proxy.as_ref()) };
                with_errands(k, ErrandRoute { peers: tor.clone(), max_delay: ERRAND_MAX_DELAY }, proxy.as_ref())
            }
            None => KyotoRoute { listed: listed.clone(), services: services.clone(), ..resolve_kyoto(&e.id, e.route, peers.clone(), proxy.as_ref()) },
        });
        let local = chain.iter().find(|e| kind(e, "local")).map(|e| e.id.clone());
        let rpc = chain.iter().find(|e| kind(e, "rpc")).and_then(|e| resolve(e, proxy.as_ref()));
        let broadcast_by = entries("broadcast")?
            .iter()
            .filter_map(|e| match e.kind.as_deref() {
                Some("local") => Some(Authority::Local),
                Some("rpc") => Some(Authority::Rpc),
                Some("kyoto") => Some(Authority::Kyoto),
                _ => None,
            })
            .collect();
        let authority = kyoto.is_some() || local.is_some() || rpc.is_some();
        Ok(Routes {
            chain: if authority { vec![] } else { chain.iter().filter_map(|e| resolve(e, proxy.as_ref())).filter(|s| s.kind == Kind::Electrum).collect() },
            local,
            rpc,
            kyoto,
            history: servers("history")?,
            pending: servers("pending")?,
            fees_local: entries("fees")?.iter().any(|e| kind(e, "local")),
            fees: servers("fees")?,
            broadcast_by,
            broadcast: servers("broadcast")?,
            check: servers("check")?,
            poll_secs: 30,
            kyoto_required: None,
            tor_use,
            proxy,
        })
    }

    /// A local test chain: its loopback servers fill every role, reached directly; the local node
    /// and Kyoto's peers, when configured, are the authorities.
    pub fn regtest(cfg: &RegtestConfig) -> Self {
        let mut all = vec![];
        // A test chain's servers are the harness's own.
        let entry = |id: String, url: &str, operator: String| Entry { id, url: url.to_string(), operator, route: Route::Direct, kind: None, credentials: false, cert_sha256: None, user_added: true };
        for (i, url) in cfg.electrum.iter().enumerate() {
            all.push(entry(format!("electrum-{i}"), url, format!("regtest-{i}")));
        }
        let sources: Vec<Source> = all.iter().filter_map(|e| resolve(e, None)).collect();
        let tor_use = cfg.tor_use.as_deref().and_then(TorUse::parse);
        let proxy = cfg.proxy.as_deref().filter(|_| tor_use != Some(TorUse::None)).and_then(|p| Proxy::parse(p).ok());
        let kyoto = (!cfg.kyoto.is_empty()).then(|| {
            let k = resolve_kyoto("kyoto", Route::Direct, cfg.kyoto.clone(), None);
            match cfg.kyoto_tor.is_empty() || tor_use == Some(TorUse::None) {
                true => k,
                false => with_errands(k, ErrandRoute { peers: cfg.kyoto_tor.clone(), max_delay: Duration::from_millis(cfg.errand_delay_ms.unwrap_or(0)) }, proxy.as_ref()),
            }
        });
        let local = cfg.local.then(|| "local".to_string());
        let mut broadcast_by = vec![];
        if local.is_some() {
            broadcast_by.push(Authority::Local);
        }
        if kyoto.is_some() {
            broadcast_by.push(Authority::Kyoto);
        }
        let authority = kyoto.is_some() || local.is_some();
        let syncing = if cfg.check_only { vec![] } else { sources.clone() };
        Routes {
            proxy,
            tor_use,
            chain: if authority { vec![] } else { sources.iter().filter(|s| s.kind == Kind::Electrum).cloned().collect() },
            fees_local: local.is_some(),
            local,
            rpc: None,
            kyoto,
            history: syncing.clone(),
            pending: syncing.clone(),
            fees: sources.clone(),
            broadcast_by,
            broadcast: syncing,
            check: sources.clone(),
            poll_secs: cfg.poll_secs.unwrap_or(1),
            kyoto_required: cfg.kyoto_required,
        }
    }

    /// Whether the table routes anything: a server, Kyoto or the local node.
    pub fn has_entries(&self) -> bool {
        !self.every().is_empty() || self.kyoto.is_some() || self.local.is_some() || self.rpc.is_some()
    }

    /// Regtest: the node module's table when it holds entries, with regtest.json's poll and
    /// quorum; regtest.json's own servers when it holds none.
    pub fn for_regtest(table: Option<Routes>, cfg: Option<&RegtestConfig>) -> Routes {
        match table.filter(Routes::has_entries) {
            Some(mut r) => {
                if let Some(c) = cfg {
                    r.poll_secs = c.poll_secs.unwrap_or(1);
                    r.kyoto_required = c.kyoto_required.or(r.kyoto_required);
                }
                r
            }
            None => cfg.map(Routes::regtest).unwrap_or_default(),
        }
    }

    pub fn every(&self) -> Vec<&Source> {
        let mut seen = std::collections::BTreeSet::new();
        [&self.chain, &self.history, &self.pending, &self.fees, &self.broadcast, &self.check]
            .into_iter()
            .flatten()
            .chain(self.rpc.iter())
            .filter(|s| seen.insert(s.id.clone()))
            .collect()
    }

    pub fn roles_of(&self, id: &str) -> Vec<&'static str> {
        if self.rpc.as_ref().is_some_and(|s| s.id == id) { return vec!["chain", "history", "pending", "fees", "broadcast"]; }
        [("chain", &self.chain), ("history", &self.history), ("pending", &self.pending), ("fees", &self.fees), ("broadcast", &self.broadcast), ("check", &self.check)]
            .into_iter()
            .filter(|(_, l)| l.iter().any(|s| s.id == id))
            .map(|(n, _)| n)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn onion() -> String {
        format!("{}.onion", "a2".repeat(28))
    }

    fn table(proxy: Option<&str>) -> String {
        let e = |id: &str, url: String, route: &str| json!({"id": id, "url": url, "operator": "op", "route": route});
        json!({
            "ok": true,
            "proxy": proxy,
            "chain": [e("a", "ssl://electrum.example:50002".into(), "tor"), {"id": "kyoto", "kind": "kyoto", "url": "", "operator": "kyoto", "route": "onion"}],
            "peers": [format!("{}:8333", onion())],
            "history": [e("a", "ssl://electrum.example:50002".into(), "tor"), e("o", format!("tcp://{}:50001", onion()), "onion")],
            "fees": [e("f", "ssl://fees.example:50002".into(), "tor")],
            "broadcast": [e("a", "ssl://electrum.example:50002".into(), "tor")],
            "check": [{"id": "l", "url": "tcp://192.168.1.20:50001", "operator": "op", "route": "direct", "userAdded": true},
                      e("d", "tcp://192.168.1.21:50001".into(), "direct")],
        })
        .to_string()
    }

    #[test]
    fn a_table_with_a_proxy_routes_through_tor() {
        let r = Routes::from_table(&table(Some("socks5h://127.0.0.1:9050"))).unwrap();
        assert_eq!(r.proxy, Some(Proxy { host: "127.0.0.1".into(), port: 9050 }));
        assert!(r.chain.is_empty(), "Kyoto holds the chain, not the server");
        let k = r.kyoto.clone().unwrap();
        assert_eq!((k.route, k.peers.len(), k.down), (Route::Onion, 1, None));
        assert!(r.history.iter().all(|s| s.down.is_none()));
        assert_eq!(r.history[1].kind, Kind::Electrum);
        assert_eq!(r.fees[0].kind, Kind::Electrum);
        assert_eq!(r.roles_of("a"), vec!["history", "broadcast"]);
        assert_eq!(r.every().len(), 5);
    }

    fn split(proxy: Option<&str>, tor_use: &str) -> Routes {
        let mut t: Value = serde_json::from_str(&table(proxy)).unwrap();
        t["torUse"] = json!(tor_use);
        t["kyotoSplit"] = json!({
            "chain": {"route": "direct", "peers": [{"peer": "203.0.113.7:8333", "source": "list", "ok": true, "services": "3145"},
                                                   {"peer": "[2001:db8::7]:8333", "source": "seed", "ok": false, "services": 1097}]},
            "tor": {"route": "onion", "peers": [{"peer": format!("{}:8333", onion()), "source": "list", "ok": true}]},
        });
        Routes::from_table(&t.to_string()).unwrap()
    }

    #[test]
    fn identifying_splits_kyoto_and_none_drops_tor() {
        let r = split(Some("socks5h://127.0.0.1:9050"), "identifying");
        assert_eq!(r.tor_use, Some(TorUse::Identifying));
        let k = r.kyoto.unwrap();
        assert_eq!((k.route, k.peers.clone(), k.down), (Route::Direct, vec!["203.0.113.7:8333".to_string(), "[2001:db8::7]:8333".to_string()], None));
        assert_eq!((k.services["203.0.113.7:8333"], k.services["[2001:db8::7]:8333"]), (3145, 1097), "services as a string or a number");
        assert_eq!(k.listed.unwrap()[1].source, PeerSource::Seed);
        assert_eq!(k.errands, Some(ErrandRoute { peers: vec![format!("{}:8333", onion())], max_delay: ERRAND_MAX_DELAY }));

        // No proxy: the split waits for Tor, never dials only half of it.
        let k = split(None, "identifying").kyoto.unwrap();
        assert_eq!(k.down.as_deref(), Some("matched blocks go through Tor, and no proxy is set"));

        // `none`: no proxy whatever the table says, and the all-Tor entry with it.
        let r = split(Some("socks5h://127.0.0.1:9050"), "none");
        assert_eq!((r.proxy.clone(), r.tor_use), (None, Some(TorUse::None)));
        let k = r.kyoto.unwrap();
        assert_eq!((k.route, k.errands, k.down.as_deref()), (Route::Onion, None, Some("routed through Tor, and no proxy is set")));

        // A table without the keys, from an older node module: all-Tor as before.
        let r = Routes::from_table(&table(Some("socks5h://127.0.0.1:9050"))).unwrap();
        assert_eq!((r.tor_use, r.kyoto.unwrap().errands), (None, None));
    }

    #[test]
    fn without_a_proxy_tor_routes_fail_closed() {
        let r = Routes::from_table(&table(None)).unwrap();
        assert!(r.history.iter().all(|s| s.down.as_deref() == Some("routed through Tor, and no proxy is set")));
        assert!(r.check[0].down.is_none(), "the user's own network needs no proxy");
        assert!(!r.check[0].encrypted && r.check[1].down.as_deref().is_some_and(|d| d.contains("you added")), "plain text only to the user's own");
        assert!(Routes::from_table(&json!({"proxy": "socks5://127.0.0.1:9050"}).to_string()).is_err(), "names must resolve at the proxy");
        assert!(Routes::from_table(&json!({"ok": false, "error": "not authorized"}).to_string()).is_err());
    }

    #[test]
    fn plain_text_only_to_onions_and_our_own_network() {
        let p = Proxy::parse("socks5h://127.0.0.1:9050").unwrap();
        let e = |url: &str, route| Entry { id: "x".into(), url: url.into(), operator: String::new(), route, kind: None, credentials: false, cert_sha256: None, user_added: true };
        assert!(resolve(&e("tcp://electrum.example:50001", Route::Tor), Some(&p)).unwrap().down.is_some());
        assert!(resolve(&e("tcp://electrum.example:50001", Route::Direct), None).unwrap().down.is_some());
        assert!(resolve(&e("tcp://127.0.0.1:60401", Route::Direct), None).unwrap().down.is_none());
        assert!(resolve(&Entry { kind: Some("rpc".into()), ..e("http://nas.local:8332", Route::Direct) }, None).unwrap().down.is_none());
        assert!(resolve(&e("ssl://electrum.example:50002", Route::Direct), None).unwrap().down.is_none(), "the user's choice, with TLS");
        let o = format!("tcp://{}:50001", onion());
        assert!(resolve(&e(&o, Route::Direct), None).unwrap().down.is_some());
        assert!(resolve(&e(&o, Route::Onion), Some(&p)).unwrap().down.is_none());
        assert!(resolve(&e("ssl://electrum.example:50002", Route::Onion), Some(&p)).unwrap().down.is_some());
        assert!(resolve(&e("ftp://x", Route::Direct), None).is_none());
        assert_eq!(host_of("ssl://[fd00::2]:50002"), Some("fd00::2"));
        assert_eq!(host_of("https://rpc.example/api"), Some("rpc.example"));
    }

    #[test]
    fn the_node_modules_table_reads_whole() {
        // bitcoin_node_module's route_table: kinds named, Kyoto in the chain, an older module's Esplora left out.
        let reply = json!({"ok": true, "network": "signet", "proxy": "socks5h://127.0.0.1:9050",
            "chain": [{"id": "kyoto", "kind": "kyoto", "url": "", "operator": "kyoto", "route": "onion"}],
            "history": [{"id": "x", "kind": "esplora", "url": "https://esplora.example/api", "operator": "esplora.example", "route": "tor", "credentials": true},
                        {"id": "e1", "kind": "electrum", "url": "ssl://electrum.example.com:50002", "operator": "example.com", "route": "tor"}],
            "pending": [], "fees": [{"id": "e1", "kind": "electrum", "url": "ssl://electrum.example.com:50002", "operator": "example.com", "route": "tor"}],
            "broadcast": [], "check": [], "peers": ["a.onion:38333"], "unrouted": []})
        .to_string();
        let r = Routes::from_table(&reply).unwrap();
        assert!(r.chain.is_empty() && r.local.is_none());
        assert_eq!(r.kyoto.as_ref().map(|k| k.peers.clone()), Some(vec!["a.onion:38333".to_string()]));
        assert_eq!(r.kyoto.as_ref().unwrap().listed, None, "plain host:port: the core keeps the old rules");
        assert_eq!(r.history.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), vec!["e1"]);
        assert_eq!(r.fees[0].kind, Kind::Electrum);
    }

    #[test]
    fn peers_with_their_records_say_where_each_came_from() {
        let reply = json!({"ok": true, "proxy": "socks5h://127.0.0.1:9050",
            "chain": [{"id": "kyoto", "kind": "kyoto", "url": "", "operator": "peers", "route": "onion"}],
            "peers": [{"peer": "a.onion:8333", "source": "list", "ok": true}, {"peer": "b.onion:8333", "source": "learned", "ok": false},
                {"peer": "[fd00::2]:8333", "source": "own", "ok": false}, {"peer": "c.onion:8333", "source": "something new"},
                {"source": "list"}, 7]})
        .to_string();
        let k = Routes::from_table(&reply).unwrap().kyoto.unwrap();
        assert_eq!(k.peers, vec!["a.onion:8333", "b.onion:8333", "[fd00::2]:8333", "c.onion:8333"], "bad entries skipped");
        let l = k.listed.unwrap();
        assert_eq!((l[0].source, l[0].ok), (PeerSource::List, true));
        assert_eq!((l[1].source, l[1].ok), (PeerSource::Learned, false));
        assert_eq!((l[2].source, l[3].source), (PeerSource::Own, PeerSource::Seed), "an unknown source counts as a seed");
    }

    #[test]
    fn the_local_node_comes_before_kyoto() {
        let local = json!({"id": "local", "kind": "local", "url": "logos://bitcoind_module", "operator": "local", "route": "direct"});
        let kyoto = json!({"id": "kyoto", "kind": "kyoto", "url": "p2p://peer-list", "operator": "peers", "route": "direct"});
        let reply = json!({"ok": true, "proxy": null, "chain": [local, kyoto], "broadcast": [local, kyoto], "fees": [local],
            "history": [local, kyoto], "peers": ["192.168.1.20:8333"]})
        .to_string();
        let r = Routes::from_table(&reply).unwrap();
        assert_eq!(r.local.as_deref(), Some("local"));
        assert_eq!(r.broadcast_by, vec![Authority::Local, Authority::Kyoto]);
        assert!(r.fees_local && r.history.is_empty() && r.chain.is_empty());
        assert_eq!(r.kyoto.unwrap().down, None, "the user's own network needs no proxy");
        // Tor routes without a proxy fail closed, and an empty list has no one to dial.
        assert!(resolve_kyoto("kyoto", Route::Tor, vec!["a:1".into()], None).down.is_some());
        assert!(resolve_kyoto("kyoto", Route::Direct, vec![], None).down.is_some());
    }

    #[test]
    fn plain_text_only_to_a_server_the_person_added() {
        let e = |url: &str, user_added| Entry { id: "x".into(), url: url.into(), operator: String::new(), route: Route::Direct, kind: None, credentials: false, cert_sha256: None, user_added };
        let added = resolve(&e("tcp://192.168.1.5:50001", true), None).unwrap();
        assert_eq!((added.down, added.encrypted), (None, false), "the app marks it not encrypted");
        assert!(resolve(&e("tcp://192.168.1.5:50001", false), None).unwrap().down.unwrap().contains("you added"));
        assert!(resolve(&Entry { kind: Some("rpc".into()), ..e("http://nas.local:8332", false) }, None).unwrap().down.is_some(), "not a default nor a listed one");
        assert!(resolve(&e("ssl://192.168.1.5:50002", false), None).unwrap().encrypted);
        let p = Proxy::parse("socks5h://127.0.0.1:9050").unwrap();
        let onion = Entry { route: Route::Onion, ..e(&format!("tcp://{}:50001", onion()), false) };
        let o = resolve(&onion, Some(&p)).unwrap();
        assert_eq!((o.down, o.encrypted), (None, true), "Tor encrypts to an onion service");
    }

    #[test]
    fn certificate_pins() {
        let pin = "AB:".repeat(31) + "AB";
        let e = |url: &str, pin: &str| Entry { id: "x".into(), url: url.into(), operator: String::new(), route: Route::Direct, kind: None, credentials: false, cert_sha256: Some(pin.into()), user_added: true };
        let ok = resolve(&e("ssl://192.168.1.5:50002", &pin), None).unwrap();
        assert_eq!((ok.pin, ok.down), (Some([0xab; 32]), None));
        assert!(resolve(&e("tcp://192.168.1.5:50001", &pin), None).unwrap().down.unwrap().contains("ssl://"));
        let rpc = |url: &str| Entry { kind: Some("rpc".into()), ..e(url, &pin) };
        let ok = resolve(&rpc("https://192.168.1.5/api"), None).unwrap();
        assert_eq!((ok.pin, ok.down), (Some([0xab; 32]), None), "an https:// RPC server takes a pin");
        assert!(resolve(&rpc("http://192.168.1.5/api"), None).unwrap().down.unwrap().contains("https://"), "not plain http");
        assert!(resolve(&e("https://192.168.1.5/api", &pin), None).is_none(), "https:// alone was Esplora's");
        assert!(resolve(&e("ssl://192.168.1.5:50002", "abcd"), None).unwrap().down.unwrap().contains("hex"));
        assert_eq!(resolve(&e("ssl://192.168.1.5:50002", ""), None).unwrap().pin, None, "an empty pin is none");
    }

    #[test]
    fn regtest_takes_the_node_modules_routes_when_it_has_any() {
        let cfg = RegtestConfig { electrum: vec!["tcp://127.0.0.1:60601".into()], poll_secs: Some(1), kyoto_required: Some(3), ..Default::default() };
        let table = Routes::from_table(&table(None)).unwrap();
        let r = Routes::for_regtest(Some(table), Some(&cfg));
        assert_eq!((r.kyoto.is_some(), r.poll_secs, r.kyoto_required), (true, 1, Some(3)), "the table, regtest.json's poll and quorum");
        let empty = Routes::from_table(&json!({"ok": true, "proxy": null}).to_string()).unwrap();
        assert!(!empty.has_entries());
        let r = Routes::for_regtest(Some(empty), Some(&cfg));
        assert_eq!(r.chain[0].url, "tcp://127.0.0.1:60601", "nothing routed: regtest.json's servers");
        assert_eq!(Routes::for_regtest(None, Some(&cfg)).history.len(), 1);
    }

    #[test]
    fn regtest_fills_every_role_directly() {
        let r = Routes::regtest(&RegtestConfig { electrum: vec!["tcp://127.0.0.1:60401".into(), "tcp://127.0.0.1:60411".into()], ..Default::default() });
        assert_eq!((r.chain.len(), r.history.len(), r.broadcast.len()), (2, 2, 2));
        assert!(r.history.iter().all(|s| s.route == Route::Direct && s.down.is_none()));
        assert_eq!(r.poll_secs, 1);
        assert_ne!(Isolation::fresh(), Isolation::fresh());
    }
}

#[cfg(test)]
mod rpc_tests {
    use super::*;
    #[test]
    fn rpc_is_never_asked_for_addresses() {
        let e=serde_json::json!({"id":"rpc","kind":"rpc","url":"https://rpc.example","route":"direct"});
        let r=Routes::from_table(&serde_json::json!({"chain":[e],"history":[e],"pending":[e],"fees":[e],"broadcast":[e],"check":[e]}).to_string()).unwrap();
        assert_eq!(r.rpc.as_ref().unwrap().kind,Kind::Rpc);
        assert!(r.history.is_empty() && r.pending.is_empty() && r.fees.is_empty() && r.check.is_empty());
        assert_eq!(r.broadcast_by,vec![Authority::Rpc]);
        assert_eq!(r.every().len(),1);
    }
}
