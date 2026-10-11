//! Sources by role, from `bitcoin_node_module`'s `route_table(network)` or, on regtest, from
//! `regtest.json`. A source routed through Tor without a proxy is down, never reached directly.

use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;

use crate::network::RegtestConfig;

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
    Esplora,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub url: String,
    #[serde(default)]
    pub operator: String,
    pub route: Route,
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
    pub chain: Vec<Source>,
    pub history: Vec<Source>,
    pub pending: Vec<Source>,
    pub fees: Vec<Source>,
    pub broadcast: Vec<Source>,
    pub check: Vec<Source>,
    /// A second operator is enabled.
    pub cross_check: bool,
    /// Seconds between chain polls.
    pub poll_secs: u64,
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

fn is_loopback_or_lan(host: &str) -> bool {
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
        "http" | "https" => Some(Kind::Esplora),
        _ => None,
    }
}

fn plaintext(url: &str) -> bool {
    url.starts_with("tcp://") || url.starts_with("http://")
}

/// Decides whether and how an entry is reachable. Plain text crosses only Tor to an onion service
/// or the user's own network; everything else is TLS.
pub fn resolve(e: &Entry, proxy: Option<&Proxy>) -> Option<Source> {
    let kind = kind_of(&e.url)?;
    let host = host_of(&e.url).unwrap_or_default().to_string();
    let onion = is_onion(&host);
    let down = match e.route {
        Route::Tor | Route::Onion if proxy.is_none() => Some("routed through Tor, and no proxy is set".to_string()),
        Route::Onion if !onion => Some("an onion route needs an onion address".to_string()),
        Route::Direct if onion => Some("an onion service is reached through Tor only".to_string()),
        Route::Tor if plaintext(&e.url) && !onion => Some("a server reached through Tor must use TLS".to_string()),
        Route::Direct if plaintext(&e.url) && !is_loopback_or_lan(&host) => {
            Some("a server reached directly must use TLS unless it is on your own network".to_string())
        }
        _ if host.is_empty() => Some("no host in the URL".to_string()),
        _ => None,
    };
    Some(Source { id: e.id.clone(), url: e.url.clone(), operator: e.operator.clone(), route: e.route, kind, down })
}

impl Routes {
    /// Parses a `route_table` reply. Entries of kinds this pass doesn't speak (Kyoto, the local
    /// node) are skipped.
    pub fn from_table(reply: &str) -> Result<Self, String> {
        let v: Value = serde_json::from_str(reply).map_err(|e| format!("route_table: {e}"))?;
        if v.get("ok").is_some_and(|ok| ok == false) {
            return Err(v["error"].as_str().unwrap_or("route_table refused").to_string());
        }
        let proxy = match v["proxy"].as_str().map(str::trim).filter(|s| !s.is_empty() && *s != "direct") {
            Some(p) => Some(Proxy::parse(p)?),
            None => None,
        };
        let role = |name: &str| -> Result<Vec<Source>, String> {
            let entries: Vec<Entry> = match v.get(name) {
                Some(Value::Array(_)) => serde_json::from_value(v[name].clone()).map_err(|e| format!("route_table.{name}: {e}"))?,
                _ => vec![],
            };
            Ok(entries.iter().filter_map(|e| resolve(e, proxy.as_ref())).collect())
        };
        Ok(Routes {
            chain: role("chain")?.into_iter().filter(|s| s.kind == Kind::Electrum).collect(),
            history: role("history")?,
            pending: role("pending")?,
            fees: role("fees")?,
            broadcast: role("broadcast")?,
            check: role("check")?,
            cross_check: v["crossCheck"].as_bool().unwrap_or(false),
            poll_secs: 30,
            proxy,
        })
    }

    /// A local test chain: its loopback servers fill every role, reached directly.
    pub fn regtest(cfg: &RegtestConfig) -> Self {
        let mut all = vec![];
        for (i, url) in cfg.electrum.iter().enumerate() {
            all.push(Entry { id: format!("electrum-{i}"), url: url.clone(), operator: format!("regtest-{i}"), route: Route::Direct });
        }
        for (i, url) in cfg.esplora.iter().enumerate() {
            all.push(Entry { id: format!("esplora-{i}"), url: url.clone(), operator: format!("regtest-esplora-{i}"), route: Route::Direct });
        }
        let sources: Vec<Source> = all.iter().filter_map(|e| resolve(e, None)).collect();
        Routes {
            proxy: None,
            chain: sources.iter().filter(|s| s.kind == Kind::Electrum).cloned().collect(),
            history: sources.clone(),
            pending: sources.clone(),
            fees: sources.clone(),
            broadcast: sources.clone(),
            check: sources.clone(),
            cross_check: sources.len() > 1,
            poll_secs: cfg.poll_secs.unwrap_or(1),
        }
    }

    pub fn every(&self) -> Vec<&Source> {
        let mut seen = std::collections::BTreeSet::new();
        [&self.chain, &self.history, &self.pending, &self.fees, &self.broadcast, &self.check]
            .into_iter()
            .flatten()
            .filter(|s| seen.insert(s.id.clone()))
            .collect()
    }

    pub fn roles_of(&self, id: &str) -> Vec<&'static str> {
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
            "chain": [e("a", "ssl://electrum.example:50002".into(), "tor"), e("k", "kyoto://peers".into(), "tor")],
            "history": [e("a", "ssl://electrum.example:50002".into(), "tor"), e("o", format!("tcp://{}:50001", onion()), "onion")],
            "fees": [e("f", "https://esplora.example/api".into(), "tor")],
            "broadcast": [e("a", "ssl://electrum.example:50002".into(), "tor")],
            "check": [e("l", "tcp://192.168.1.20:50001".into(), "direct")],
            "crossCheck": true,
        })
        .to_string()
    }

    #[test]
    fn a_table_with_a_proxy_routes_through_tor() {
        let r = Routes::from_table(&table(Some("socks5h://127.0.0.1:9050"))).unwrap();
        assert_eq!(r.proxy, Some(Proxy { host: "127.0.0.1".into(), port: 9050 }));
        assert_eq!(r.chain.len(), 1, "Kyoto entries wait for the Kyoto pass");
        assert!(r.history.iter().all(|s| s.down.is_none()));
        assert_eq!(r.history[1].kind, Kind::Electrum);
        assert_eq!(r.fees[0].kind, Kind::Esplora);
        assert!(r.cross_check);
        assert_eq!(r.roles_of("a"), vec!["chain", "history", "broadcast"]);
        assert_eq!(r.every().len(), 4);
    }

    #[test]
    fn without_a_proxy_tor_routes_fail_closed() {
        let r = Routes::from_table(&table(None)).unwrap();
        assert!(r.history.iter().all(|s| s.down.as_deref() == Some("routed through Tor, and no proxy is set")));
        assert!(r.check[0].down.is_none(), "the user's own network needs no proxy");
        assert!(Routes::from_table(&json!({"proxy": "socks5://127.0.0.1:9050"}).to_string()).is_err(), "names must resolve at the proxy");
        assert!(Routes::from_table(&json!({"ok": false, "error": "not authorized"}).to_string()).is_err());
    }

    #[test]
    fn plain_text_only_to_onions_and_our_own_network() {
        let p = Proxy::parse("socks5h://127.0.0.1:9050").unwrap();
        let e = |url: &str, route| Entry { id: "x".into(), url: url.into(), operator: String::new(), route };
        assert!(resolve(&e("tcp://electrum.example:50001", Route::Tor), Some(&p)).unwrap().down.is_some());
        assert!(resolve(&e("tcp://electrum.example:50001", Route::Direct), None).unwrap().down.is_some());
        assert!(resolve(&e("tcp://127.0.0.1:60401", Route::Direct), None).unwrap().down.is_none());
        assert!(resolve(&e("http://nas.local:3002", Route::Direct), None).unwrap().down.is_none());
        assert!(resolve(&e("ssl://electrum.example:50002", Route::Direct), None).unwrap().down.is_none(), "the user's choice, with TLS");
        let o = format!("tcp://{}:50001", onion());
        assert!(resolve(&e(&o, Route::Direct), None).unwrap().down.is_some());
        assert!(resolve(&e(&o, Route::Onion), Some(&p)).unwrap().down.is_none());
        assert!(resolve(&e("ssl://electrum.example:50002", Route::Onion), Some(&p)).unwrap().down.is_some());
        assert!(resolve(&e("ftp://x", Route::Direct), None).is_none());
        assert_eq!(host_of("ssl://[fd00::2]:50002"), Some("fd00::2"));
        assert_eq!(host_of("https://esplora.example/api"), Some("esplora.example"));
    }

    #[test]
    fn regtest_fills_every_role_directly() {
        let r = Routes::regtest(&RegtestConfig { electrum: vec!["tcp://127.0.0.1:60401".into(), "tcp://127.0.0.1:60411".into()], esplora: vec![], poll_secs: None });
        assert_eq!((r.chain.len(), r.history.len(), r.broadcast.len()), (2, 2, 2));
        assert!(r.history.iter().all(|s| s.route == Route::Direct && s.down.is_none()));
        assert!(r.cross_check);
        assert_eq!(r.poll_secs, 1);
        assert_ne!(Isolation::fresh(), Isolation::fresh());
    }
}
