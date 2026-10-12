//! Kyoto's peers from the node module: which 8 a start dials, and what the core tells the node
//! module back, how each peer it tried did and the peers they gossiped (`report_peers`). The
//! node module keeps each peer's record, skips one that failed 3 times in a row for a day, and
//! lists what it keeps in `route_table` as `{ peer, source, ok }`. README, "Kyoto", has the
//! rules and why.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use bdk_kyoto::bip157::{AddrV2, AddrV2Message, DialOutcome};
use rand::seq::SliceRandom;
use serde::Serialize;
use serde_json::{json, Value};

use crate::kyoto::{onion_name, SUBSET};
use crate::network::BNetwork;

/// Services Kyoto needs of a peer: NETWORK, WITNESS and COMPACT_FILTERS (bits 0, 3, 6).
pub const REQUIRED_SERVICES: u64 = 1 | 1 << 3 | 1 << 6;
/// The first protocol version Kyoto talks to (BIP 339, wtxid relay).
pub const MIN_VERSION: u32 = 70016;
/// At least this many of a start's peers come from the curated list, when it has them.
pub const MIN_LISTED: usize = 3;
/// At most this many learned peers per start come from any one gossiping peer.
pub const MAX_PER_FROM: usize = 2;
/// Gossiped addresses older than this aren't reported.
pub const LEARNED_MAX_AGE: u64 = 3 * 24 * 3600;
/// Learned peers go to the node module at most this often; a report holds at most this many
/// outcomes and this many learned peers.
pub const LEARNED_EVERY: Duration = Duration::from_secs(60);
pub const LEARNED_PER_REPORT: usize = 500;
pub const OUTCOMES_PER_REPORT: usize = 500;
/// Learned peers kept until reported; past it, the stalest go.
const LEARNED_PENDING: usize = 2_000;
/// A peer already reported goes again once seen this much later, so the node module's
/// 3 days count from a recent sighting.
const LEARNED_REFRESH: u64 = 6 * 3600;
/// Reported peers remembered for that, and for crediting a learned peer to its gossiper; past
/// it, the record starts over.
const LEARNED_REPORTED: usize = 20_000;
/// While a client runs, its outcomes wait this long after its start, then go at most once a
/// minute; the rest go when it stops.
pub const SETTLE: Duration = Duration::from_secs(30);

/// Where the node module has a peer from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSource {
    /// The curated peer list.
    List,
    /// Gossip a peer sent, reported by a core.
    Learned,
    /// Bitcoin Core's fixed seeds.
    Seed,
    /// The person's own.
    Own,
}

impl PeerSource {
    /// An unknown source counts as a seed: neither curated nor capped.
    pub fn parse(text: &str) -> PeerSource {
        match text {
            "list" => PeerSource::List,
            "learned" => PeerSource::Learned,
            "own" => PeerSource::Own,
            _ => PeerSource::Seed,
        }
    }
}

/// A peer in the route table, with what the node module knows of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub peer: String,
    pub source: PeerSource,
    /// It connected with the services Kyoto needs before.
    pub ok: bool,
    /// For a learned peer, the peer that gossiped it, as this core reported it: the table
    /// doesn't say.
    pub from: Option<String>,
}

/// The peers a start dials, in the order to dial them: the person's own first; then at least
/// `MIN_LISTED` from the list when it has them; then the rest. Within each, peers that connected
/// before come ahead of new ones, at random, and at most `MAX_PER_FROM` learned peers credited
/// to one gossiping peer (or to none) are taken. `avoid` sits out unless nothing else is left.
pub fn choose(listed: &[Listed], avoid: &HashSet<String>, rng: &mut impl rand::Rng) -> Vec<String> {
    let mut seen = HashSet::new();
    let usable: Vec<&Listed> = listed.iter().filter(|l| seen.insert(l.peer.as_str())).collect();
    let fresh: Vec<&Listed> = usable.iter().copied().filter(|l| !avoid.contains(&l.peer)).collect();
    let pool = if fresh.is_empty() { usable } else { fresh };
    let (mut own, mut rest): (Vec<&Listed>, Vec<&Listed>) = pool.into_iter().partition(|l| l.source == PeerSource::Own);
    own.shuffle(rng);
    rest.shuffle(rng);
    // A stable sort keeps the shuffle within each tier.
    rest.sort_by_key(|l| !l.ok);
    let mut out: Vec<String> = own.iter().take(SUBSET).map(|l| l.peer.clone()).collect();
    let mut taken = vec![false; rest.len()];
    let want = MIN_LISTED.min(rest.iter().filter(|l| l.source == PeerSource::List).count());
    for (i, l) in rest.iter().enumerate().filter(|(_, l)| l.source == PeerSource::List).take(want) {
        if out.len() < SUBSET {
            out.push(l.peer.clone());
            taken[i] = true;
        }
    }
    let mut per_from: HashMap<&str, usize> = HashMap::new();
    for (i, l) in rest.iter().enumerate() {
        if out.len() >= SUBSET {
            break;
        }
        if taken[i] {
            continue;
        }
        if l.source == PeerSource::Learned {
            let n = per_from.entry(l.from.as_deref().unwrap_or("")).or_default();
            if *n >= MAX_PER_FROM {
                continue;
            }
            *n += 1;
        }
        out.push(l.peer.clone());
    }
    out
}

/// What one start says of one peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    pub peer: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

/// A dial's outcome for the node module: ok when the version showed the services and protocol
/// Kyoto needs, else why not: `services`, `timeout`, `refused` or `unreachable`. `None` when it
/// failed on this side (the local network, the proxy), which says nothing of the peer.
pub fn verdict(outcome: DialOutcome) -> Option<(bool, Option<&'static str>)> {
    match outcome {
        DialOutcome::Version { services, version } if version >= MIN_VERSION && services.to_u64() & REQUIRED_SERVICES == REQUIRED_SERVICES => Some((true, None)),
        DialOutcome::Version { .. } => Some((false, Some("services"))),
        DialOutcome::TimedOut => Some((false, Some("timeout"))),
        DialOutcome::Refused => Some((false, Some("refused"))),
        DialOutcome::Unreachable => Some((false, Some("unreachable"))),
        DialOutcome::Local => None,
    }
}

/// A gossiped peer for the node module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Learned {
    pub addr: String,
    pub port: u16,
    pub services: u64,
    pub seen_at: u64,
    pub from: String,
}

/// A gossiped address the node module keeps: an onion v3 service (on regtest, an address on
/// the user's network instead), with bits 0, 3 and 6, seen within 3 days, at most 10 minutes ahead.
pub fn learned(net: BNetwork, from: &str, m: &AddrV2Message, now: u64) -> Option<Learned> {
    let seen = u64::from(m.time);
    if m.port == 0 || m.services.to_u64() & REQUIRED_SERVICES != REQUIRED_SERVICES || seen + LEARNED_MAX_AGE < now || seen > now + 600 {
        return None;
    }
    let lan = |ip: std::net::IpAddr| crate::routes::is_loopback_or_lan(&ip.to_string());
    let regtest = net == BNetwork::Regtest;
    let addr = match &m.addr {
        AddrV2::TorV3(key) if !regtest => onion_name(key),
        AddrV2::Ipv4(ip) if regtest && lan((*ip).into()) => ip.to_string(),
        AddrV2::Ipv6(ip) if regtest && lan((*ip).into()) => ip.to_string(),
        _ => return None,
    };
    Some(Learned { addr, port: m.port, services: m.services.to_u64(), seen_at: seen, from: from.to_string() })
}

/// What the core owes the node module: each start's outcomes and the peers gossiped since the
/// last report.
#[derive(Debug, Default)]
pub struct PeerReports {
    outcomes: Vec<Outcome>,
    /// This start's failures until one of its peers answers: a start in which none did says more
    /// about this side (offline, Tor still starting) than about the peers.
    held: Vec<Outcome>,
    answered: bool,
    learned: HashMap<(String, u16), Learned>,
    /// The sighting last reported of each peer.
    reported: HashMap<(String, u16), u64>,
    /// The gossiper each reported peer is credited to, by `host:port`: the table doesn't say.
    credits: HashMap<String, String>,
    last_sent: Option<Instant>,
    last_learned: Option<Instant>,
    /// Addresses peers gossiped, and those kept for the node module, since the wallet opened.
    pub gossiped: u64,
    pub kept: u64,
}

impl PeerReports {
    /// A new start; failures of the last one, which no peer answered, are dropped.
    pub fn start(&mut self) {
        if !self.held.is_empty() {
            tracing::info!(target: "bitcoin", "kyoto: no peer answered; {} failures not reported", self.held.len());
        }
        self.held.clear();
        self.answered = false;
    }

    pub fn dial(&mut self, peer: &str, outcome: DialOutcome) {
        let Some((ok, reason)) = verdict(outcome) else { return };
        let o = Outcome { peer: peer.to_string(), ok, reason };
        if matches!(outcome, DialOutcome::Version { .. }) {
            self.answered = true;
            self.outcomes.append(&mut self.held);
            self.outcomes.push(o);
        } else if self.answered {
            self.outcomes.push(o);
        } else {
            self.held.push(o);
        }
    }

    /// Peers set aside after a filter-header conflict: a failure each.
    pub fn conflict(&mut self, peers: &[String]) {
        self.outcomes.extend(peers.iter().map(|p| Outcome { peer: p.clone(), ok: false, reason: Some("conflict") }));
    }

    pub fn gossip(&mut self, net: BNetwork, from: &str, addrs: &[AddrV2Message], now: u64) {
        self.gossiped += addrs.len() as u64;
        for l in addrs.iter().filter_map(|m| learned(net, from, m, now)) {
            self.kept += 1;
            let key = (l.addr.clone(), l.port);
            if self.reported.get(&key).is_some_and(|r| l.seen_at < r + LEARNED_REFRESH) {
                continue;
            }
            match self.learned.get_mut(&key) {
                // The first peer to gossip it keeps the credit; the sighting is the latest.
                Some(had) => had.seen_at = had.seen_at.max(l.seen_at),
                None => {
                    self.learned.insert((l.addr.clone(), l.port), l);
                }
            }
        }
        if self.learned.len() > LEARNED_PENDING {
            let mut by_age: Vec<((String, u16), u64)> = self.learned.iter().map(|(k, l)| (k.clone(), l.seen_at)).collect();
            by_age.sort_by_key(|(_, seen)| *seen);
            for (k, _) in by_age.into_iter().take(self.learned.len() - LEARNED_PENDING) {
                self.learned.remove(&k);
            }
        }
    }

    /// The report due at `now`, if any: a start's outcomes when it `ended`, or, while it runs and
    /// has `settled`, at most once a minute; learned peers at most once a minute, 500 of them,
    /// new ones before sightings of reported ones, the freshest first; the rest wait.
    pub fn take(&mut self, now: Instant, ended: bool, settled: bool) -> Option<Value> {
        let minute_since = |t: Option<Instant>, every: Duration| t.is_none_or(|t| now >= t + every);
        let outcomes_due = !self.outcomes.is_empty() && (ended || (settled && minute_since(self.last_sent, LEARNED_EVERY)));
        let learned_due = !self.learned.is_empty() && minute_since(self.last_learned, LEARNED_EVERY);
        if !outcomes_due && !learned_due {
            return None;
        }
        let outcomes: Vec<Outcome> = if outcomes_due { self.outcomes.drain(..self.outcomes.len().min(OUTCOMES_PER_REPORT)).collect() } else { vec![] };
        let mut learned = vec![];
        if learned_due {
            let mut all: Vec<Learned> = self.learned.drain().map(|(_, l)| l).collect();
            let old = |l: &Learned| self.reported.contains_key(&(l.addr.clone(), l.port));
            all.sort_by(|a, b| old(a).cmp(&old(b)).then(b.seen_at.cmp(&a.seen_at)).then_with(|| (&a.addr, a.port).cmp(&(&b.addr, b.port))));
            for l in all.split_off(all.len().min(LEARNED_PER_REPORT)) {
                self.learned.insert((l.addr.clone(), l.port), l);
            }
            if self.reported.len() + all.len() > LEARNED_REPORTED {
                self.reported.clear();
            }
            if self.credits.len() + all.len() > LEARNED_REPORTED {
                self.credits.clear();
            }
            self.reported.extend(all.iter().map(|l| ((l.addr.clone(), l.port), l.seen_at)));
            for l in &all {
                self.credits.entry(peer_text(&l.addr, l.port)).or_insert_with(|| l.from.clone());
            }
            learned = all;
            self.last_learned = Some(now);
        }
        self.last_sent = Some(now);
        Some(json!({ "outcomes": outcomes, "learned": learned }))
    }

    /// The gossiper a learned peer was reported with, by this core.
    pub fn credit(&self, peer: &str) -> Option<&str> {
        self.credits.get(peer).map(String::as_str)
    }

    /// The credits, to keep with the wallet, and back.
    pub fn credits_json(&self) -> String {
        serde_json::to_string(&self.credits).unwrap_or_default()
    }

    pub fn load_credits(&mut self, text: &str) {
        self.credits = serde_json::from_str(text).unwrap_or_default();
    }
}

/// `host:port` as the node module lists a peer; IPv6 in brackets.
fn peer_text(addr: &str, port: u16) -> String {
    if addr.contains(':') {
        format!("[{addr}]:{port}")
    } else {
        format!("{addr}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_kyoto::bip157::ServiceFlags;
    use rand::SeedableRng;

    fn entry(peer: &str, source: PeerSource, ok: bool, from: Option<&str>) -> Listed {
        Listed { peer: peer.into(), source, ok, from: from.map(String::from) }
    }

    fn count(picked: &[String], prefix: &str) -> usize {
        picked.iter().filter(|p| p.starts_with(prefix)).count()
    }

    #[test]
    fn a_start_takes_three_listed_prefers_known_peers_and_caps_each_gossiper() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let none = HashSet::new();
        // Learned peers that connected before outnumber the list: three listed still come along.
        let mut table: Vec<Listed> = (0..10).map(|i| entry(&format!("learned-a{i}:1"), PeerSource::Learned, true, Some("a.onion:8333"))).collect();
        table.extend((0..10).map(|i| entry(&format!("learned-b{i}:1"), PeerSource::Learned, true, Some("b.onion:8333"))));
        table.extend((0..10).map(|i| entry(&format!("learned-c{i}:1"), PeerSource::Learned, true, Some("c.onion:8333"))));
        table.extend((0..5).map(|i| entry(&format!("list{i}:1"), PeerSource::List, false, None)));
        for _ in 0..20 {
            let picked = choose(&table, &none, &mut rng);
            assert_eq!(picked.len(), SUBSET);
            assert_eq!(count(&picked, "list"), 3, "{picked:?}");
            assert!(picked[..3].iter().all(|p| p.starts_with("list")), "the listed are dialled first: {picked:?}");
            for g in ["learned-a", "learned-b", "learned-c"] {
                assert!(count(&picked, g) <= MAX_PER_FROM, "{picked:?}");
            }
        }
        // Peers that connected before go ahead of new ones, of any source.
        let mut table: Vec<Listed> = (0..6).map(|i| entry(&format!("list-ok{i}:1"), PeerSource::List, true, None)).collect();
        table.extend((0..20).map(|i| entry(&format!("list-new{i}:1"), PeerSource::List, false, None)));
        table.extend((0..2).map(|i| entry(&format!("seed-ok{i}:1"), PeerSource::Seed, true, None)));
        table.extend((0..20).map(|i| entry(&format!("seed-new{i}:1"), PeerSource::Seed, false, None)));
        let picked = choose(&table, &none, &mut rng);
        assert_eq!((count(&picked, "list-ok"), count(&picked, "seed-ok")), (6, 2), "{picked:?}");
        // Too few known: new ones fill the rest, and fewer than three listed are all taken.
        let table = vec![entry("list0:1", PeerSource::List, false, None), entry("list1:1", PeerSource::List, true, None), entry("seed0:1", PeerSource::Seed, false, None)];
        let picked = choose(&table, &none, &mut rng);
        assert_eq!(picked.len(), 3);
        assert_eq!(picked[0], "list1:1", "the listed peer that connected before is dialled first");
        // Learned peers without a gossiper on record share one cap.
        let table: Vec<Listed> = (0..6).map(|i| entry(&format!("anon{i}:1"), PeerSource::Learned, true, None)).collect();
        assert_eq!(choose(&table, &none, &mut rng).len(), MAX_PER_FROM);
    }

    #[test]
    fn own_peers_bypass_the_rule_and_a_conflicts_peers_sit_out() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(9);
        let none = HashSet::new();
        let own: Vec<Listed> = (0..12).map(|i| entry(&format!("own{i}:1"), PeerSource::Own, false, None)).collect();
        let mut table = own.clone();
        table.extend((0..5).map(|i| entry(&format!("list{i}:1"), PeerSource::List, true, None)));
        let picked = choose(&table, &none, &mut rng);
        assert_eq!((picked.len(), count(&picked, "own")), (SUBSET, SUBSET), "own peers first, all of the subset");
        let few = vec![entry("own0:1", PeerSource::Own, false, None), entry("list0:1", PeerSource::List, false, None)];
        assert_eq!(choose(&few, &none, &mut rng), vec!["own0:1".to_string(), "list0:1".to_string()]);
        // A conflict's peers sit out the next start, unless nobody else is left.
        let table: Vec<Listed> = (0..10).map(|i| entry(&format!("list{i}:1"), PeerSource::List, true, None)).collect();
        let avoid: HashSet<String> = (0..4).map(|i| format!("list{i}:1")).collect();
        for _ in 0..20 {
            assert!(choose(&table, &avoid, &mut rng).iter().all(|p| !avoid.contains(p)));
        }
        let only: Vec<Listed> = table[..4].to_vec();
        assert_eq!(choose(&only, &avoid, &mut rng).len(), 4, "all of them rather than none");
        // A peer listed twice is dialled once.
        let twice = vec![entry("list0:1", PeerSource::List, true, None), entry("list0:1", PeerSource::Seed, true, None)];
        assert_eq!(choose(&twice, &none, &mut rng).len(), 1);
    }

    fn v(services: u64, version: u32) -> DialOutcome {
        DialOutcome::Version { services: ServiceFlags::from(services), version }
    }

    #[test]
    fn a_dial_is_ok_with_the_services_and_otherwise_says_why() {
        assert_eq!(verdict(v(REQUIRED_SERVICES | 1 << 10, 70016)), Some((true, None)));
        assert_eq!(verdict(v(1 | 1 << 3, 70016)), Some((false, Some("services"))), "no filters");
        assert_eq!(verdict(v(1 | 1 << 6, 70016)), Some((false, Some("services"))), "no witness");
        assert_eq!(verdict(v(REQUIRED_SERVICES, 70015)), Some((false, Some("services"))), "too old");
        assert_eq!(verdict(DialOutcome::TimedOut), Some((false, Some("timeout"))));
        assert_eq!(verdict(DialOutcome::Refused), Some((false, Some("refused"))));
        assert_eq!(verdict(DialOutcome::Unreachable), Some((false, Some("unreachable"))));
        assert_eq!(verdict(DialOutcome::Local), None, "the proxy or this side failed");
    }

    fn gossip(addr: AddrV2, services: u64, time: u64) -> AddrV2Message {
        AddrV2Message { time: time as u32, services: ServiceFlags::from(services), addr, port: 8333 }
    }

    #[test]
    fn only_recent_onion_peers_that_serve_filters_are_learned_and_on_regtest_lan_ones() {
        let now = 1_800_000_000;
        let key = [5u8; 32];
        let onion = AddrV2::TorV3(key);
        let good = learned(BNetwork::Mainnet, "a.onion:8333", &gossip(onion.clone(), REQUIRED_SERVICES, now - 3600), now).unwrap();
        assert_eq!((good.addr, good.port, good.services, good.seen_at, good.from.as_str()), (onion_name(&key), 8333, REQUIRED_SERVICES, now - 3600, "a.onion:8333"));
        let reject = |net, addr: AddrV2, services, time| learned(net, "x", &gossip(addr, services, time), now).is_none();
        assert!(reject(BNetwork::Mainnet, onion.clone(), REQUIRED_SERVICES, now - LEARNED_MAX_AGE - 1), "older than 3 days");
        assert!(reject(BNetwork::Mainnet, onion.clone(), REQUIRED_SERVICES, now + 3600), "from the future");
        assert!(reject(BNetwork::Mainnet, onion.clone(), 1 | 1 << 6, now), "no witness");
        assert!(reject(BNetwork::Mainnet, onion.clone(), 1 | 1 << 3, now), "no filters");
        assert!(reject(BNetwork::Mainnet, AddrV2::Ipv4([203, 0, 113, 7].into()), REQUIRED_SERVICES, now), "clearnet");
        assert!(reject(BNetwork::Mainnet, AddrV2::Ipv4([127, 0, 0, 1].into()), REQUIRED_SERVICES, now), "loopback off regtest");
        assert!(reject(BNetwork::Regtest, AddrV2::Ipv4([203, 0, 113, 7].into()), REQUIRED_SERVICES, now), "clearnet on regtest");
        assert!(reject(BNetwork::Regtest, onion.clone(), REQUIRED_SERVICES, now), "the node module keeps none on regtest");
        assert!(reject(BNetwork::Mainnet, AddrV2::I2p([1; 32]), REQUIRED_SERVICES, now));
        assert!(!reject(BNetwork::Regtest, AddrV2::Ipv4([127, 0, 0, 1].into()), REQUIRED_SERVICES, now), "loopback on regtest");
        assert!(!reject(BNetwork::Regtest, AddrV2::Ipv4([192, 168, 1, 20].into()), REQUIRED_SERVICES, now), "the LAN on regtest");
        let v6 = learned(BNetwork::Regtest, "x", &gossip(AddrV2::Ipv6("fd00::2".parse().unwrap()), REQUIRED_SERVICES, now), now).unwrap();
        assert_eq!((v6.addr.as_str(), peer_text(&v6.addr, v6.port)), ("fd00::2", "[fd00::2]:8333".to_string()));
    }

    #[test]
    fn reports_carry_each_starts_outcomes_and_learned_peers_once_a_minute() {
        let t0 = Instant::now();
        let now = 1_800_000_000u64;
        let mut r = PeerReports::default();
        r.start();
        // Failures wait for an answer; a start nobody answered reports none of them.
        r.dial("dead:1", DialOutcome::TimedOut);
        r.dial("proxy:1", DialOutcome::Local);
        assert_eq!(r.take(t0, false, true), None);
        r.start();
        assert_eq!(r.take(t0, true, true), None, "dropped at the next start");
        r.dial("refusing:1", DialOutcome::Refused);
        r.dial("good:1", v(REQUIRED_SERVICES, 70016));
        r.dial("old:1", v(REQUIRED_SERVICES, 70001));
        let onions: Vec<AddrV2Message> = (0..600u32).map(|i| gossip(AddrV2::TorV3([(i % 256) as u8, (i / 256) as u8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]), REQUIRED_SERVICES, now - u64::from(i))).collect();
        r.gossip(BNetwork::Mainnet, "good:1", &onions, now);
        // Before the start settles only the learned peers may go; once it ends, its outcomes go.
        let first = r.take(t0, false, false).unwrap();
        assert_eq!(first["outcomes"], json!([]));
        assert_eq!(first["learned"].as_array().unwrap().len(), LEARNED_PER_REPORT);
        assert_eq!(first["learned"][0]["seenAt"], now, "the freshest first");
        assert_eq!(first["learned"][0]["from"], "good:1");
        let peer = format!("{}:8333", first["learned"][0]["addr"].as_str().unwrap());
        assert_eq!(r.credit(&peer), Some("good:1"), "a learned peer in the table is credited to its gossiper");
        let mut back = PeerReports::default();
        back.load_credits(&r.credits_json());
        assert_eq!((back.credit(&peer), back.credits.len()), (Some("good:1"), LEARNED_PER_REPORT));
        assert_eq!((r.gossiped, r.kept), (600, 600));
        let ended = r.take(t0 + Duration::from_secs(5), true, false).unwrap();
        assert_eq!(ended["outcomes"], json!([
            {"peer": "refusing:1", "ok": false, "reason": "refused"},
            {"peer": "good:1", "ok": true},
            {"peer": "old:1", "ok": false, "reason": "services"},
        ]));
        assert_eq!(ended["learned"], json!([]), "learned peers wait a minute");
        r.start();
        r.dial("good:1", v(REQUIRED_SERVICES, 70016));
        r.conflict(&["good:1".to_string()]);
        assert_eq!(r.take(t0 + Duration::from_secs(20), false, true), None, "a minute since the last report");
        let next = r.take(t0 + Duration::from_secs(65), false, true).unwrap();
        assert_eq!(next["outcomes"], json!([{"peer": "good:1", "ok": true}, {"peer": "good:1", "ok": false, "reason": "conflict"}]));
        assert_eq!(next["learned"].as_array().unwrap().len(), 100, "the rest");
        assert_eq!(r.take(t0 + LEARNED_EVERY * 3, true, true), None, "nothing left");
        // A peer gossiped again keeps its first gossiper and its latest sighting; one reported
        // already goes again only when seen hours later.
        let fresh = AddrV2::TorV3([9; 32]);
        r.gossip(BNetwork::Mainnet, "a:1", &[gossip(fresh.clone(), REQUIRED_SERVICES, now)], now);
        r.gossip(BNetwork::Mainnet, "b:1", &[gossip(fresh.clone(), REQUIRED_SERVICES, now + 60)], now + 60);
        r.gossip(BNetwork::Mainnet, "b:1", &onions[..1], now + 60);
        let again = r.take(t0 + LEARNED_EVERY * 3, false, false).unwrap();
        assert_eq!(again["learned"], json!([{"addr": onion_name(&[9; 32]), "port": 8333, "services": REQUIRED_SERVICES, "seenAt": now + 60, "from": "a:1"}]));
        let later = now + LEARNED_REFRESH;
        r.gossip(BNetwork::Mainnet, "b:1", &[gossip(onions[0].addr.clone(), REQUIRED_SERVICES, later)], later);
        let refreshed = r.take(t0 + LEARNED_EVERY * 4, false, false).unwrap();
        assert_eq!((refreshed["learned"].as_array().unwrap().len(), &refreshed["learned"][0]["seenAt"]), (1, &json!(later)));
    }

    #[test]
    fn a_report_holds_at_most_500_outcomes() {
        let mut r = PeerReports::default();
        r.dial("good:1", v(REQUIRED_SERVICES, 70016));
        for i in 0..600 {
            r.dial(&format!("p{i}:1"), DialOutcome::Refused);
        }
        let t0 = Instant::now();
        assert_eq!(r.take(t0, true, false).unwrap()["outcomes"].as_array().unwrap().len(), OUTCOMES_PER_REPORT);
        assert_eq!(r.take(t0, true, false).unwrap()["outcomes"].as_array().unwrap().len(), 101);
    }

    #[test]
    fn peers_not_yet_reported_go_before_new_sightings_of_reported_ones() {
        let (t0, now) = (Instant::now(), 1_800_000_000u64);
        let mut r = PeerReports::default();
        let at = |i: u32, seen: u64| gossip(AddrV2::TorV3([(i % 256) as u8, (i / 256) as u8, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]), REQUIRED_SERVICES, seen);
        let first: Vec<AddrV2Message> = (0..600).map(|i| at(i, now)).collect();
        r.gossip(BNetwork::Mainnet, "a:1", &first, now);
        assert_eq!(r.take(t0, false, false).unwrap()["learned"].as_array().unwrap().len(), 500);
        // All 600 seen again much later: the 100 never reported go first.
        let later = now + LEARNED_REFRESH;
        let again: Vec<AddrV2Message> = (0..600).map(|i| at(i, later)).collect();
        r.gossip(BNetwork::Mainnet, "a:1", &again, later);
        let next = r.take(t0 + LEARNED_EVERY, false, false).unwrap();
        let reported: HashSet<String> = next["learned"].as_array().unwrap().iter().map(|l| l["addr"].as_str().unwrap().to_string()).collect();
        let never: Vec<String> = (500..600).map(|i| learned(BNetwork::Mainnet, "a:1", &at(i, now), now).unwrap().addr).collect();
        let missing: Vec<&String> = never.iter().filter(|a| !reported.contains(*a)).collect();
        assert_eq!(reported.len(), 500);
        assert!(missing.is_empty(), "{} never reported were left behind", missing.len());
    }
}
