//! Each source's health, the one history server at a time with failover in order, suspects, and
//! the exposure record of which servers have learned the wallet's addresses.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{json, Value};

use crate::crosscheck::{Track, Verdict};
use crate::routes::{Routes, Source};

/// Consecutive failures before history moves to the next server.
pub const FAILOVER_AFTER: u32 = 3;

#[derive(Debug, Clone, Default)]
pub struct Health {
    pub failures: u32,
    /// A failing source is not asked again before this, so a hung one can't stall every step.
    pub retry_at: Option<u64>,
    pub last_ok: Option<u64>,
    pub last_error: Option<String>,
    pub last_sync: Option<u64>,
    pub suspect: Option<String>,
    pub tip: Option<u32>,
    pub track: Track,
}

impl Health {
    pub fn stale(&self) -> bool {
        self.track.verdict == Some(Verdict::Stale)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Exposure {
    pub source: String,
    pub url: String,
    pub operator: String,
    pub role: String,
    pub since: u64,
    pub last: u64,
}

#[derive(Debug, Default)]
pub struct Ledger {
    pub health: BTreeMap<String, Health>,
    pub exposure: BTreeMap<String, Exposure>,
    /// The history server last used, for failing back once an earlier one recovers.
    pub current_history: Option<String>,
}

impl Ledger {
    pub fn health_mut(&mut self, id: &str) -> &mut Health {
        self.health.entry(id.to_string()).or_default()
    }

    pub fn usable(&self, s: &Source) -> bool {
        let h = self.health.get(&s.id);
        s.down.is_none() && h.is_none_or(|h| h.suspect.is_none() && !h.stale() && h.failures < FAILOVER_AFTER)
    }

    /// The first history server in order that is healthy: an earlier one that recovered comes back,
    /// since it already knows the addresses.
    pub fn history<'a>(&self, routes: &'a Routes) -> Option<&'a Source> {
        routes.history.iter().find(|s| self.usable(s))
    }

    /// Whether `id` may be asked now: not while it backs off after failures.
    pub fn may_ask(&self, id: &str, now: u64) -> bool {
        self.health.get(id).and_then(|h| h.retry_at).is_none_or(|t| now >= t)
    }

    pub fn ok(&mut self, id: &str, now: u64) {
        let h = self.health_mut(id);
        h.failures = 0;
        h.retry_at = None;
        h.last_ok = Some(now);
        h.last_error = None;
    }

    /// Backs off 5 s, doubling per failure in a row, up to 5 minutes.
    pub fn failed(&mut self, id: &str, error: &str, now: u64) {
        let h = self.health_mut(id);
        h.failures = h.failures.saturating_add(1);
        h.last_error = Some(error.to_string());
        h.retry_at = Some(now + (5u64 << h.failures.min(6).saturating_sub(1)).min(300));
    }

    /// Returns true when this is news.
    pub fn suspect(&mut self, id: &str, reason: &str) -> bool {
        let h = self.health_mut(id);
        let fresh = h.suspect.is_none();
        if fresh {
            h.suspect = Some(reason.to_string());
        }
        fresh
    }

    pub fn clear_suspect(&mut self, id: &str) -> bool {
        match self.health.get_mut(id) {
            Some(h) => {
                let had = h.suspect.take().is_some();
                h.track = Track::default();
                had
            }
            None => false,
        }
    }

    /// Records that `s` learned the wallet's addresses (history) or a transaction (broadcast).
    /// Returns true the first time.
    pub fn expose(&mut self, s: &Source, role: &str, now: u64) -> bool {
        match self.exposure.get_mut(&s.id) {
            Some(e) => {
                e.last = now;
                if role == "history" && e.role != "history" {
                    e.role = "history".into();
                }
                false
            }
            None => {
                self.exposure.insert(
                    s.id.clone(),
                    Exposure { source: s.id.clone(), url: s.url.clone(), operator: s.operator.clone(), role: role.into(), since: now, last: now },
                );
                true
            }
        }
    }

    pub fn status(&self, routes: &Routes) -> Value {
        let history = self.history(routes).map(|s| s.id.clone());
        let rows: Vec<Value> = routes
            .every()
            .into_iter()
            .map(|s| {
                let h = self.health.get(&s.id).cloned().unwrap_or_default();
                let state = if s.down.is_some() {
                    "down"
                } else if h.suspect.is_some() {
                    "suspect"
                } else if h.stale() {
                    "stale"
                } else if h.failures >= FAILOVER_AFTER {
                    "failing"
                } else if h.last_ok.is_some() {
                    "ok"
                } else {
                    "unknown"
                };
                json!({
                    "id": s.id, "url": s.url, "operator": s.operator, "kind": s.kind, "route": s.route,
                    "roles": routes.roles_of(&s.id), "state": state, "suspect": h.suspect.is_some(),
                    "suspectReason": h.suspect, "lastSync": h.last_sync, "lastOk": h.last_ok,
                    "error": s.down.clone().or(h.last_error.clone()), "tip": h.tip,
                    "verdict": h.track.verdict, "history": history.as_deref() == Some(s.id.as_str()),
                })
            })
            .collect();
        json!(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::RegtestConfig;

    fn routes() -> Routes {
        Routes::regtest(&RegtestConfig { electrum: vec!["tcp://127.0.0.1:1".into(), "tcp://127.0.0.1:2".into(), "tcp://127.0.0.1:3".into()], ..Default::default() })
    }

    #[test]
    fn history_fails_over_in_order_and_comes_back() {
        let r = routes();
        let mut l = Ledger::default();
        assert_eq!(l.history(&r).unwrap().id, "electrum-0");
        for _ in 0..FAILOVER_AFTER {
            l.failed("electrum-0", "timeout", 0);
        }
        assert_eq!(l.history(&r).unwrap().id, "electrum-1");
        l.suspect("electrum-1", "anchor mismatch");
        assert_eq!(l.history(&r).unwrap().id, "electrum-2");
        // The first recovers: history returns to it, since it already knows the addresses.
        l.ok("electrum-0", 10);
        assert_eq!(l.history(&r).unwrap().id, "electrum-0");
        assert!(l.clear_suspect("electrum-1"));
        assert!(!l.clear_suspect("electrum-1"));
    }

    #[test]
    fn a_failing_source_backs_off() {
        let mut l = Ledger::default();
        assert!(l.may_ask("a", 0));
        l.failed("a", "timeout", 100);
        assert!(!l.may_ask("a", 104) && l.may_ask("a", 105));
        l.failed("a", "timeout", 105);
        assert!(!l.may_ask("a", 114) && l.may_ask("a", 115));
        for _ in 0..10 {
            l.failed("a", "timeout", 200);
        }
        assert!(l.may_ask("a", 500), "never more than five minutes");
        l.ok("a", 501);
        assert!(l.may_ask("a", 501));
    }

    #[test]
    fn a_stale_server_is_not_used_for_history() {
        let r = routes();
        let mut l = Ledger::default();
        l.health_mut("electrum-0").track.verdict = Some(Verdict::Stale);
        assert_eq!(l.history(&r).unwrap().id, "electrum-1");
        let s = l.status(&r);
        assert_eq!(s[0]["state"], "stale");
        assert_eq!(s[1]["history"], true);
    }

    #[test]
    fn exposure_records_the_first_time_and_since_when() {
        let r = routes();
        let mut l = Ledger::default();
        assert!(l.expose(&r.history[0], "broadcast", 100));
        assert!(!l.expose(&r.history[0], "history", 200));
        let e = &l.exposure["electrum-0"];
        assert_eq!((e.since, e.last, e.role.as_str()), (100, 200, "history"));
        assert!(l.suspect("electrum-2", "tx mismatch"));
        assert!(!l.suspect("electrum-2", "again"));
    }
}
