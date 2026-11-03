//! The tip watch: each enabled server's tip against the chain authority's. Headers a server shows
//! above it count once they link to the authority's chain and pass the same checks; shown for
//! half an hour, the authority may be held back. A server that lags is left out of history.

use rand::Rng;

/// Tips this close count as level.
pub const TIP_SLACK: u32 = 2;
/// A server ahead this long means the authority may be held back.
pub const AHEAD_ALERT_SECS: u64 = 30 * 60;
/// Checks run on every new authority tip and at least this often, with jitter.
pub const INTERVAL_SECS: u64 = 10 * 60;
/// A server lags once it is behind in this many checks in a row, the first this long ago: a burst
/// of blocks leaves an honest server behind for a moment.
pub const LAG_CHECKS: u32 = 2;
pub const LAG_AFTER_SECS: u64 = 60;
/// Headers above the authority are asked from this far below its tip, so a server across a short
/// reorg still links.
pub const LINK_BACK: u32 = 6;

/// Per server memory between checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Watch {
    pub ahead_since: Option<u64>,
    pub behind_since: Option<u64>,
    pub behind_checks: u32,
    /// Not used for history or pending until it catches up.
    pub lagging: bool,
    /// The alert was raised; again only after it is level once more.
    pub ahead: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    Nothing,
    Lags,
    /// Checked headers above the authority for half an hour.
    AuthorityBehind,
}

/// Judges a server's tip: the height its headers were checked to, where it claimed more than the
/// slack above the authority.
pub fn judge(w: &mut Watch, auth_tip: u32, tip: u32, now: u64) -> Seen {
    let mut seen = Seen::Nothing;
    if tip + TIP_SLACK < auth_tip {
        let since = *w.behind_since.get_or_insert(now);
        w.behind_checks += 1;
        if !w.lagging && w.behind_checks >= LAG_CHECKS && now.saturating_sub(since) >= LAG_AFTER_SECS {
            w.lagging = true;
            seen = Seen::Lags;
        }
    } else {
        (w.behind_since, w.behind_checks, w.lagging) = (None, 0, false);
    }
    if tip > auth_tip + TIP_SLACK {
        let since = *w.ahead_since.get_or_insert(now);
        if !w.ahead && now.saturating_sub(since) >= AHEAD_ALERT_SECS {
            w.ahead = true;
            seen = Seen::AuthorityBehind;
        }
    } else {
        (w.ahead_since, w.ahead) = (None, false);
    }
    seen
}

/// The next scheduled check: the interval, plus or minus a fifth.
pub fn next_delay_secs() -> u64 {
    let jitter = INTERVAL_SECS / 5;
    rand::thread_rng().gen_range(INTERVAL_SECS - jitter..=INTERVAL_SECS + jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_or_close_tips_are_level() {
        let mut w = Watch::default();
        for tip in [98, 100, 102] {
            assert_eq!(judge(&mut w, 100, tip, 0), Seen::Nothing);
        }
        assert_eq!(w, Watch::default());
    }

    #[test]
    fn three_behind_lags_once_it_lasts_until_it_catches_up() {
        let mut w = Watch::default();
        assert_eq!(judge(&mut w, 100, 97, 0), Seen::Nothing, "one check is not a lag");
        assert_eq!(judge(&mut w, 100, 97, 59), Seen::Nothing, "two, within a minute");
        assert_eq!(judge(&mut w, 100, 97, 60), Seen::Lags);
        assert_eq!(judge(&mut w, 100, 97, 120), Seen::Nothing, "said once");
        assert!(w.lagging);
        assert_eq!(judge(&mut w, 100, 99, 180), Seen::Nothing);
        assert_eq!((w.lagging, w.behind_since, w.behind_checks), (false, None, 0));
    }

    #[test]
    fn a_burst_of_blocks_raises_nothing() {
        // 100 blocks at once: each new tip is checked at once, and the server catches up in seconds.
        let mut w = Watch::default();
        for (i, tip) in (110..=200).step_by(10).enumerate() {
            assert_eq!(judge(&mut w, tip, tip - 6, i as u64), Seen::Nothing, "tip {tip}");
        }
        assert_eq!(judge(&mut w, 200, 200, 15), Seen::Nothing);
        assert_eq!(judge(&mut w, 210, 204, 600), Seen::Nothing, "behind again later, once");
        assert!(!w.lagging);
    }

    #[test]
    fn three_ahead_for_half_an_hour_says_the_authority_is_behind_once() {
        let mut w = Watch::default();
        assert_eq!(judge(&mut w, 100, 103, 0), Seen::Nothing);
        assert_eq!(judge(&mut w, 100, 103, AHEAD_ALERT_SECS - 1), Seen::Nothing);
        assert_eq!(judge(&mut w, 100, 104, AHEAD_ALERT_SECS), Seen::AuthorityBehind);
        assert_eq!(judge(&mut w, 100, 105, AHEAD_ALERT_SECS + 600), Seen::Nothing, "said once");
        // Level again: the clock restarts, and a later lead is news.
        assert_eq!(judge(&mut w, 104, 105, AHEAD_ALERT_SECS + 1200), Seen::Nothing);
        assert_eq!((w.ahead_since, w.ahead), (None, false));
        assert_eq!(judge(&mut w, 104, 110, 4000), Seen::Nothing);
        assert_eq!(judge(&mut w, 104, 110, 4000 + AHEAD_ALERT_SECS), Seen::AuthorityBehind);
    }

    #[test]
    fn checks_come_every_ten_minutes_or_so() {
        for _ in 0..20 {
            assert!((480..=720).contains(&next_delay_secs()));
        }
    }
}
