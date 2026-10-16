//! Cross-checks: each enabled server's tip and one header at a random height, against the chain
//! authority. Never the heights of the wallet's own transactions.

use bitcoin::BlockHash;
use rand::Rng;
use serde::Serialize;

/// Tips this close count as the same chain, once the hashes agree at the lower one.
pub const TIP_SLACK: u32 = 2;
/// A server ahead this long means the authority may be held back.
pub const AHEAD_ALERT_SECS: u64 = 30 * 60;
/// Checks run on every new authority tip and at least this often, with jitter.
pub const INTERVAL_SECS: u64 = 10 * 60;
/// A server is stale once it lags in this many checks in a row, the first this long ago: a burst
/// of blocks leaves an honest server behind for a moment.
pub const STALE_CHECKS: u32 = 2;
pub const STALE_AFTER_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Agrees,
    /// Behind by more than the slack, in checks over a minute apart: not used for history or
    /// pending until it catches up.
    Stale,
    /// Ahead by more than the slack for half an hour. Its chain is never adopted.
    AuthorityBehind,
    /// Another block below the tip, still there after the next block.
    Suspect,
}

/// What one server said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    pub tip: u32,
    /// The server's hash at `min(tip, authority tip)`.
    pub hash_at_lower: Option<BlockHash>,
    /// The server's hash at the random height asked.
    pub random: Option<(u32, BlockHash)>,
}

/// Per server memory between checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Track {
    pub ahead_since: Option<u64>,
    /// When the server was first seen behind, and in how many checks in a row since.
    pub behind_since: Option<u64>,
    pub behind_checks: u32,
    /// The authority tip when a mismatch was first seen.
    pub mismatch_at: Option<u32>,
    pub verdict: Option<Verdict>,
}

/// Judges an answer against the authority's tip and its hashes.
pub fn judge(track: &mut Track, auth_tip: u32, auth_hash: &dyn Fn(u32) -> Option<BlockHash>, answer: &Answer, now: u64) -> Verdict {
    let lower = answer.tip.min(auth_tip);
    let differs_at_lower = matches!((answer.hash_at_lower, auth_hash(lower)), (Some(a), Some(b)) if a != b);
    let differs_random = answer.random.is_some_and(|(h, hash)| h <= lower && auth_hash(h).is_some_and(|ours| ours != hash));
    let verdict = if differs_at_lower || differs_random {
        // A one-block race at the tip settles itself; a mismatch that survives a new block does not.
        match track.mismatch_at {
            Some(seen) if auth_tip > seen => Verdict::Suspect,
            Some(_) => track.verdict.unwrap_or(Verdict::Agrees),
            None => {
                track.mismatch_at = Some(auth_tip);
                track.verdict.unwrap_or(Verdict::Agrees)
            }
        }
    } else {
        track.mismatch_at = None;
        if answer.tip + TIP_SLACK < auth_tip {
            let since = *track.behind_since.get_or_insert(now);
            track.behind_checks += 1;
            if track.behind_checks >= STALE_CHECKS && now.saturating_sub(since) >= STALE_AFTER_SECS { Verdict::Stale } else { Verdict::Agrees }
        } else if answer.tip > auth_tip + TIP_SLACK {
            let since = *track.ahead_since.get_or_insert(now);
            if now.saturating_sub(since) >= AHEAD_ALERT_SECS { Verdict::AuthorityBehind } else { Verdict::Agrees }
        } else {
            Verdict::Agrees
        }
    };
    if answer.tip <= auth_tip + TIP_SLACK {
        track.ahead_since = None;
    }
    if answer.tip + TIP_SLACK >= auth_tip {
        (track.behind_since, track.behind_checks) = (None, 0);
    }
    // A suspect stays suspect until the backend clears it.
    if track.verdict == Some(Verdict::Suspect) {
        return Verdict::Suspect;
    }
    track.verdict = Some(verdict);
    verdict
}

/// A height between the wallet's birthday and the tip, never one of the wallet's own.
pub fn random_height(birthday: u32, tip: u32, avoid: &dyn Fn(u32) -> bool) -> Option<u32> {
    if tip <= birthday {
        return None;
    }
    let mut rng = rand::thread_rng();
    if let Some(h) = (0..16).map(|_| rng.gen_range(birthday..=tip)).find(|h| !avoid(*h)) {
        return Some(h);
    }
    // Nearly all the wallet's own: walk on from a random height, so one that isn't is still found.
    let span = u64::from(tip - birthday) + 1;
    let start = rng.gen_range(0..span);
    (0..span).map(|i| birthday + ((start + i) % span) as u32).find(|h| !avoid(*h))
}

/// The next scheduled check: the interval, plus or minus a fifth.
pub fn next_delay_secs() -> u64 {
    let jitter = INTERVAL_SECS / 5;
    rand::thread_rng().gen_range(INTERVAL_SECS - jitter..=INTERVAL_SECS + jitter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn bh(n: u32) -> BlockHash {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.to_le_bytes());
        BlockHash::from_byte_array(b)
    }

    fn ours(h: u32) -> Option<BlockHash> {
        Some(bh(h))
    }

    fn answer(tip: u32, auth_tip: u32) -> Answer {
        Answer { tip, hash_at_lower: Some(bh(tip.min(auth_tip))), random: None }
    }

    #[test]
    fn same_or_close_tips_agree() {
        let mut t = Track::default();
        assert_eq!(judge(&mut t, 100, &ours, &answer(100, 100), 0), Verdict::Agrees);
        assert_eq!(judge(&mut t, 100, &ours, &answer(98, 100), 0), Verdict::Agrees);
        assert_eq!(judge(&mut t, 100, &ours, &answer(102, 100), 0), Verdict::Agrees);
    }

    #[test]
    fn three_behind_is_stale_once_it_lasts_until_it_catches_up() {
        let mut t = Track::default();
        assert_eq!(judge(&mut t, 100, &ours, &answer(97, 100), 0), Verdict::Agrees, "one check is not a lag");
        assert_eq!(judge(&mut t, 100, &ours, &answer(97, 100), 59), Verdict::Agrees, "two, within a minute");
        assert_eq!(judge(&mut t, 100, &ours, &answer(97, 100), 60), Verdict::Stale);
        assert_eq!(judge(&mut t, 100, &ours, &answer(99, 100), 120), Verdict::Agrees);
        assert_eq!((t.behind_since, t.behind_checks), (None, 0));
    }

    #[test]
    fn a_burst_of_blocks_raises_nothing() {
        // 100 blocks at once: each new tip is checked at once, and the server catches up in seconds.
        let mut t = Track::default();
        for (i, tip) in (110..=200).step_by(10).enumerate() {
            let behind = if tip == 200 { 194 } else { tip - 6 };
            assert_eq!(judge(&mut t, tip, &ours, &answer(behind, tip), i as u64), Verdict::Agrees, "tip {tip}");
        }
        assert_eq!(judge(&mut t, 200, &ours, &answer(200, 200), 15), Verdict::Agrees);
        // Behind again later, once: still nothing.
        assert_eq!(judge(&mut t, 210, &ours, &answer(204, 210), 600), Verdict::Agrees);
    }

    #[test]
    fn three_ahead_for_half_an_hour_says_the_authority_is_behind() {
        let mut t = Track::default();
        assert_eq!(judge(&mut t, 100, &ours, &answer(103, 100), 0), Verdict::Agrees);
        assert_eq!(judge(&mut t, 100, &ours, &answer(103, 100), AHEAD_ALERT_SECS - 1), Verdict::Agrees);
        assert_eq!(judge(&mut t, 100, &ours, &answer(104, 100), AHEAD_ALERT_SECS), Verdict::AuthorityBehind);
        // Back within the slack: the clock restarts.
        assert_eq!(judge(&mut t, 103, &ours, &answer(104, 103), AHEAD_ALERT_SECS + 1), Verdict::Agrees);
        assert_eq!(t.ahead_since, None);
    }

    #[test]
    fn a_different_hash_is_suspect_only_after_the_next_block() {
        let mut t = Track::default();
        let forked = Answer { tip: 100, hash_at_lower: Some(bh(9_999)), random: None };
        assert_eq!(judge(&mut t, 100, &ours, &forked, 0), Verdict::Agrees, "a tip race settles itself");
        assert_eq!(judge(&mut t, 100, &ours, &forked, 60), Verdict::Agrees);
        let still = Answer { tip: 101, hash_at_lower: Some(bh(9_999)), random: None };
        assert_eq!(judge(&mut t, 101, &ours, &still, 600), Verdict::Suspect);
        // Suspect sticks, even when the server later agrees.
        assert_eq!(judge(&mut t, 102, &ours, &answer(102, 102), 1200), Verdict::Suspect);
    }

    #[test]
    fn a_race_that_resolves_clears_the_mismatch() {
        let mut t = Track::default();
        let forked = Answer { tip: 100, hash_at_lower: Some(bh(9_999)), random: None };
        judge(&mut t, 100, &ours, &forked, 0);
        assert_eq!(judge(&mut t, 101, &ours, &answer(101, 101), 600), Verdict::Agrees);
        assert_eq!(t.mismatch_at, None);
    }

    #[test]
    fn the_random_header_counts_too() {
        let mut t = Track::default();
        let lying = Answer { tip: 100, hash_at_lower: Some(bh(100)), random: Some((40, bh(1)))};
        judge(&mut t, 100, &ours, &lying, 0);
        let again = Answer { tip: 101, hash_at_lower: Some(bh(101)), random: Some((60, bh(2))) };
        assert_eq!(judge(&mut t, 101, &ours, &again, 600), Verdict::Suspect);
    }

    #[test]
    fn random_heights_avoid_the_wallets_own() {
        for _ in 0..50 {
            let h = random_height(10, 20, &|h| h % 2 == 0).unwrap();
            assert!(h % 2 == 1 && (10..=20).contains(&h));
        }
        assert_eq!(random_height(20, 20, &|_| false), None);
        // One height left that isn't the wallet's: always found, never a lost draw.
        for _ in 0..50 {
            assert_eq!(random_height(10, 20, &|h| h != 17), Some(17));
        }
        assert_eq!(random_height(10, 20, &|_| true), None);
        let d = next_delay_secs();
        assert!((480..=720).contains(&d));
    }
}
