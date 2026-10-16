//! One header store per network, shared by the wallets on it: `<data>/headers/<network>.db`.
//! Headers are public, so a new wallet, a reset database key or a second wallet reads them here
//! instead of from the network. Plain SQLite, and nothing in it is taken as stored: each load
//! checks the chain from its checkpoint as a source's headers are checked, and a write keeps the
//! chain with the most work, in one transaction.

use std::path::{Path, PathBuf};
use std::time::Duration;

use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::pow::Work;
use bitcoin::BlockHash;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use crate::headers::HeaderChain;
use crate::network::BNetwork;

const FORMAT: &str = "1";
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS headers (height INTEGER PRIMARY KEY, header BLOB NOT NULL, hash BLOB NOT NULL);
";

/// What a write did with a wallet's chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    /// The store holds the chain now.
    Stored,
    /// The store held it already, or a chain with as much work or more where the two part.
    Kept,
    /// The store and the chain share no checkpoint yet: the wallet keeps its chain itself.
    Detached,
}

pub struct SharedHeaders {
    conn: Connection,
    net: BNetwork,
    path: PathBuf,
}

fn sql(e: rusqlite::Error) -> String {
    format!("shared headers: {e}")
}

fn remove(path: &Path) {
    for p in [path.to_path_buf(), path.with_extension("db-wal"), path.with_extension("db-shm")] {
        let _ = std::fs::remove_file(p);
    }
}

fn meta(conn: &Connection, key: &str) -> Result<Option<String>, String> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional().map_err(sql)
}

fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<(), String> {
    conn.execute("INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2", params![key, value]).map(|_| ()).map_err(sql)
}

fn stored_hash(tx: &Transaction, height: u32) -> Result<Option<BlockHash>, String> {
    let raw: Option<Vec<u8>> = tx.query_row("SELECT hash FROM headers WHERE height = ?1", [height], |r| r.get(0)).optional().map_err(sql)?;
    Ok(raw.and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()).map(BlockHash::from_byte_array))
}

/// The chain's headers from `from` up, in the store.
fn insert(tx: &Transaction, chain: &HeaderChain, from: u32, to: u32) -> Result<(), String> {
    let mut st = tx.prepare("INSERT OR REPLACE INTO headers (height, header, hash) VALUES (?1, ?2, ?3)").map_err(sql)?;
    for (h, header) in chain.headers_from(from).take_while(|(h, _)| *h <= to) {
        let hash = chain.hash_at(h).expect("a height the chain holds");
        st.execute(params![h, serialize(header), hash.to_byte_array().to_vec()]).map_err(sql)?;
    }
    Ok(())
}

impl SharedHeaders {
    /// Opens `dir/<network>.db`; a file that isn't one is removed and started again.
    pub fn open(dir: &Path, net: BNetwork) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("shared headers: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let path = dir.join(format!("{}.db", net.name()));
        Self::open_at(&path, net).or_else(|(bad, e)| {
            // Only a file that is no store of this network's starts again: a busy one is another writer's.
            if !bad {
                return Err(e);
            }
            tracing::warn!(target: "bitcoin", "{e}: {} starts again", path.display());
            remove(&path);
            Self::open_at(&path, net).map_err(|(_, e)| e)
        })
    }

    /// The error says whether the file is no store of this network's (true) or merely unavailable.
    fn open_at(path: &Path, net: BNetwork) -> Result<Self, (bool, String)> {
        let bad = |e: rusqlite::Error| {
            let corrupt = matches!(e.sqlite_error_code(), Some(rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt));
            (corrupt, sql(e))
        };
        let mut conn = Connection::open(path).map_err(bad)?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(bad)?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).map_err(bad)?;
        // A journal mode switch can be refused at once while another opener holds the file, without
        // waiting on the busy timeout: so it is asked again for as long.
        let t0 = std::time::Instant::now();
        loop {
            match conn.execute_batch("PRAGMA journal_mode = WAL;") {
                Ok(()) => break,
                Err(e) if t0.elapsed() < Duration::from_secs(5)
                    && matches!(e.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)) =>
                {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(e) => return Err(bad(e)),
            }
        }
        // One transaction, so a second opener never sees the store half made.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(bad)?;
        tx.execute_batch(SCHEMA).map_err(bad)?;
        match (meta(&tx, "network").map_err(|e| (false, e))?, meta(&tx, "format").map_err(|e| (false, e))?) {
            (None, None) => {
                set_meta(&tx, "network", net.name()).map_err(|e| (false, e))?;
                set_meta(&tx, "format", FORMAT).map_err(|e| (false, e))?;
            }
            (Some(n), Some(f)) if n == net.name() && f == FORMAT => {}
            _ => return Err((true, "shared headers: another network's or another format".into())),
        }
        tx.commit().map_err(bad)?;
        crate::storage::restrict(path);
        Ok(Self { conn, net, path: path.to_path_buf() })
    }

    /// The stored chain, checked from its checkpoint as a source's headers are: linkage, proof of
    /// work, the difficulty rules, the time rules. A header that fails is cut off with all above
    /// it, to be read from the network again; a store that can't be read starts again.
    pub fn load(&mut self, now: u32) -> Option<HeaderChain> {
        match self.load_checked(now) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(target: "bitcoin", "{e}: {} starts again", self.path.display());
                let _ = self.conn.execute_batch("DELETE FROM headers; DELETE FROM meta WHERE key = 'base';");
                None
            }
        }
    }

    fn load_checked(&mut self, now: u32) -> Result<Option<HeaderChain>, String> {
        let Some(base) = meta(&self.conn, "base")?.and_then(|b| b.parse::<u32>().ok()) else { return Ok(None) };
        let cp = self.net.checkpoint_at(base).ok_or_else(|| format!("shared headers: {base} is no checkpoint of {}", self.net.name()))?;
        let mut st = self.conn.prepare("SELECT height, header FROM headers WHERE height >= ?1 ORDER BY height").map_err(sql)?;
        let rows = st.query_map([base], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?))).map_err(sql)?;
        let (mut stored, mut top) = (vec![], base);
        for row in rows {
            let (h, raw) = row.map_err(sql)?;
            top = h;
            match deserialize::<Header>(&raw) {
                Ok(header) if h == base && header != cp.header => return Err("shared headers: the stored checkpoint isn't the network's".into()),
                Ok(header) => stored.push((h, header)),
                Err(_) => break,
            }
        }
        drop(st);
        let chain = HeaderChain::restore_from(self.net, cp, stored, now);
        if chain.tip_height() < top {
            tracing::warn!(target: "bitcoin", "the shared {} headers fail the checks from {}: {} kept, the rest is read again",
                self.net.name(), chain.tip_height() + 1, chain.tip_height() - base);
            self.conn.execute("DELETE FROM headers WHERE height > ?1", [chain.tip_height()]).map_err(sql)?;
        }
        Ok(Some(chain))
    }

    /// Keeps `chain` above where it and the store part, when it holds more work there than the
    /// store does; ties keep the store's. A chain from a lower checkpoint takes the store down to
    /// it once it reaches the store's own.
    pub fn write(&mut self, chain: &HeaderChain) -> Result<Written, String> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sql)?;
        let written = Self::write_in(&tx, chain)?;
        tx.commit().map_err(sql)?;
        Ok(written)
    }

    fn write_in(tx: &Transaction, chain: &HeaderChain) -> Result<Written, String> {
        let cb = chain.base();
        let Some(sb) = meta(tx, "base")?.and_then(|b| b.parse::<u32>().ok()) else {
            insert(tx, chain, cb, chain.tip_height())?;
            set_meta(tx, "base", &cb.to_string())?;
            return Ok(Written::Stored);
        };
        // Where the two meet: the chain's checkpoint in the store, or the store's on the chain.
        let lowered = match sb.cmp(&cb) {
            std::cmp::Ordering::Greater if chain.hash_at(sb).is_some() && chain.hash_at(sb) == stored_hash(tx, sb)? => {
                insert(tx, chain, cb, sb)?;
                set_meta(tx, "base", &cb.to_string())?;
                true
            }
            std::cmp::Ordering::Greater => return Ok(Written::Detached),
            _ if stored_hash(tx, cb)? != chain.hash_at(cb) => return Ok(Written::Detached),
            _ => false,
        };
        let meet = sb.max(cb);
        let stored_tip: u32 = tx.query_row("SELECT max(height) FROM headers", [], |r| r.get(0)).map_err(sql)?;
        // The highest height both hold the same block at, searched down from the lower tip.
        let mut fork = meet;
        let mut hi = stored_tip.min(chain.tip_height());
        'search: while hi > meet {
            let lo = hi.saturating_sub(2_015).max(meet + 1);
            let mut st = tx.prepare("SELECT height, hash FROM headers WHERE height BETWEEN ?1 AND ?2 ORDER BY height DESC").map_err(sql)?;
            let rows = st.query_map([lo, hi], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?))).map_err(sql)?;
            for row in rows {
                let (h, raw) = row.map_err(sql)?;
                if chain.hash_at(h).is_some_and(|ours| ours.to_byte_array().as_slice() == raw.as_slice()) {
                    fork = h;
                    break 'search;
                }
            }
            hi = lo - 1;
        }
        let mut theirs = Work::from_be_bytes([0; 32]);
        {
            let mut st = tx.prepare("SELECT header FROM headers WHERE height > ?1").map_err(sql)?;
            for raw in st.query_map([fork], |r| r.get::<_, Vec<u8>>(0)).map_err(sql)? {
                if let Ok(h) = deserialize::<Header>(&raw.map_err(sql)?) {
                    theirs = theirs + h.work();
                }
            }
        }
        if chain.work_after(fork) > theirs {
            tx.execute("DELETE FROM headers WHERE height > ?1", [fork]).map_err(sql)?;
            insert(tx, chain, fork + 1, chain.tip_height())?;
            return Ok(Written::Stored);
        }
        Ok(if lowered { Written::Stored } else { Written::Kept })
    }

    /// Drops the stored headers from `from` up when they are still the ones the sources disowned.
    pub fn disown(&mut self, from: u32, hash: BlockHash) -> Result<(), String> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sql)?;
        if stored_hash(&tx, from)? == Some(hash) {
            tx.execute("DELETE FROM headers WHERE height >= ?1", [from]).map_err(sql)?;
        }
        tx.commit().map_err(sql)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::tests::regtest_branch;

    const NOW: u32 = 2_000_000_000;

    fn genesis() -> Header {
        BNetwork::Regtest.checkpoint().header
    }

    fn chain_of(n: usize, salt: u32) -> HeaderChain {
        let mut c = HeaderChain::new(BNetwork::Regtest);
        c.try_extend(0, &regtest_branch(&genesis(), n, genesis().time, salt), NOW);
        c
    }

    fn fork_of(c: &HeaderChain, at: u32, n: usize, salt: u32) -> HeaderChain {
        let mut f = c.clone();
        let from = *c.header_at(at).unwrap();
        f.try_extend(at, &regtest_branch(&from, n, from.time + 1, salt), NOW);
        f
    }

    #[test]
    fn a_chain_comes_back_checked() {
        let dir = tempfile::tempdir().unwrap();
        let c = chain_of(3_000, 1);
        let mut s = SharedHeaders::open(dir.path(), BNetwork::Regtest).unwrap();
        assert_eq!(s.load(NOW).map(|c| c.tip_height()), None, "empty");
        assert_eq!(s.write(&c).unwrap(), Written::Stored);
        assert_eq!(s.write(&c).unwrap(), Written::Kept, "the same chain again");
        drop(s);
        let mut s = SharedHeaders::open(dir.path(), BNetwork::Regtest).unwrap();
        let back = s.load(NOW).unwrap();
        assert_eq!((back.tip_height(), back.tip_hash(), back.total_work()), (3_000, c.tip_hash(), c.total_work()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.path().join("regtest.db")).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn the_most_work_chain_stays_and_ties_keep_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = SharedHeaders::open(dir.path(), BNetwork::Regtest).unwrap();
        let a = chain_of(3_000, 2);
        s.write(&a).unwrap();
        // A wallet behind, on the same chain, and one on a lighter or an equal fork: nothing moves.
        let mut behind = a.clone();
        behind.truncate(2_500);
        assert_eq!(s.write(&behind).unwrap(), Written::Kept);
        assert_eq!(s.write(&fork_of(&a, 2_000, 900, 3)).unwrap(), Written::Kept);
        assert_eq!(s.write(&fork_of(&a, 2_000, 1_000, 4)).unwrap(), Written::Kept, "a tie keeps the store's");
        assert_eq!(s.load(NOW).unwrap().tip_hash(), a.tip_hash());
        // A heavier fork replaces what is above the fork, as a reorg does.
        let heavier = fork_of(&a, 2_000, 1_001, 5);
        assert_eq!(s.write(&heavier).unwrap(), Written::Stored);
        let back = s.load(NOW).unwrap();
        assert_eq!((back.tip_height(), back.tip_hash(), back.hash_at(2_000)), (3_001, heavier.tip_hash(), a.hash_at(2_000)));
        // And a wallet extending it, as a new block does.
        let next = fork_of(&heavier, 3_001, 2, 6);
        assert_eq!(s.write(&next).unwrap(), Written::Stored);
        assert_eq!(s.load(NOW).unwrap().tip_hash(), next.tip_hash());
    }

    #[test]
    fn checkpoints_meet_or_the_wallet_keeps_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = SharedHeaders::open(dir.path(), BNetwork::Regtest).unwrap();
        let full = chain_of(3_000, 7);
        // A wallet whose chain starts at 1,000 (as from a higher checkpoint) fills the store first.
        let high = full.suffix(1_000).unwrap();
        assert_eq!(s.write(&high).unwrap(), Written::Stored);
        // One from genesis that hasn't reached 1,000 can't join it yet.
        let mut early = full.clone();
        early.truncate(900);
        assert_eq!(s.write(&early).unwrap(), Written::Detached);
        // Once it has, the store goes down to genesis, and loads from there.
        assert_eq!(s.write(&full).unwrap(), Written::Stored);
        let back = s.load(NOW).unwrap();
        assert_eq!((back.base(), back.tip_height(), back.hash_at(500)), (0, 3_000, full.hash_at(500)));
        // A chain from 1,000 on another branch below it shares no checkpoint with the store.
        let other = chain_of(3_000, 8).suffix(1_000).unwrap();
        assert_eq!(s.write(&other).unwrap(), Written::Detached);
    }

    #[test]
    fn a_tampered_header_is_cut_off_with_all_above_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = SharedHeaders::open(dir.path(), BNetwork::Regtest).unwrap();
        let c = chain_of(3_000, 9);
        s.write(&c).unwrap();
        // Another merkle root at 1,500: regtest's work is no bar, but 1,501 no longer links to it.
        let mut bad = *c.header_at(1_500).unwrap();
        bad.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0xab; 32]);
        s.conn.execute("UPDATE headers SET header = ?1 WHERE height = 1500", params![serialize(&bad)]).unwrap();
        assert!(s.load(NOW).unwrap().tip_height() <= 1_500);
        // A header that doesn't link to the one below it is cut at once.
        bad.prev_blockhash = BlockHash::all_zeros();
        s.conn.execute("UPDATE headers SET header = ?1 WHERE height = 1500", params![serialize(&bad)]).unwrap();
        s.write(&c).unwrap();
        s.conn.execute("UPDATE headers SET header = ?1 WHERE height = 1500", params![serialize(&bad)]).unwrap();
        let back = s.load(NOW).unwrap();
        assert_eq!(back.tip_height(), 1_499);
        let left: u32 = s.conn.query_row("SELECT max(height) FROM headers", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 1_499, "the rest is dropped, to be read again");
        assert_eq!(s.write(&c).unwrap(), Written::Stored);
        assert_eq!(s.load(NOW).unwrap().tip_height(), 3_000);
        // A row that isn't a header at all ends what is kept as well.
        s.conn.execute("UPDATE headers SET header = x'00' WHERE height = 10", []).unwrap();
        assert_eq!(s.load(NOW).unwrap().tip_height(), 9);
    }

    #[test]
    fn a_file_that_is_no_database_starts_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = SharedHeaders::open(dir.path(), BNetwork::Regtest).unwrap();
        s.write(&chain_of(100, 10)).unwrap();
        drop(s);
        let path = dir.path().join("regtest.db");
        remove(&path.with_extension("db-wal"));
        std::fs::write(&path, vec![0x5a; 8192]).unwrap();
        let mut s = SharedHeaders::open(dir.path(), BNetwork::Regtest).unwrap();
        assert!(s.load(NOW).is_none());
        assert_eq!(s.write(&chain_of(100, 10)).unwrap(), Written::Stored);
        // Another network's store under this name is not taken either.
        drop(s);
        std::fs::rename(&path, dir.path().join("signet.db")).unwrap();
        remove(&path);
        let mut s = SharedHeaders::open(dir.path(), BNetwork::Signet).unwrap();
        assert!(s.load(NOW).is_none());
    }

    #[test]
    fn two_writers_end_with_the_heavier_chain() {
        let dir = tempfile::tempdir().unwrap();
        let base = chain_of(2_000, 11);
        let (a, b) = (fork_of(&base, 1_500, 600, 12), fork_of(&base, 1_500, 700, 13));
        std::thread::scope(|scope| {
            for c in [&a, &b] {
                let dir = dir.path();
                scope.spawn(move || {
                    let mut s = SharedHeaders::open(dir, BNetwork::Regtest).unwrap();
                    for _ in 0..5 {
                        s.write(c).unwrap();
                    }
                });
            }
        });
        let mut s = SharedHeaders::open(dir.path(), BNetwork::Regtest).unwrap();
        assert_eq!(s.load(NOW).unwrap().tip_hash(), b.tip_hash());
        // Headers sources disowned are dropped, unless the store moved on meanwhile.
        s.disown(1_501, a.hash_at(1_501).unwrap()).unwrap();
        assert_eq!(s.load(NOW).unwrap().tip_height(), 2_200);
        s.disown(1_501, b.hash_at(1_501).unwrap()).unwrap();
        assert_eq!(s.load(NOW).unwrap().tip_height(), 1_500);
    }
}
