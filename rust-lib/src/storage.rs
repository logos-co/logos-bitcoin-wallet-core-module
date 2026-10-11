//! The wallet database: SQLCipher under the key the keystore releases, holding BDK's tables and
//! the core's own (headers, held anchors, exposure, suspects, sends).

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("wrong key, or not a wallet database")]
    WrongKey,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS core_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS core_headers (height INTEGER PRIMARY KEY, header BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS core_old_hashes (height INTEGER PRIMARY KEY, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS core_held (txid TEXT NOT NULL, height INTEGER NOT NULL, hash TEXT NOT NULL,
    time INTEGER NOT NULL, source TEXT NOT NULL, PRIMARY KEY (txid, hash));
CREATE TABLE IF NOT EXISTS core_exposure (source TEXT PRIMARY KEY, url TEXT NOT NULL, operator TEXT NOT NULL,
    role TEXT NOT NULL, since INTEGER NOT NULL, last INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS core_suspects (source TEXT PRIMARY KEY, reason TEXT NOT NULL, since INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS core_reported (txid TEXT PRIMARY KEY, source TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS core_sends (txid TEXT PRIMARY KEY, raw BLOB NOT NULL, inputs TEXT NOT NULL,
    state TEXT NOT NULL, created INTEGER NOT NULL, replaces TEXT, via TEXT, broadcast TEXT);
";

/// Opens (or creates) the encrypted database with a raw 256-bit key.
pub fn open_encrypted(path: &Path, key: &[u8; 32]) -> Result<Connection, StorageError> {
    let conn = Connection::open(path)?;
    let mut pragma = format!("PRAGMA key = \"x'{}'\";", hex::encode(key));
    let keyed = conn.execute_batch(&pragma);
    zeroize::Zeroize::zeroize(&mut pragma);
    keyed?;
    // A wrong key only shows when the first page is read.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).map_err(|_| StorageError::WrongKey)?;
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
    conn.execute_batch(SCHEMA)?;
    restrict(path);
    Ok(conn)
}

/// Owner-only files; the directory above is 0700. On Windows the profile's ACL already is.
#[cfg_attr(not(unix), allow(unused_variables))]
pub fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [path.to_path_buf(), path.with_extension("db-wal"), path.with_extension("db-shm")] {
            if p.exists() {
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

pub fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>, StorageError> {
    Ok(conn.query_row("SELECT value FROM core_meta WHERE key = ?1", [key], |r| r.get(0)).optional()?)
}

pub fn meta_set(conn: &Connection, key: &str, value: &str) -> Result<(), StorageError> {
    conn.execute("INSERT INTO core_meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2", params![key, value])?;
    Ok(())
}

/// Logs to `core.log` in the persistence directory, restarting it past 10 MB. Never logs secrets:
/// callers pass heights, counts, txids, source ids and errors.
pub fn init_log(dir: &Path) {
    let path = dir.join("core.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 10 * 1024 * 1024) {
        let _ = std::fs::remove_file(&path);
    }
    if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = tracing_subscriber::fmt()
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .try_init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_database_is_encrypted_and_a_wrong_key_reads_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.db");
        let conn = open_encrypted(&path, &[7; 32]).unwrap();
        let v: String = conn.query_row("PRAGMA cipher_version", [], |r| r.get(0)).unwrap();
        assert!(!v.is_empty());
        meta_set(&conn, "birthday", "481824").unwrap();
        assert_eq!(meta_get(&conn, "birthday").unwrap().as_deref(), Some("481824"));
        drop(conn);
        assert!(matches!(open_encrypted(&path, &[8; 32]), Err(StorageError::WrongKey)));
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(15).any(|w| w == b"SQLite format 3"));
        assert!(!raw.windows(6).any(|w| w == b"481824"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
