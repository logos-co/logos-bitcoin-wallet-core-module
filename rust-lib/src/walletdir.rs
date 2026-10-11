//! A wallet on disk: `wallets/<network>/<group>/` (0700) with public metadata and the encrypted
//! database (0600). No key material and no descriptors outside the encrypted database.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::network::{BNetwork, Family};
use crate::storage::{open_encrypted, StorageError};


const META: &str = "wallet.json";
const DB: &str = "wallet.db";
const FORMAT: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum DirError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("wallet files: {0}")]
    Io(#[from] std::io::Error),
    #[error("wallet.json: {0}")]
    Meta(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub format: u32,
    pub group: String,
    pub family: Family,
    pub network: BNetwork,
    pub created_at: u64,
}

pub struct WalletDir {
    pub path: PathBuf,
}

/// The keystore's group ids become directory names, so only plain ones are taken.
pub fn valid_group(g: &str) -> bool {
    g.starts_with("g_") && g.len() <= 80 && g.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn private_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(tmp, path)
}

impl WalletDir {
    pub fn new(root: &Path, network: BNetwork, group: &str) -> Self {
        Self { path: root.join(network.name()).join(group) }
    }

    pub fn exists(&self) -> bool {
        self.path.join(META).exists() && self.path.join(DB).exists()
    }

    pub fn meta(&self) -> Result<Meta, DirError> {
        let raw = fs::read(self.path.join(META))?;
        serde_json::from_slice(&raw).map_err(|e| DirError::Meta(e.to_string()))
    }

    /// Opens the database, creating the directory and metadata for a new wallet.
    pub fn open(&self, root: &Path, meta: &Meta, key: &[u8; 32]) -> Result<Connection, DirError> {
        private_dir(root)?;
        if let Some(parent) = self.path.parent() {
            private_dir(parent)?;
        }
        private_dir(&self.path)?;
        let conn = open_encrypted(&self.path.join(DB), key)?;
        if !self.path.join(META).exists() {
            write_private(&self.path.join(META), &serde_json::to_vec_pretty(meta).expect("plain struct"))?;
        }
        Ok(conn)
    }

    /// Moves a database the key no longer opens out of the way, keeping it for the person.
    pub fn set_aside(&self) -> Result<PathBuf, DirError> {
        let stamp = now_secs();
        let aside = self.path.join(format!("{DB}.unreadable-{stamp}"));
        fs::rename(self.path.join(DB), &aside)?;
        for ext in ["-wal", "-shm"] {
            let p = self.path.join(format!("{DB}{ext}"));
            if p.exists() {
                fs::rename(&p, self.path.join(format!("{DB}.unreadable-{stamp}{ext}")))?;
            }
        }
        Ok(aside)
    }

    pub fn new_meta(group: &str, family: Family, network: BNetwork) -> Meta {
        Meta { format: FORMAT, group: group.into(), family, network, created_at: now_secs() }
    }
}

/// The wallets known on a network, in group order.
pub fn list(root: &Path, network: BNetwork) -> Vec<Meta> {
    let mut out = vec![];
    if let Ok(entries) = fs::read_dir(root.join(network.name())) {
        for e in entries.flatten() {
            let w = WalletDir { path: e.path() };
            if let Ok(m) = w.meta() {
                if w.exists() {
                    out.push(m);
                }
            }
        }
    }
    out.sort_by(|a, b| a.group.cmp(&b.group));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_and_listing() {
        let root = tempfile::tempdir().unwrap();
        let wallets = root.path().join("wallets");
        let w = WalletDir::new(&wallets, BNetwork::Signet, "g_abc");
        let meta = WalletDir::new_meta("g_abc", Family::Bitcoin, BNetwork::Signet);
        assert!(!w.exists());
        drop(w.open(&wallets, &meta, &[1; 32]).unwrap());
        assert!(w.exists());
        assert_eq!(w.meta().unwrap().family, Family::Bitcoin);
        assert_eq!(list(&wallets, BNetwork::Signet).len(), 1);
        assert!(list(&wallets, BNetwork::Mainnet).is_empty());
        let raw = fs::read_to_string(w.path.join("wallet.json")).unwrap();
        assert!(!raw.contains("pub") && !raw.contains("key"), "no descriptors or keys in plain files: {raw}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&wallets).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(fs::metadata(w.path.join("wallet.json")).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn a_database_the_key_no_longer_opens_is_set_aside() {
        let root = tempfile::tempdir().unwrap();
        let wallets = root.path().join("wallets");
        let w = WalletDir::new(&wallets, BNetwork::Signet, "g_abc");
        let meta = WalletDir::new_meta("g_abc", Family::Bitcoin, BNetwork::Signet);
        drop(w.open(&wallets, &meta, &[1; 32]).unwrap());
        assert!(matches!(w.open(&wallets, &meta, &[2; 32]), Err(DirError::Storage(StorageError::WrongKey))));
        let aside = w.set_aside().unwrap();
        assert!(aside.exists() && !w.path.join("wallet.db").exists());
        drop(w.open(&wallets, &meta, &[2; 32]).unwrap());
        assert!(w.exists(), "a fresh database under the new key");
    }

    #[test]
    fn group_names() {
        assert!(valid_group("g_0123abcd"));
        assert!(!valid_group("../g_x"));
        assert!(!valid_group("x_123"));
        assert!(!valid_group("g_a/b"));
    }
}
