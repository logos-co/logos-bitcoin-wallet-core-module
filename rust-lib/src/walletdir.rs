//! A wallet on disk: `wallets/<network>/w_<32 hex>/` (0700), a random name, with `wallet.json` and
//! the encrypted database (0600). `wallet.json` names only its format and its seed; which account
//! it holds is sealed in it under the core's key for that seed's wallets, read only while the seed
//! is unlocked. No key material and no descriptors outside the encrypted database.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use logos_signer_interface::wallets::{self, DataKey};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::network::{BNetwork, Family};
use crate::storage::{open_encrypted, StorageError};

const META: &str = "wallet.json";
const DB: &str = "wallet.db";
const FORMAT: u32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum DirError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("wallet files: {0}")]
    Io(#[from] std::io::Error),
    #[error("wallet.json: {0}")]
    Meta(String),
}

/// `wallet.json` as written.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Plain {
    format: u32,
    seed: String,
    about: String,
}

/// What the box in `wallet.json` holds, and what `list_wallets` shows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub format: u32,
    /// The account id it was last opened by.
    pub group: String,
    /// Its database's scope ([`crate::manager::database_scope`]), the same whichever signer opens it.
    pub account: String,
    pub seed: String,
    pub family: Family,
    pub network: BNetwork,
    pub created_at: u64,
}

/// The core's key for a seed's wallet files at a generation; `None` while the seed is locked.
pub type Keys<'a> = &'a dyn Fn(&str, u32) -> Option<DataKey>;

pub struct WalletDir {
    pub path: PathBuf,
}

/// Account ids (a keystore group `g_…`, a device's `shell-…`, `keycard-…`) are kept in the box and
/// shown, so only plain ones are taken: never `.`, `..`, a separator or a name Windows reserves.
pub fn valid_group(g: &str) -> bool {
    let b = g.as_bytes();
    let windows = ["con", "prn", "aux", "nul"].iter().any(|r| g.eq_ignore_ascii_case(r))
        || (b.len() == 4 && (b[..3].eq_ignore_ascii_case(b"com") || b[..3].eq_ignore_ascii_case(b"lpt")) && b[3].is_ascii_digit());
    !b.is_empty() && b.len() <= 80 && b[0] != b'.' && !windows && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
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

/// A key from `data_key` as SQLCipher takes it.
pub fn raw(key: &DataKey) -> Result<Zeroizing<[u8; 32]>, DirError> {
    let mut out = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(key.key.expose(), &mut out[..]).map_err(|_| DirError::Meta("the data key is not 32 bytes of hex".into()))?;
    Ok(out)
}

impl WalletDir {
    /// A new directory under a random name, not made until [`WalletDir::open`].
    pub fn create(root: &Path, network: BNetwork) -> Self {
        Self { path: root.join(network.name()).join(format!("w_{}", hex::encode(rand::random::<[u8; 16]>()))) }
    }

    pub fn exists(&self) -> bool {
        self.path.join(META).exists() && self.path.join(DB).exists()
    }

    /// The box's associated data: the directory's own name, so one can't stand in for another.
    fn aad(&self) -> String {
        format!("bitcoin_wallet_core wallet.json\0{}", self.path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default())
    }

    fn plain(&self) -> Result<Plain, DirError> {
        let raw = fs::read(self.path.join(META))?;
        let p: Plain = serde_json::from_slice(&raw).map_err(|e| DirError::Meta(e.to_string()))?;
        if p.format != FORMAT {
            return Err(DirError::Meta(format!("format {}", p.format)));
        }
        Ok(p)
    }

    /// The seed it belongs to and the generation its box is sealed under, without any key.
    pub fn sealed(&self) -> Result<(String, u32), DirError> {
        let p = self.plain()?;
        let g = wallets::generation(&p.about).map_err(|e| DirError::Meta(e.message))?;
        Ok((p.seed, g))
    }

    pub fn meta(&self, key: &DataKey) -> Result<Meta, DirError> {
        let p = self.plain()?;
        let plain = wallets::open(key, &p.about, &self.aad()).map_err(|e| DirError::Meta(e.message))?;
        serde_json::from_slice(&plain).map_err(|e| DirError::Meta(e.to_string()))
    }

    /// Opens the database, creating the directory for a new wallet, and seals `meta` again under
    /// `files`, the seed's current key for its wallet files.
    pub fn open(&self, root: &Path, meta: &Meta, files: &DataKey, key: &[u8; 32]) -> Result<Connection, DirError> {
        let conn = self.open_db(root, key)?;
        self.seal(meta, files)?;
        Ok(conn)
    }

    pub fn open_db(&self, root: &Path, key: &[u8; 32]) -> Result<Connection, DirError> {
        private_dir(root)?;
        if let Some(parent) = self.path.parent() {
            private_dir(parent)?;
        }
        private_dir(&self.path)?;
        Ok(open_encrypted(&self.path.join(DB), key)?)
    }

    pub fn seal(&self, meta: &Meta, files: &DataKey) -> Result<(), DirError> {
        let body = serde_json::to_vec(meta).expect("plain struct");
        let about = wallets::seal(files, &body, &self.aad()).map_err(|e| DirError::Meta(e.message))?;
        let plain = Plain { format: FORMAT, seed: meta.seed.clone(), about };
        write_private(&self.path.join(META), &serde_json::to_vec_pretty(&plain).expect("plain struct"))?;
        Ok(())
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

    pub fn new_meta(group: &str, account: &str, seed: &str, family: Family, network: BNetwork) -> Meta {
        Meta { format: FORMAT, group: group.into(), account: account.into(), seed: seed.into(), family, network, created_at: now_secs() }
    }
}

fn dirs(root: &Path, network: BNetwork) -> Vec<WalletDir> {
    let mut out = vec![];
    if let Ok(entries) = fs::read_dir(root.join(network.name())) {
        for e in entries.flatten() {
            let w = WalletDir { path: e.path() };
            if w.exists() {
                out.push(w);
            }
        }
    }
    out
}

/// The wallets on a network whose seeds are unlocked, in group order, and how many are locked.
pub fn list(root: &Path, network: BNetwork, keys: Keys) -> (Vec<Meta>, usize) {
    let (mut out, mut locked) = (vec![], 0);
    for w in dirs(root, network) {
        let Ok((seed, g)) = w.sealed() else { continue };
        match keys(&seed, g) {
            Some(k) => out.extend(w.meta(&k).ok()),
            None => locked += 1,
        }
    }
    out.sort_by(|a, b| a.group.cmp(&b.group));
    (out, locked)
}

/// The directory holding a seed's account, its metadata and the generation it is sealed under.
pub fn find(root: &Path, network: BNetwork, seed: &str, account: &str, keys: Keys) -> Option<(WalletDir, Meta, u32)> {
    dirs(root, network).into_iter().find_map(|w| {
        let (s, g) = w.sealed().ok()?;
        if s != seed {
            return None;
        }
        let m = w.meta(&keys(&s, g)?).ok()?;
        (m.account == account).then_some((w, m, g))
    })
}

/// Every seed with wallet files on any network, with the generations they are sealed under.
pub fn seeds(root: &Path) -> BTreeMap<String, BTreeSet<u32>> {
    let mut out: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    for n in [BNetwork::Mainnet, BNetwork::Testnet4, BNetwork::Signet, BNetwork::Regtest] {
        for w in dirs(root, n) {
            if let Ok((seed, g)) = w.sealed() {
                out.entry(seed).or_default().insert(g);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use logos_signer_interface::Secret;

    fn key(byte: u8, generation: u32) -> DataKey {
        DataKey { key: Secret::new(hex::encode([byte; 32])), generation }
    }

    fn unlocked(seed: &str, g: u32) -> Option<DataKey> {
        (seed == "s_1").then(|| key(1, g))
    }

    #[test]
    fn layout_and_listing() {
        let root = tempfile::tempdir().unwrap();
        let wallets = root.path().join("wallets");
        let w = WalletDir::create(&wallets, BNetwork::Signet);
        let meta = WalletDir::new_meta("g_abc", "wallet/btc_1", "s_1", Family::Bitcoin, BNetwork::Signet);
        assert!(!w.exists());
        drop(w.open(&wallets, &meta, &key(1, 0), &[1; 32]).unwrap());
        assert!(w.exists());
        let name = w.path.file_name().unwrap().to_str().unwrap().to_string();
        assert!(name.starts_with("w_") && name.len() == 34, "{name}");
        assert_eq!(w.meta(&key(1, 0)).unwrap(), meta);
        assert!(w.meta(&key(2, 0)).is_err(), "another key");
        assert_eq!(list(&wallets, BNetwork::Signet, &unlocked), (vec![meta.clone()], 0));
        assert_eq!(list(&wallets, BNetwork::Signet, &|_, _| None), (vec![], 1), "a locked seed's wallet isn't listed");
        assert!(list(&wallets, BNetwork::Mainnet, &unlocked).0.is_empty());
        let raw = fs::read_to_string(w.path.join("wallet.json")).unwrap();
        for hidden in ["g_abc", "btc_1", "bitcoin", "pub", "key"] {
            assert!(!raw.contains(hidden), "{hidden} in plain wallet.json: {raw}");
        }
        assert_eq!(seeds(&wallets), BTreeMap::from([("s_1".to_string(), BTreeSet::from([0]))]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&wallets).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(fs::metadata(w.path.join("wallet.json")).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn a_wallet_is_found_by_its_seed_and_account() {
        let root = tempfile::tempdir().unwrap();
        let wallets = root.path().join("wallets");
        for (account, seed) in [("wallet/btc_1", "s_1"), ("wallet/btc_2", "s_1"), ("wallet/btc_1", "s_2")] {
            let w = WalletDir::create(&wallets, BNetwork::Regtest);
            let k = if seed == "s_1" { key(1, 0) } else { key(2, 0) };
            drop(w.open(&wallets, &WalletDir::new_meta("g_x", account, seed, Family::Bitcoin, BNetwork::Regtest), &k, &[3; 32]).unwrap());
        }
        let (w, m, g) = find(&wallets, BNetwork::Regtest, "s_1", "wallet/btc_2", &unlocked).unwrap();
        assert_eq!((m.account.as_str(), g), ("wallet/btc_2", 0));
        assert!(w.exists());
        assert!(find(&wallets, BNetwork::Regtest, "s_2", "wallet/btc_1", &unlocked).is_none(), "its seed is locked");
        assert!(find(&wallets, BNetwork::Regtest, "s_1", "wallet/btc_3", &unlocked).is_none());
    }

    #[test]
    fn a_box_sealed_again_opens_under_the_new_generation_only() {
        let root = tempfile::tempdir().unwrap();
        let wallets = root.path().join("wallets");
        let w = WalletDir::create(&wallets, BNetwork::Signet);
        let meta = WalletDir::new_meta("g_abc", "wallet/btc_1", "s_1", Family::Bitcoin, BNetwork::Signet);
        drop(w.open(&wallets, &meta, &key(1, 0), &[1; 32]).unwrap());
        w.seal(&meta, &key(1, 1)).unwrap();
        assert_eq!(w.sealed().unwrap(), ("s_1".to_string(), 1));
        assert!(w.meta(&key(1, 0)).is_err());
        assert_eq!(w.meta(&key(1, 1)).unwrap(), meta);
    }

    #[test]
    fn a_database_the_key_no_longer_opens_is_set_aside() {
        let root = tempfile::tempdir().unwrap();
        let wallets = root.path().join("wallets");
        let w = WalletDir::create(&wallets, BNetwork::Signet);
        let meta = WalletDir::new_meta("g_abc", "wallet/btc_1", "s_1", Family::Bitcoin, BNetwork::Signet);
        drop(w.open(&wallets, &meta, &key(1, 0), &[1; 32]).unwrap());
        assert!(matches!(w.open(&wallets, &meta, &key(1, 0), &[2; 32]), Err(DirError::Storage(StorageError::WrongKey))));
        let aside = w.set_aside().unwrap();
        assert!(aside.exists() && !w.path.join("wallet.db").exists());
        drop(w.open(&wallets, &meta, &key(1, 0), &[2; 32]).unwrap());
        assert!(w.exists(), "a fresh database under the new key");
    }

    #[test]
    fn group_names() {
        for ok in ["g_0123abcd", "shell-f0150787-84-0-0", "keycard-73c5da0a-86-1-0", "ledger-73c5da0a-84-1-0", "mock-segwit", "x_123", "COM", "console"] {
            assert!(valid_group(ok), "{ok}");
        }
        let long = "a".repeat(81);
        for bad in ["", ".", "..", ".hidden", "../g_x", "..\\g_x", "g_a/b", "g_a\\b", "/abs", "C:", "g_ x", "g_é", "abé", "g_a\0", "nul", "CON", "Aux", "com1", "LPT9", &long] {
            assert!(!valid_group(bad), "{bad:?}");
        }
        assert!(valid_group(&long[1..]), "80 characters");
    }
}
