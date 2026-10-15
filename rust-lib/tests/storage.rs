//! Spike 4: the wallet database is SQLCipher under BDK's own store (rusqlite 0.31, BDK's pin), on
//! every target. Create, write 10,000 transaction updates, close and reopen intact; a wrong key
//! fails cleanly and reads nothing; the files hold no descriptor, xpub, address or txid; a
//! 10,000-transaction wallet reopens within 2 s.
//!   cargo test --release --no-default-features --test storage -- --ignored --nocapture
//! SPIKE4_DIR keeps the files: wallets/ (encrypted), plain/ (an unencrypted control) and
//! needles.txt, for `strings -a <file> | grep -cFf needles.txt` on each.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::KeychainKind;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use bitcoin_wallet_core::network::{configure_regtest, BNetwork, Family};
use bitcoin_wallet_core::storage::StorageError;
use bitcoin_wallet_core::wallet::{load_or_create, Cell};
use bitcoin_wallet_core::walletdir::{DirError, WalletDir};

const TXS: u32 = 10_000;
const PER_BLOCK: u32 = 10;
const GROUP: &str = "g_spike4";
const REOPEN_LIMIT: Duration = Duration::from_secs(2);
// The test phrase's BIP84 account (abandon ×11 about, 73c5da0a), as the keystore hands it over.
const XPUB: &str = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";

fn descriptors() -> (String, String) {
    (format!("wpkh([73c5da0a/84'/1'/0']{XPUB}/0/*)"), format!("wpkh([73c5da0a/84'/1'/0']{XPUB}/1/*)"))
}

fn digest(label: &str, n: u32) -> [u8; 32] {
    sha256d::Hash::hash(format!("spike4 {label} {n}").as_bytes()).to_byte_array()
}

fn block_hash(height: u32) -> BlockHash {
    BlockHash::from_byte_array(digest("block", height))
}

/// What must not show in the files: text as `strings` would print it, and raw bytes.
#[derive(Default)]
struct Needles {
    text: Vec<String>,
    raw: Vec<Vec<u8>>,
}

impl Needles {
    fn wallet(&mut self, external: &str, internal: &str) {
        self.text.extend([XPUB.to_string(), external.to_string(), internal.to_string()]);
    }

    fn tx(&mut self, txid: Txid, address: String, spk: &ScriptBuf) {
        self.text.push(txid.to_string());
        self.text.push(address);
        let mut raw = txid.to_byte_array().to_vec();
        self.raw.push(raw.clone());
        raw.reverse();
        self.raw.push(raw);
        self.raw.push(spk.as_bytes().to_vec());
    }
}

/// Every needle found in `files`: in printable runs, as `strings -a` reads a file, then as raw bytes.
fn hits(files: &[PathBuf], needles: &Needles) -> Vec<String> {
    let mut by_prefix: HashMap<[u8; 8], Vec<&[u8]>> = HashMap::new();
    for r in &needles.raw {
        by_prefix.entry(r[..8].try_into().unwrap()).or_default().push(r);
    }
    let shortest = needles.text.iter().map(String::len).min().unwrap_or(usize::MAX);
    let mut out = vec![];
    for f in files {
        let bytes = std::fs::read(f).unwrap();
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        for run in bytes.split(|b| !(0x20..0x7f).contains(b) && *b != b'\t').filter(|r| r.len() >= shortest) {
            let run = String::from_utf8_lossy(run);
            for n in needles.text.iter().filter(|n| run.contains(n.as_str())) {
                out.push(format!("{name}: text {n}"));
            }
        }
        for (i, w) in bytes.windows(8).enumerate() {
            if let Some(cands) = by_prefix.get(w) {
                for c in cands.iter().filter(|c| bytes[i..].starts_with(c)) {
                    out.push(format!("{name}: bytes {} at {i}", hex::encode(c)));
                }
            }
        }
    }
    out
}

fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
    v.sort();
    v
}

/// Names and contents, to show a refused open changed nothing.
fn snapshot(dir: &Path) -> BTreeMap<String, [u8; 32]> {
    files_in(dir).into_iter().map(|p| (p.file_name().unwrap().to_string_lossy().to_string(), sha256d::Hash::hash(&std::fs::read(&p).unwrap()).to_byte_array())).collect()
}

/// Applies `n` transactions, one update each, ten to a block: even ones pay a new receive address,
/// odd ones a new change address. With `core`, every tenth is also noted in the core's own
/// `core_reported`.
fn write_updates(cell: &mut Cell, n: u32, core: bool, needles: &mut Needles) -> u64 {
    let mut total = 0;
    for i in 0..n {
        let keychain = if i % 2 == 0 { KeychainKind::External } else { KeychainKind::Internal };
        let info = cell.wallet.reveal_next_address(keychain);
        let spk = info.address.script_pubkey();
        let value = 10_000 + u64::from(i);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_byte_array(digest("prev", i)), vout: 0 }, ..Default::default() }],
            output: vec![TxOut { value: Amount::from_sat(value), script_pubkey: spk.clone() }],
        };
        let txid = tx.compute_txid();
        let height = 1 + i / PER_BLOCK;
        let block = BlockId { height, hash: block_hash(height) };
        let mut u = TxUpdate::default();
        u.txs.push(Arc::new(tx));
        u.anchors.insert((ConfirmationBlockTime { block_id: block, confirmation_time: 1_700_000_000 + u64::from(height) * 600 }, txid));
        let chain = (i % PER_BLOCK == 0).then(|| cell.wallet.latest_checkpoint().push(block).expect("a block on the tip"));
        cell.wallet.apply_update(bdk_wallet::Update { tx_update: u, chain, ..Default::default() }).unwrap();
        cell.persist().unwrap();
        if core && i % 10 == 0 {
            cell.reported(&[txid], "electrum-0", 1_700_000_000).unwrap();
        }
        needles.tx(txid, info.address.to_string(), &spk);
        total += value;
    }
    total
}

/// The same store without a key: what BDK writes in the clear, so a scan that finds nothing in the
/// encrypted files is a scan that would have found something.
fn plaintext_control(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let (ext, int) = descriptors();
    let mut conn = rusqlite::Connection::open(dir.join("wallet.db")).unwrap();
    let (wallet, _) = load_or_create(&mut conn, &ext, &int, BNetwork::Regtest).unwrap();
    let mut cell = Cell { wallet, conn, network: BNetwork::Regtest, family: Family::Bitcoin, shared: None };
    let mut needles = Needles::default();
    needles.wallet(&ext, &int);
    write_updates(&mut cell, 4, false, &mut needles);
    drop(cell);
    let found = hits(&files_in(dir), &needles);
    for kind in [format!("text {XPUB}"), "text wpkh(".to_string()] {
        assert!(found.iter().any(|h| h.contains(&kind)), "the control should show {kind}: {found:?}");
    }
    let txid = |h: &&String| h.split(": text ").nth(1).is_some_and(|n| n.len() == 64 && n.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(found.iter().filter(txid).count() >= 4, "txids in the clear: {found:?}");
    assert!(found.iter().any(|h| h.contains(": bytes 0014")), "scripts in the clear: {found:?}");
    println!("SPIKE4 control: the unencrypted store shows {} of the needles", found.len());
}

#[test]
#[ignore = "spike 4: 10,000 persisted updates; run with --release"]
fn spike4_encrypted_storage() {
    configure_regtest(Default::default());
    let kept = std::env::var_os("SPIKE4_DIR").map(PathBuf::from);
    let tmp = tempfile::tempdir().unwrap();
    let base = kept.clone().unwrap_or_else(|| tmp.path().to_path_buf());
    for sub in ["wallets", "plain"] {
        let _ = std::fs::remove_dir_all(base.join(sub));
    }
    plaintext_control(&base.join("plain"));

    let (ext, int) = descriptors();
    let root = base.join("wallets");
    let dir = WalletDir::new(&root, BNetwork::Regtest, GROUP);
    let meta = WalletDir::new_meta(GROUP, Family::Bitcoin, BNetwork::Regtest);
    let key: [u8; 32] = rand::random();
    let mut needles = Needles::default();
    needles.wallet(&ext, &int);

    // Create, then 10,000 updates, each persisted on its own.
    let mut conn = dir.open(&root, &meta, &key).unwrap();
    let (wallet, created) = load_or_create(&mut conn, &ext, &int, BNetwork::Regtest).unwrap();
    assert!(created);
    let mut cell = Cell { wallet, conn, network: BNetwork::Regtest, family: Family::Bitcoin, shared: None };
    let pragma = |p: &str| cell.conn.query_row(&format!("PRAGMA {p}"), [], |r| r.get::<_, String>(0)).unwrap();
    // CommonCrypto's provider has no version string: rusqlite panics on its NULL text.
    let provider = if cfg!(target_vendor = "apple") { pragma("cipher_provider") } else { pragma("cipher_provider_version") };
    let provider = format!("{provider}; SQLCipher {}", pragma("cipher_version"));
    let t = Instant::now();
    let total = write_updates(&mut cell, TXS, true, &mut needles);
    let written = t.elapsed();
    let open_files = files_in(&dir.path);
    let open_hits = hits(&open_files, &needles);
    drop(cell);

    // Closed: reopen with the key, timed from the file to a loaded wallet and its balance.
    let t = Instant::now();
    let mut conn = dir.open(&root, &meta, &key).unwrap();
    let (wallet, created) = load_or_create(&mut conn, &ext, &int, BNetwork::Regtest).unwrap();
    let count = wallet.transactions().count();
    let balance = wallet.balance();
    let reopened = t.elapsed();
    assert!(!created, "the stored wallet loads");
    assert_eq!(count, TXS as usize);
    assert_eq!(balance.confirmed.to_sat(), total);
    assert_eq!(wallet.latest_checkpoint().height(), TXS / PER_BLOCK);
    assert_eq!(wallet.derivation_index(KeychainKind::External), Some(TXS / 2 - 1));
    assert_eq!(wallet.derivation_index(KeychainKind::Internal), Some(TXS / 2 - 1));
    let reported: u32 = conn.query_row("SELECT count(*) FROM core_reported", [], |r| r.get(0)).unwrap();
    assert_eq!(reported, TXS / 10);
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
    assert_eq!(integrity, "ok");
    let cipher_errors = conn.prepare("PRAGMA cipher_integrity_check").unwrap().query_map([], |r| r.get::<_, String>(0)).unwrap().count();
    assert_eq!(cipher_errors, 0, "every page's HMAC checks");
    drop(wallet);
    drop(conn);

    // A wrong key: refused at the first read, nothing returned, nothing on disk changed.
    let before = snapshot(&dir.path);
    let mut wrong = key;
    wrong[0] ^= 0xff;
    let refused = dir.open(&root, &meta, &wrong);
    assert!(matches!(refused, Err(DirError::Storage(StorageError::WrongKey))), "{:?}", refused.err());
    let unkeyed = rusqlite::Connection::open(dir.path.join("wallet.db")).unwrap();
    assert!(unkeyed.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).is_err(), "no key, no tables");
    drop(unkeyed);
    assert_eq!(snapshot(&dir.path), before, "a refused open leaves the files as they were");
    let mut conn = dir.open(&root, &meta, &key).expect("the right key still opens it");
    assert_eq!(load_or_create(&mut conn, &ext, &int, BNetwork::Regtest).unwrap().0.transactions().count(), TXS as usize);
    drop(conn);

    // The files, open (with the WAL) and closed, hold none of the wallet's strings.
    let closed_files = files_in(&dir.path);
    let closed_hits = hits(&closed_files, &needles);
    let raw = std::fs::read(dir.path.join("wallet.db")).unwrap();
    assert!(!raw.windows(15).any(|w| w == b"SQLite format 3"));
    if let Some(k) = &kept {
        let mut text = needles.text.join("\n");
        text.push('\n');
        std::fs::write(k.join("needles.txt"), text).unwrap();
    }
    let size: u64 = closed_files.iter().map(|f| std::fs::metadata(f).unwrap().len()).sum();
    let names = |v: &[PathBuf]| v.iter().map(|f| f.file_name().unwrap().to_string_lossy().to_string()).collect::<Vec<_>>().join(",");
    println!(
        "SPIKE4 {} provider=\"{provider}\" updates={TXS} write_ms={} per_update_us={} reopen_ms={} db_bytes={size} wrong_key=refused open_files=[{}] open_hits={} closed_files=[{}] closed_hits={} needles={}+{}",
        std::env::consts::OS,
        written.as_millis(),
        written.as_micros() / u128::from(TXS),
        reopened.as_millis(),
        names(&open_files),
        open_hits.len(),
        names(&closed_files),
        closed_hits.len(),
        needles.text.len(),
        needles.raw.len(),
    );
    assert!(open_hits.is_empty(), "while open: {open_hits:?}");
    assert!(closed_hits.is_empty(), "closed: {closed_hits:?}");
    assert!(reopened < REOPEN_LIMIT, "reopened in {reopened:?}");
}
