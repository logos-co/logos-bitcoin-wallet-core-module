//! Kyoto, the BIP157/158 light client, as a chain authority: bdk_kyoto 0.18.0 on bip157 0.7.0
//! with our patches. Each start dials a random 8 of the node module's peers, whitelist only; a
//! peer that fails 3 starts is skipped for a day. README, "Kyoto", has the rules and why.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bdk_kyoto::bip157::chain::{ChainState, IndexedHeader};
use bdk_kyoto::bip157::{self, AddrV2, Builder, HashCheckpoint, Header, Info, ServiceFlags, TrustedPeer, Warning};
use bdk_kyoto::builder::BuilderExt;
use bdk_kyoto::{Requester, SyncConfig};
use bdk_wallet::chain::keychain_txout::KeychainTxOutIndex;
use bdk_wallet::{KeychainKind, Update, Wallet};
use bitcoin::BlockHash;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::network::BNetwork;
use crate::routes::{KyotoRoute, Proxy, Route};

/// Peers dialled per start, taken at random from the list.
pub const SUBSET: usize = 8;
/// Starts in a row a peer may fail before it is skipped.
pub const FAILS_TO_SKIP: u32 = 3;
pub const SKIP_SECS: u64 = 24 * 3600;
/// bdk_wallet's lookahead: bdk_kyoto watches the revealed addresses plus this many, fixed at build.
pub const LOOKAHEAD: u32 = 25;
/// A first sync hands over what it found every this many filters, so a lost peer set resumes there.
pub const CHECKPOINT_FILTERS: u32 = 2_016;
/// Kyoto restarts this far below the last height it scanned, for a reorg since.
pub const RESTART_DEPTH: u32 = 8;

/// A peer as the light client dials it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peer {
    Ip(SocketAddr),
    /// A v3 onion service: its ed25519 key.
    Onion([u8; 32], u16),
    /// A name on the user's own network, resolved there.
    Lan(String, u16),
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The key in a v3 onion name, after checking its version and checksum.
pub fn onion_key(host: &str) -> Result<[u8; 32], String> {
    let name = host.strip_suffix(".onion").ok_or("not an onion name")?;
    if name.len() != 56 {
        return Err(format!("{host}: only v3 onion services (56 characters) are supported"));
    }
    let mut bits: u64 = 0;
    let (mut nbits, mut out) = (0u32, Vec::with_capacity(35));
    for c in name.bytes() {
        let v = B32.iter().position(|b| *b == c.to_ascii_lowercase()).ok_or_else(|| format!("{host}: not base32"))? as u64;
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    let (key, rest) = out.split_at(32);
    if rest[2] != 3 {
        return Err(format!("{host}: not a version 3 onion name"));
    }
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(key);
    h.update([3u8]);
    if h.finalize()[..2] != rest[..2] {
        return Err(format!("{host}: the onion name's checksum is wrong"));
    }
    Ok(key.try_into().expect("32 bytes"))
}

fn is_lan_name(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "localhost" || [".local", ".lan", ".home.arpa", ".internal"].iter().any(|s| h.len() > s.len() && h.ends_with(s))
}

/// `host:port` from the node module: an IP address, a v3 onion name, or a name on the user's network.
pub fn parse_peer(text: &str, default_port: u16) -> Result<Peer, String> {
    let t = text.trim();
    if let Ok(sa) = t.parse::<SocketAddr>() {
        return Ok(Peer::Ip(sa));
    }
    let (host, port) = match t.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') || h.starts_with('[') => (h.trim_matches(['[', ']']), p.parse::<u16>().map_err(|_| format!("{t}: bad port"))?),
        _ => (t.trim_matches(['[', ']']), default_port),
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Peer::Ip(SocketAddr::new(ip, port)));
    }
    if host.ends_with(".onion") {
        return Ok(Peer::Onion(onion_key(host)?, port));
    }
    if is_lan_name(host) {
        return Ok(Peer::Lan(host.to_string(), port));
    }
    Err(format!("{t}: Kyoto would resolve {host} outside Tor; use an IP address or an onion name"))
}

impl Peer {
    fn trusted(&self) -> TrustedPeer {
        match self {
            Peer::Ip(sa) => TrustedPeer::from_socket_addr(*sa),
            Peer::Onion(key, port) => TrustedPeer::new(AddrV2::TorV3(*key), Some(*port), ServiceFlags::NONE),
            Peer::Lan(host, port) => TrustedPeer::from_hostname(host.clone(), *port),
        }
    }

    /// Whether a connection the client reports is to this peer; ports aren't reported.
    fn is(&self, addr: &AddrV2) -> bool {
        match (self, addr) {
            (Peer::Ip(sa), AddrV2::Ipv4(ip)) => sa.ip() == IpAddr::V4(*ip),
            (Peer::Ip(sa), AddrV2::Ipv6(ip)) => sa.ip() == IpAddr::V6(*ip),
            (Peer::Onion(key, _), AddrV2::TorV3(k)) => key == k,
            _ => false,
        }
    }

    fn reachable(&self, route: Route) -> Result<(), String> {
        match (self, route) {
            (Peer::Onion(..), Route::Direct) => Err("an onion peer is reached through Tor only".into()),
            (Peer::Lan(..), Route::Tor | Route::Onion) => Err("a name on your network can't be reached through Tor".into()),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHealth {
    pub fails: u32,
    pub skip_until: u64,
}

/// Failures per peer across starts, kept with the wallet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBook {
    pub peers: BTreeMap<String, PeerHealth>,
}

impl PeerBook {
    /// A random `SUBSET` of `list` without the peers skipped today; all of them if every one is.
    pub fn pick(&self, list: &[String], now: u64, rng: &mut impl rand::Rng) -> Vec<String> {
        let mut usable: Vec<String> = list.iter().filter(|p| self.peers.get(*p).is_none_or(|h| h.skip_until <= now)).cloned().collect();
        if usable.is_empty() {
            usable = list.to_vec();
        }
        usable.shuffle(rng);
        usable.truncate(SUBSET);
        usable
    }

    /// A start in which `peer` never connected; the third in a row skips it for a day.
    pub fn failed(&mut self, peer: &str, now: u64) {
        let h = self.peers.entry(peer.to_string()).or_default();
        h.fails += 1;
        if h.fails >= FAILS_TO_SKIP {
            h.fails = 0;
            h.skip_until = now + SKIP_SECS;
        }
    }

    pub fn connected(&mut self, peer: &str) {
        self.peers.remove(peer);
    }

    /// Skips `peer` for a day at once: it took part in a filter-header conflict.
    pub fn skip(&mut self, peer: &str, now: u64) {
        let h = self.peers.entry(peer.to_string()).or_default();
        (h.fails, h.skip_until) = (0, now + SKIP_SECS);
    }

    pub fn skipped(&self, now: u64) -> usize {
        self.peers.values().filter(|h| h.skip_until > now).count()
    }
}

/// Kyoto's quorum: 3 peers on mainnet and 2 on signet, however few it may dial; on testnet4 and
/// regtest, 2 (regtest: as configured) or as many as it may dial, down to 1.
pub fn required(net: BNetwork, regtest: Option<u8>, peers: usize) -> u8 {
    let dialable = peers.clamp(1, u8::MAX as usize) as u8;
    match net {
        BNetwork::Mainnet => 3,
        BNetwork::Signet => 2,
        BNetwork::Testnet4 => 2.min(dialable),
        BNetwork::Regtest => regtest.unwrap_or(2).min(dialable).max(1),
    }
}

/// How long a peer has, per step: Tor circuits take seconds where a LAN takes milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub handshake: Duration,
    /// `None` keeps bip157's default, 5 s.
    pub response: Option<Duration>,
    pub filter_batch: Duration,
}

pub fn timeouts(route: Route) -> Timeouts {
    match route {
        Route::Direct => Timeouts { handshake: Duration::from_secs(5), response: None, filter_batch: Duration::from_secs(30) },
        // The response timeout also covers the version handshake after the SOCKS connect.
        Route::Tor | Route::Onion => Timeouts { handshake: Duration::from_secs(30), response: Some(Duration::from_secs(15)), filter_batch: Duration::from_secs(240) },
    }
}

/// Kyoto takes its SOCKS proxy by IP address only.
pub fn proxy_addr(p: &Proxy) -> Result<SocketAddr, String> {
    let ip = match p.host.as_str() {
        "localhost" => IpAddr::from([127, 0, 0, 1]),
        h => h.parse::<IpAddr>().map_err(|_| format!("Kyoto needs the proxy by IP address, not {h}"))?,
    };
    Ok(SocketAddr::new(ip, p.port))
}

/// Where a start begins: strictly after `from`, Kyoto's chain holding the authority's headers up
/// to `known_to` (a snapshot, none downloaded again); headers only up to the tip first, then a
/// rescan from `rescan_from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Start {
    pub from: (u32, BlockHash),
    pub known_to: u32,
    pub headers_only: bool,
    pub rescan_from: Option<u32>,
}

/// What a running client reports to the sync thread.
pub enum Feed {
    /// The wallet's transactions since the last update and Kyoto's chain, with the height of the
    /// last filter checked, and whether that is the tip or a checkpoint on the way there.
    Update { update: Box<Update>, scanned: Option<u32>, synced: bool },
    /// The share of filter headers and filters done, and Kyoto's header height.
    Progress { fraction: f32, height: u32 },
    Warning(String),
    /// Peers sent conflicting filter headers; bip157 disconnected one of them and can't say which lied.
    Conflict,
    /// The node stopped: it ran out of peers, or was told to.
    Stopped(Option<String>),
}

/// The phase a client is in, for status. Kyoto reports progress only as whole batches finish, so
/// a catch-up within one batch reads `syncing` until its filters are in; `headers` in status
/// is Kyoto's best header, to compare with a peer's tip.
pub fn phase(updated: bool, fraction: f32) -> &'static str {
    // Filter headers count a quarter of the work; past it, filters are downloading.
    match (updated, fraction) {
        (true, _) => "synced",
        (false, f) if f <= 0.0 => "syncing",
        (false, f) if f < 0.25 => "filter_headers",
        _ => "filters",
    }
}

/// One running light client, on a runtime of its own: bip157 spawns a task per peer, and
/// dropping the node leaves them spinning on a closed channel, so a stop shuts the runtime down.
pub struct Client {
    pub requester: Requester,
    feed: Receiver<Feed>,
    rt: Option<tokio::runtime::Runtime>,
    /// The subset this start dials, those named on the user's network, those seen connected, and
    /// those connected at the last look.
    pub peers: Vec<String>,
    lan: HashSet<String>,
    seen: Arc<Mutex<HashSet<String>>>,
    now: Arc<Mutex<Vec<String>>>,
    connected: Arc<Mutex<usize>>,
    best_header: Arc<Mutex<u32>>,
    /// The wallet's last revealed indices when the client cloned its address index.
    pub revealed: [Option<u32>; 2],
    /// The highest index of each keychain this client watches now.
    pub window: [u32; 2],
    widen: Arc<Mutex<BTreeMap<KeychainKind, u32>>>,
    pub start: Start,
    pub started: Instant,
    /// An update came, at a checkpoint or the tip; one came with filters synced to the tip.
    pub updated: bool,
    pub synced: bool,
}

const KEYCHAINS: [KeychainKind; 2] = [KeychainKind::External, KeychainKind::Internal];

impl Client {
    /// Builds and starts a client for `wallet`, dialling `peers` on `route`; `wake` is set when
    /// an update or a stop waits for the sync thread. It watches each keychain's revealed index
    /// plus `lookahead`. `snapshot` holds the headers from `start.from` to `start.known_to`.
    #[allow(clippy::too_many_arguments)]
    pub fn start(wallet: &Wallet, route: &KyotoRoute, proxy: Option<&Proxy>, required: u8, peers: Vec<String>, start: Start, snapshot: Vec<Header>, lookahead: u32, wake: Arc<std::sync::atomic::AtomicBool>) -> Result<Client, String> {
        let net = wallet.network();
        let default_port = match net {
            bitcoin::Network::Bitcoin => 8333,
            bitcoin::Network::Testnet4 => 48333,
            bitcoin::Network::Signet => 38333,
            bitcoin::Network::Regtest => 18444,
            _ => 18333,
        };
        let mut dial = vec![];
        for p in &peers {
            match parse_peer(p, default_port).and_then(|x| x.reachable(route.route).map(|_| x)) {
                Ok(x) => dial.push((p.clone(), x)),
                Err(e) => tracing::warn!(target: "bitcoin", "kyoto: skipped {p}: {e}"),
            }
        }
        if dial.is_empty() {
            return Err("Kyoto has no peer it can dial on its route".into());
        }
        let t = timeouts(route.route);
        let mut b = Builder::new(net)
            .whitelist_only()
            .add_peers(dial.iter().map(|(_, p)| p.trusted()))
            .required_peers(required)
            .handshake_timeout(t.handshake)
            .filter_batch_timeout(t.filter_batch);
        if let Some(r) = t.response {
            b = b.response_timeout(r);
        }
        if matches!(route.route, Route::Tor | Route::Onion) {
            b = b.socks5_proxy(proxy_addr(proxy.ok_or("routed through Tor, and no proxy is set")?)?);
        }
        if start.headers_only {
            b = b.headers_only_sync();
        }
        let cp = HashCheckpoint::new(start.from.0, start.from.1);
        let lookahead = lookahead.max(LOOKAHEAD);
        let config = SyncConfig::wallet_recovery_sync(cp, lookahead).build();
        let client = if snapshot.len() > 1 {
            let headers = snapshot.into_iter().enumerate().map(|(i, header)| IndexedHeader { height: start.from.0 + i as u32, header }).collect();
            b.build_with_wallet_from(wallet, config, ChainState::Snapshot(headers))
        } else {
            b.build_with_wallet(wallet, config)
        }
        .map_err(|e| e.to_string())?;
        let revealed = KEYCHAINS.map(|k| wallet.derivation_index(k));
        let window = revealed.map(|r| r.unwrap_or(0) + lookahead - 1);
        let (client, logging, mut updates) = client.subscribe();
        let (client, node) = client.managed_start();
        let requester = client.requester();
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("bitcoin-kyoto").enable_all().build().map_err(|e| e.to_string())?;
        let (tx, feed) = channel::<Feed>();
        let (stopped, woken) = (tx.clone(), wake.clone());
        rt.spawn(async move {
            let why = node.run().await.err().map(|e| e.to_string());
            let _ = stopped.send(Feed::Stopped(why));
            woken.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        let updated = tx.clone();
        updates.checkpoint_every(CHECKPOINT_FILTERS);
        let widen = updates.widen_handle();
        rt.spawn(async move {
            while let Ok(u) = updates.update().await {
                if updated.send(Feed::Update { update: Box::new(u), scanned: updates.scanned(), synced: updates.synced() }).is_err() {
                    break;
                }
                wake.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
        rt.spawn(drain_logs(logging, tx.clone()));
        let (seen, connected, best_header) = (Arc::new(Mutex::new(HashSet::new())), Arc::new(Mutex::new(0usize)), Arc::new(Mutex::new(start.from.0)));
        let now = Arc::new(Mutex::new(vec![]));
        rt.spawn(watch_peers(requester.clone(), dial.clone(), Watched { seen: seen.clone(), now: now.clone(), connected: connected.clone(), best_header: best_header.clone() }));
        tracing::info!(target: "bitcoin", "kyoto: started after {} holding headers to {} with {} peers, quorum {required}{}", start.from.0, start.known_to, dial.len(),
            if start.headers_only { ", headers first" } else { "" });
        let lan = dial.iter().filter(|(_, p)| matches!(p, Peer::Lan(..))).map(|(t, _)| t.clone()).collect();
        Ok(Client { requester, feed, rt: Some(rt), peers: dial.into_iter().map(|(p, _)| p).collect(), lan, seen, now, connected, best_header, revealed, window, widen, start, started: Instant::now(), updated: false, synced: false })
    }

    pub fn poll(&mut self) -> Vec<Feed> {
        let out: Vec<Feed> = self.feed.try_iter().collect();
        for f in &out {
            if let Feed::Update { synced, .. } = f {
                self.updated = true;
                self.synced |= *synced;
            }
        }
        out
    }

    pub fn connected(&self) -> usize {
        *self.connected.lock().unwrap()
    }

    /// Kyoto's best header height, as last asked.
    pub fn best_header(&self) -> u32 {
        *self.best_header.lock().unwrap()
    }

    /// The peers of this start never seen connected; names on the user's network resolve to
    /// addresses that can't be told apart, so they don't count.
    pub fn unseen(&self) -> Vec<String> {
        let seen = self.seen.lock().unwrap();
        self.peers.iter().filter(|p| !seen.contains(*p) && !self.lan.contains(*p)).cloned().collect()
    }

    pub fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().iter().cloned().collect()
    }

    /// The peers of this start connected at the last look, once a second.
    pub fn connected_now(&self) -> Vec<String> {
        self.now.lock().unwrap().clone()
    }

    /// Whether this client's chain holds the block at `height`, so it can scan again from there.
    pub fn covers(&self, height: u32) -> bool {
        self.start.from.0 <= height
    }

    /// Watches `lookahead` past each keychain's revealed index in the wallet from the next filter
    /// on, and with `rescan_from`, checks the filters again after that height. Nothing is
    /// downloaded but them.
    pub fn widen(&mut self, wallet: &Wallet, lookahead: u32, rescan_from: Option<u32>) -> Result<(), String> {
        let lookahead = lookahead.max(LOOKAHEAD);
        let wider = KEYCHAINS.map(|k| wallet.derivation_index(k).unwrap_or(0) + lookahead - 1);
        self.window = [self.window[0].max(wider[0]), self.window[1].max(wider[1])];
        *self.widen.lock().map_err(|e| e.to_string())? = KEYCHAINS.into_iter().zip(self.window).collect();
        if let Some(h) = rescan_from {
            self.requester.rescan_from(h).map_err(|e| e.to_string())?;
            self.synced = false;
        }
        Ok(())
    }

    /// The wallet revealed an address past what the client watches: it must watch further.
    pub fn needs_rebuild(&self, wallet: &Wallet) -> bool {
        KEYCHAINS.iter().zip(self.window).any(|(k, w)| wallet.derivation_index(*k).is_some_and(|i| i > w))
    }


    /// Stops the node and every task of its runtime, peers included; nothing waits.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        let _ = self.requester.shutdown();
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.shutdown();
    }
}


/// The highest used index of each keychain a gap-limit scan reaches: from 0, never past `gap`
/// unused addresses in a row. A payment further out doesn't widen a scan.
pub fn reachable_used(index: &KeychainTxOutIndex<KeychainKind>, gap: u32) -> BTreeMap<KeychainKind, u32> {
    let mut out = BTreeMap::new();
    for k in KEYCHAINS {
        let (mut last, mut i) = (None::<u32>, 0u32);
        while i <= last.map_or(gap.saturating_sub(1), |l| l.saturating_add(gap)) {
            if index.is_used(k, i) {
                last = Some(i);
            }
            i += 1;
        }
        out.extend(last.map(|l| (k, l)));
    }
    out
}

/// The lookahead for a scan again when a used index comes within `gap` of `window`, the highest
/// index watched per keychain from the first block (README, "Kyoto"); `None` when it held.
pub fn rescan_lookahead(window: [u32; 2], used: &BTreeMap<KeychainKind, u32>, gap: u32) -> Option<u32> {
    let near = KEYCHAINS.iter().zip(window).any(|(k, w)| used.get(k).is_some_and(|u| u + gap > w));
    near.then(|| used.values().copied().max().unwrap_or(0) + LOOKAHEAD + 1)
}

/// bip157's warning when two peers' filter headers disagree (node.rs, `CFHeaderChanges::Conflict`).
const FILTER_HEADER_CONFLICT: &str = "conflict while peers are sending filter headers";

async fn drain_logs(mut logs: bdk_kyoto::LoggingSubscribers, tx: Sender<Feed>) {
    // A first sync reports progress thousands of times: the latest goes out every 250 ms.
    let (mut latest, mut sent): (Option<(f32, u32)>, Option<(f32, u32)>) = (None, None);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if latest != sent {
                    if let Some((fraction, height)) = latest {
                        if tx.send(Feed::Progress { fraction, height }).is_err() {
                            return;
                        }
                    }
                    sent = latest;
                }
            }
            info = logs.info_subscriber.recv() => match info {
                Some(Info::Progress(p)) => latest = Some((p.fraction_complete(), p.chain_height())),
                Some(i) => tracing::debug!(target: "bitcoin", "kyoto: {i}"),
                None => return,
            },
            warn = logs.warning_subscriber.recv() => match warn {
                Some(Warning::UnexpectedSyncError { warning }) if warning.contains(FILTER_HEADER_CONFLICT) => {
                    tracing::info!(target: "bitcoin", "kyoto: {warning}");
                    if tx.send(Feed::Conflict).is_err() {
                        return;
                    }
                }
                Some(w @ (Warning::UnexpectedSyncError { .. } | Warning::PotentialStaleTip | Warning::UnsolicitedMessage | Warning::TransactionRejected { .. })) => {
                    tracing::info!(target: "bitcoin", "kyoto: {w}");
                    if tx.send(Feed::Warning(w.to_string())).is_err() {
                        return;
                    }
                }
                Some(w) => tracing::debug!(target: "bitcoin", "kyoto: {w}"),
                None => return,
            },
        }
    }
}

/// What `watch_peers` keeps up to date for the sync thread.
struct Watched {
    seen: Arc<Mutex<HashSet<String>>>,
    now: Arc<Mutex<Vec<String>>>,
    connected: Arc<Mutex<usize>>,
    best_header: Arc<Mutex<u32>>,
}

async fn watch_peers(requester: Requester, dial: Vec<(String, Peer)>, w: Watched) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Ok(Ok(tip)) = tokio::time::timeout(Duration::from_secs(2), requester.chain_tip()).await {
            *w.best_header.lock().unwrap() = tip.height;
        }
        let Ok(Ok(info)) = tokio::time::timeout(Duration::from_secs(2), requester.peer_info()).await else {
            if !requester.is_running() {
                return;
            }
            continue;
        };
        *w.connected.lock().unwrap() = info.len();
        let now: Vec<String> = dial.iter().filter(|(_, p)| info.iter().any(|(addr, _)| p.is(addr))).map(|(t, _)| t.clone()).collect();
        w.seen.lock().unwrap().extend(now.iter().cloned());
        *w.now.lock().unwrap() = now;
    }
}

/// Headers read from Kyoto per round trip to the runtime; the caller can stop between chunks.
const HEADERS_PER_CHUNK: usize = 500;

/// Kyoto's headers from `from` through `to`, as its chain holds them now, for the authority to
/// check while Kyoto is still syncing headers.
pub fn headers_at(rt: &tokio::runtime::Handle, requester: &Requester, from: u32, to: u32, stop: &std::sync::atomic::AtomicBool) -> Result<Vec<Header>, String> {
    let mut out = Vec::with_capacity(to.saturating_sub(from) as usize + 1);
    let mut h = from;
    while h <= to {
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("stopping".into());
        }
        let end = to.min(h + HEADERS_PER_CHUNK as u32 - 1);
        let r = requester.clone();
        let got = rt.block_on(async move {
            tokio::time::timeout(Duration::from_secs(30), async move {
                let mut got = Vec::with_capacity((end - h + 1) as usize);
                for at in h..=end {
                    got.push(r.get_header(at).await.map_err(|e| e.to_string())?.ok_or_else(|| format!("Kyoto has no header at {at}"))?.header);
                }
                Ok::<_, String>(got)
            })
            .await
            .map_err(|_| "Kyoto took too long to hand over its headers".to_string())?
        })?;
        out.extend(got);
        h = end + 1;
    }
    Ok(out)
}

/// Kyoto's headers at `wanted`, read from its chain; each must hash as named. Stops early, with
/// an error, when `stop` is set.
pub fn headers(rt: &tokio::runtime::Handle, requester: &Requester, wanted: &[(u32, BlockHash)], stop: &std::sync::atomic::AtomicBool) -> Result<Vec<(u32, Header)>, String> {
    let mut out = Vec::with_capacity(wanted.len());
    for chunk in wanted.chunks(HEADERS_PER_CHUNK) {
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("stopping".into());
        }
        let r = requester.clone();
        let chunk = chunk.to_vec();
        let got = rt.block_on(async move {
            tokio::time::timeout(Duration::from_secs(30), async move {
                let mut got = Vec::with_capacity(chunk.len());
                for (h, hash) in chunk {
                    let header = r.get_header(h).await.map_err(|e| e.to_string())?.ok_or_else(|| format!("Kyoto has no header at {h} any more"))?;
                    if header.block_hash() != hash {
                        return Err(format!("Kyoto's header at {h} changed since its update"));
                    }
                    got.push((h, header.header));
                }
                Ok(got)
            })
            .await
            .map_err(|_| "Kyoto took too long to hand over its headers".to_string())?
        })?;
        out.extend(got);
    }
    Ok(out)
}

/// A broadcast through Kyoto: done when a peer asks for the transaction, within `budget`.
pub fn broadcast(rt: &tokio::runtime::Handle, requester: &Requester, tx: &bitcoin::Transaction, budget: Duration) -> Result<(), String> {
    let r = requester.clone();
    let tx = tx.clone();
    rt.block_on(async move {
        match tokio::time::timeout(budget, r.submit_package(tx)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("Kyoto stopped: {e}")),
            Err(_) => Err("no Kyoto peer asked for the transaction in time".into()),
        }
    })
}

/// The lowest fee rate the connected peers relay, in sat/vB.
pub fn min_fee_rate(rt: &tokio::runtime::Handle, requester: &Requester) -> Option<f64> {
    let r = requester.clone();
    rt.block_on(async move { tokio::time::timeout(Duration::from_secs(1), r.broadcast_min_feerate()).await.ok()?.ok() }).map(|f| f.to_sat_per_kwu() as f64 * 4.0 / 1000.0)
}

/// The checkpoint below `height` that Kyoto knows by itself: the taproot or segwit block on mainnet,
/// genesis elsewhere. A birthday below the wallet's own checkpoint starts here.
pub fn builtin_checkpoint(net: BNetwork, height: u32) -> (u32, BlockHash) {
    if net == BNetwork::Mainnet {
        for cp in [HashCheckpoint::taproot_activation(), HashCheckpoint::segwit_activation()] {
            if cp.height <= height {
                return (cp.height, cp.hash);
            }
        }
    }
    (0, bitcoin::constants::genesis_block(net.bitcoin()).block_hash())
}

pub use bip157::NodeError;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    // A made-up v3 onion name with a valid checksum, derived from a fixed key.
    fn onion_of(key: [u8; 32]) -> String {
        let mut h = Sha3_256::new();
        h.update(b".onion checksum");
        h.update(key);
        h.update([3u8]);
        let mut bytes = key.to_vec();
        bytes.extend_from_slice(&h.finalize()[..2]);
        bytes.push(3);
        let (mut bits, mut n, mut out) = (0u64, 0u32, String::new());
        for b in bytes {
            bits = (bits << 8) | b as u64;
            n += 8;
            while n >= 5 {
                n -= 5;
                out.push(B32[((bits >> n) & 31) as usize] as char);
            }
        }
        format!("{out}.onion")
    }

    #[test]
    fn peers_parse_as_kyoto_dials_them() {
        let key = [7u8; 32];
        let onion = onion_of(key);
        assert_eq!(onion.len(), 62);
        assert_eq!(parse_peer(&format!("{onion}:8333"), 1).unwrap(), Peer::Onion(key, 8333));
        assert_eq!(parse_peer(&onion, 38333).unwrap(), Peer::Onion(key, 38333));
        assert_eq!(parse_peer("127.0.0.1:18544", 1).unwrap(), Peer::Ip("127.0.0.1:18544".parse().unwrap()));
        assert_eq!(parse_peer("[fd00::2]:8333", 1).unwrap(), Peer::Ip("[fd00::2]:8333".parse().unwrap()));
        assert_eq!(parse_peer("192.168.1.20", 8333).unwrap(), Peer::Ip("192.168.1.20:8333".parse().unwrap()));
        assert_eq!(parse_peer("umbrel.local:8333", 1).unwrap(), Peer::Lan("umbrel.local".into(), 8333));
        assert!(parse_peer("seed.bitcoin.example:8333", 1).unwrap_err().contains("outside Tor"));
        let mut bad = onion.clone();
        bad.replace_range(0..1, if bad.starts_with('a') { "b" } else { "a" });
        assert!(parse_peer(&bad, 1).unwrap_err().contains("checksum"));
        assert!(parse_peer("expyuzz4wqqyqhjn.onion:8333", 1).unwrap_err().contains("v3"));
        // One connection type per client.
        assert!(Peer::Onion(key, 1).reachable(Route::Direct).is_err());
        assert!(Peer::Lan("nas.local".into(), 1).reachable(Route::Tor).is_err());
        assert!(Peer::Ip("1.2.3.4:8333".parse().unwrap()).reachable(Route::Tor).is_ok());
        assert!(Peer::Onion(key, 1).is(&AddrV2::TorV3(key)) && !Peer::Onion(key, 1).is(&AddrV2::TorV3([8; 32])));
    }

    #[test]
    fn each_start_takes_a_random_eight_and_skips_failing_peers() {
        let list: Vec<String> = (0..20).map(|i| format!("10.0.0.{i}:8333")).collect();
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let mut book = PeerBook::default();
        let a = book.pick(&list, 0, &mut rng);
        let b = book.pick(&list, 0, &mut rng);
        assert_eq!((a.len(), b.len()), (SUBSET, SUBSET));
        assert_ne!(a, b, "starts don't return to the same peers");
        // Three failed starts skip a peer for 24 hours; one success clears its count.
        let p = list[0].clone();
        book.failed(&p, 100);
        book.failed(&p, 200);
        assert_eq!(book.skipped(200), 0);
        book.failed(&p, 300);
        assert_eq!(book.skipped(300), 1);
        for _ in 0..50 {
            assert!(!book.pick(&list, 300 + SKIP_SECS - 1, &mut rng).contains(&p));
        }
        assert!((0..50).any(|_| book.pick(&list, 300 + SKIP_SECS, &mut rng).contains(&p)), "back after a day");
        book.failed(&list[1], 0);
        book.connected(&list[1]);
        assert!(!book.peers.contains_key(&list[1]));
        // When every peer is skipped, they are all tried rather than none.
        let few = vec!["10.0.0.1:1".to_string()];
        let mut all_bad = PeerBook::default();
        for _ in 0..3 {
            all_bad.failed(&few[0], 0);
        }
        assert_eq!(all_bad.pick(&few, 1, &mut rng), few);
        // The book round-trips through the wallet's meta table.
        let back: PeerBook = serde_json::from_str(&serde_json::to_string(&book).unwrap()).unwrap();
        assert_eq!(back, book);
    }

    #[test]
    fn the_quorum_follows_the_network_and_the_peers() {
        assert_eq!(required(BNetwork::Mainnet, None, 8), 3);
        assert_eq!(required(BNetwork::Signet, None, 8), 2);
        assert_eq!(required(BNetwork::Mainnet, None, 1), 3, "mainnet never runs below its quorum");
        assert_eq!(required(BNetwork::Signet, None, 1), 2);
        assert_eq!(required(BNetwork::Testnet4, None, 8), 2);
        assert_eq!(required(BNetwork::Testnet4, None, 1), 1, "testnet4's one listed peer decides alone");
        assert_eq!(required(BNetwork::Testnet4, None, 0), 1);
        assert_eq!(required(BNetwork::Regtest, Some(3), 3), 3);
        assert_eq!(required(BNetwork::Regtest, None, 0), 1);
        assert_eq!(timeouts(Route::Tor).handshake, Duration::from_secs(30));
        assert_eq!(timeouts(Route::Onion).response, Some(Duration::from_secs(15)), "Tor: 15 s per response");
        assert_eq!(timeouts(Route::Direct).response, None, "directly: bip157's default");
        assert!(proxy_addr(&Proxy::parse("socks5h://tor.example:9050").unwrap()).is_err());
        assert_eq!(proxy_addr(&Proxy::parse("socks5h://localhost:9050").unwrap()).unwrap().port(), 9050);
    }

    #[test]
    fn only_addresses_a_gap_limit_scan_reaches_widen_a_scan() {
        let x = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
        let w = bdk_wallet::Wallet::create(format!("wpkh([73c5da0a/84'/1'/0']{x}/0/*)"), format!("wpkh([73c5da0a/84'/1'/0']{x}/1/*)"))
            .network(bitcoin::Network::Regtest)
            .create_wallet_no_persist()
            .unwrap();
        let mut index = w.spk_index().clone();
        for k in KEYCHAINS {
            let _ = index.lookahead_to_target(k, 400);
        }
        assert!(reachable_used(&index, 20).is_empty());
        index.mark_used(KeychainKind::External, 25);
        assert!(reachable_used(&index, 20).is_empty(), "the first 20 hold nothing used: 25 is out of reach");
        for i in [0, 15, 35, 50, 313] {
            index.mark_used(KeychainKind::External, i);
        }
        index.mark_used(KeychainKind::Internal, 3);
        let used = reachable_used(&index, 20);
        assert_eq!((used[&KeychainKind::External], used[&KeychainKind::Internal]), (50, 3), "313 lies past 20 unused after 50");
        assert_eq!(rescan_lookahead([315, 315], &used, 20), None, "a far payment doesn't widen the scan");
    }

    #[test]
    fn a_used_index_near_the_window_starts_the_scan_over() {
        let used = |e: u32, i: Option<u32>| BTreeMap::from_iter([(KeychainKind::External, e)].into_iter().chain(i.map(|i| (KeychainKind::Internal, i))));
        // A fresh restore watches 0..=24 of each keychain.
        assert_eq!(rescan_lookahead([24, 24], &used(4, Some(1)), 20), None, "index 4 plus the gap is still watched");
        assert_eq!(rescan_lookahead([24, 24], &used(5, None), 20), Some(31), "within the gap: scan again, twice as wide");
        assert_eq!(rescan_lookahead([24, 24], &used(0, Some(9)), 20), Some(35), "change addresses count too");
        // The next window, 2 x 38 + 25, holds signet's receive index 38 with room to spare.
        assert_eq!(rescan_lookahead([38 + 64 - 1, 38 + 64 - 1], &used(38, Some(56)), 20), None);
        assert_eq!(rescan_lookahead([24, 24], &BTreeMap::new(), 20), None, "nothing used yet");
    }

    #[test]
    fn phases_for_status() {
        assert_eq!(phase(false, 0.0), "syncing");
        assert_eq!(phase(false, 0.1), "filter_headers");
        assert_eq!(phase(false, 0.25), "filters", "filter headers done, filters pending");
        assert_eq!(phase(false, 0.6), "filters");
        assert_eq!(phase(true, 0.6), "synced");
        assert_eq!(builtin_checkpoint(BNetwork::Mainnet, 800_000).0, 709_631);
        assert_eq!(builtin_checkpoint(BNetwork::Mainnet, 600_000).0, 481_823);
        assert_eq!(builtin_checkpoint(BNetwork::Signet, 300_000).0, 0);
    }
}
