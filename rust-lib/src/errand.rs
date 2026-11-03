//! One-shot Tor errands for `identifying`: Kyoto takes headers and filters directly, and each
//! matched block, and each broadcast, goes to a random onion peer over a circuit of its own
//! (fresh SOCKS credentials), then the connection closes. Retries go to other onion peers on new
//! circuits, never direct. README, "Use Tor for", has the rules and why.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bdk_kyoto::bip157::{Block, BlockHash};
use bdk_kyoto::Requester;
use bitcoin::consensus::encode;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::Transaction;
use parking_lot::Mutex;
use rand::Rng;

use crate::kyoto::{onion_name, parse_peer, Peer};
use crate::routes::{ErrandRoute, Isolation, Proxy};

/// Block errands at once; the rest wait their turn, oldest first.
const AT_ONCE: usize = 6;
/// Broadcast errands at once, each to a peer and on a circuit of its own.
const BROADCAST_AT_ONCE: usize = 3;
/// Over Tor: the connection, and each read.
const TIMEOUT: Duration = Duration::from_secs(60);
/// One block errand at most, connection to block.
const DEADLINE: Duration = Duration::from_secs(180);
const RETRY_MAX: Duration = Duration::from_secs(60);
/// Kyoto's own version message, so an onion peer can't tell an errand from a Kyoto client.
const USER_AGENT: &str = "/Rust BIP-157:0.8.1/rust-bitcoin:0.32.8/";
const PROTOCOL: u32 = 70016;
/// A block with its witnesses fits in 4 MB.
const MAX_MESSAGE: usize = 8 << 20;

/// `status.kyoto.tor` while the split runs.
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TorStatus {
    /// Matched blocks not fetched over Tor yet.
    pub pending: usize,
    pub fetched: u64,
    pub broadcasts: u64,
    /// Errands that failed and went to another onion peer.
    pub retries: u64,
    /// Tor can't be reached; nothing goes direct meanwhile.
    pub waiting: bool,
    pub last_error: Option<String>,
}

pub type Status = Arc<Mutex<TorStatus>>;

/// How far a broadcast got: a peer's pong came back after the transaction, or the transaction was
/// written to a peer that asked for it and the errand ended before the pong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    Taken,
    Maybe,
}

/// A broadcast's errands so far, shared by its lanes.
#[derive(Default)]
struct Round {
    tried: HashSet<usize>,
    taken: bool,
    maybe: bool,
    last: Option<String>,
}

/// Why an errand failed; `tor` when Tor's SOCKS port itself doesn't answer.
#[derive(Debug)]
struct Fail {
    why: String,
    tor: bool,
}

fn fail(why: impl Into<String>) -> Fail {
    Fail { why: why.into(), tor: false }
}

pub struct Errands {
    magic: Magic,
    peers: Vec<(String, Peer)>,
    proxy: Proxy,
    max_delay: Duration,
    status: Status,
    slots: tokio::sync::Semaphore,
}

impl Errands {
    pub fn new(net: bitcoin::Network, route: &ErrandRoute, proxy: &Proxy, status: Status) -> Result<Errands, String> {
        let port = crate::kyoto::default_port(net);
        let peers: Vec<(String, Peer)> = route.peers.iter().filter_map(|p| parse_peer(p, port).ok().filter(|x| !matches!(x, Peer::Lan(..))).map(|x| (p.clone(), x))).collect();
        if peers.is_empty() {
            return Err("no onion peer for matched blocks".into());
        }
        Ok(Errands { magic: net.magic(), peers, proxy: proxy.clone(), max_delay: route.max_delay, status, slots: tokio::sync::Semaphore::new(AT_ONCE) })
    }

    /// The block at `height` a filter matched, from onion peers, tried until one sends it after a
    /// random wait; none once it is no longer in Kyoto's chain. No answer while the node is stopped.
    pub async fn block(self: Arc<Self>, requester: Requester, height: u32, hash: BlockHash) -> Option<Block> {
        let _pending = Pending::new(&self.status);
        // Never closed; if it were, pend rather than let the scan pass this block.
        let Ok(_slot) = self.slots.acquire().await else { return std::future::pending().await };
        let wait = rand::thread_rng().gen_range(0..=self.max_delay.as_millis() as u64);
        tokio::time::sleep(Duration::from_millis(wait)).await;
        let (mut tried, mut backoff) = (HashSet::new(), Duration::from_secs(1));
        loop {
            if !in_chain(&requester, height, hash).await {
                return None;
            }
            let (name, peer) = self.pick(&mut tried);
            let me = self.clone();
            let got = tokio::task::spawn_blocking(move || me.fetch(&peer, hash)).await.unwrap_or_else(|e| Err(fail(e.to_string())));
            match got {
                Ok(block) => {
                    {
                        let mut s = self.status.lock();
                        s.fetched += 1;
                        s.waiting = false;
                    }
                    return in_chain(&requester, height, hash).await.then_some(block);
                }
                Err(f) => {
                    tracing::info!(target: "bitcoin", "errand for block {height} via {name}: {}", f.why);
                    self.failed(&name, &f);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(RETRY_MAX);
                }
            }
        }
    }

    fn failed(&self, name: &str, f: &Fail) {
        let mut s = self.status.lock();
        s.retries += 1;
        s.waiting = f.tor;
        s.last_error = Some(if f.tor { f.why.clone() } else { format!("{name}: {}", f.why) });
    }

    /// A random peer not tried yet; all of them again once each was.
    fn pick(&self, tried: &mut HashSet<usize>) -> (String, Peer) {
        if tried.len() >= self.peers.len() {
            tried.clear();
        }
        let left: Vec<usize> = (0..self.peers.len()).filter(|i| !tried.contains(i)).collect();
        let i = left[rand::thread_rng().gen_range(0..left.len())];
        tried.insert(i);
        self.peers[i].clone()
    }

    fn fetch(&self, peer: &Peer, hash: BlockHash) -> Result<Block, Fail> {
        let (mut c, services) = self.open(peer, false, Instant::now() + DEADLINE)?;
        if !services.has(ServiceFlags::WITNESS) || !(services.has(ServiceFlags::NETWORK) || services.has(ServiceFlags::NETWORK_LIMITED)) {
            return Err(fail("the peer serves no witness blocks"));
        }
        c.send(NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]))?;
        loop {
            match c.recv()? {
                NetworkMessage::Block(b) if b.block_hash() == hash => return checked(b),
                NetworkMessage::NotFound(_) => return Err(fail("the peer doesn't have the block")),
                NetworkMessage::Ping(n) => c.send(NetworkMessage::Pong(n))?,
                _ => {}
            }
        }
    }

    /// `inv`, then the transaction when the peer asks for it; a ping after it, so the peer has
    /// taken it before the connection closes. Once the transaction is written it may be out.
    fn broadcast(&self, peer: &Peer, tx: &Transaction, until: Instant) -> Result<Sent, Fail> {
        let (mut c, _) = self.open(peer, true, until)?;
        let (txid, wtxid) = (tx.compute_txid(), tx.compute_wtxid());
        c.send(NetworkMessage::Inv(vec![Inventory::Transaction(txid)]))?;
        loop {
            match c.recv()? {
                NetworkMessage::GetData(items) if items.iter().any(|i| matches!(i, Inventory::Transaction(t) | Inventory::WitnessTransaction(t) if *t == txid) || *i == Inventory::WTx(wtxid)) => break,
                NetworkMessage::Ping(n) => c.send(NetworkMessage::Pong(n))?,
                _ => {}
            }
        }
        c.send(NetworkMessage::Tx(tx.clone()))?;
        let nonce = rand::random();
        if c.send(NetworkMessage::Ping(nonce)).is_err() {
            return Ok(Sent::Maybe);
        }
        while let Ok(m) = c.recv() {
            if m == NetworkMessage::Pong(nonce) {
                return Ok(Sent::Taken);
            }
        }
        Ok(Sent::Maybe)
    }

    /// One lane of a broadcast: peer after peer until one takes it, another lane's peer did, or
    /// time is up. True when this lane's peer took it.
    fn broadcast_lane(&self, round: &Mutex<Round>, tx: &Transaction, until: Instant) -> bool {
        loop {
            let pick = {
                let mut r = round.lock();
                (!r.taken && Instant::now() < until).then(|| self.pick(&mut r.tried))
            };
            let Some((name, peer)) = pick else { return false };
            match self.broadcast(&peer, tx, until) {
                Ok(Sent::Taken) => {
                    round.lock().taken = true;
                    return true;
                }
                Ok(Sent::Maybe) => {
                    tracing::info!(target: "bitcoin", "broadcast errand via {name}: sent, but the errand ended before the peer's pong");
                    round.lock().maybe = true;
                }
                Err(f) => {
                    tracing::info!(target: "bitcoin", "broadcast errand via {name}: {}", f.why);
                    self.failed(&name, &f);
                    round.lock().last = Some(f.why.clone());
                    if f.tor {
                        std::thread::sleep(Duration::from_secs(1).min(until.saturating_duration_since(Instant::now())));
                    }
                }
            }
        }
    }

    /// A connection on a circuit of its own, after the version handshake; the peer's services.
    fn open(&self, peer: &Peer, relay: bool, until: Instant) -> Result<(Conn, ServiceFlags), Fail> {
        let (host, port) = match peer {
            Peer::Onion(key, port) => (onion_name(key), *port),
            Peer::Ip(sa) => (sa.ip().to_string(), sa.port()),
            Peer::Lan(..) => return Err(fail("a name on your network can't be reached through Tor")),
        };
        let timeout = TIMEOUT.min(until.saturating_duration_since(Instant::now())).max(Duration::from_secs(1));
        let tcp = crate::pin::tcp(&host, port, Some((&self.proxy, &Isolation::fresh())), timeout).map_err(|e| self.connect_failed(e))?;
        let mut c = Conn { tcp, magic: self.magic, until };
        c.send(NetworkMessage::Version(version(relay)))?;
        let (mut services, mut verack) = (None, false);
        while services.is_none() || !verack {
            match c.recv()? {
                NetworkMessage::Version(v) if v.version < PROTOCOL => return Err(fail(format!("protocol {} is below {PROTOCOL}", v.version))),
                NetworkMessage::Version(v) => {
                    services = Some(v.services);
                    c.send(NetworkMessage::Verack)?;
                }
                NetworkMessage::Verack => verack = true,
                _ => {}
            }
        }
        Ok((c, services.unwrap_or(ServiceFlags::NONE)))
    }

    /// A connection that failed: Tor itself when its SOCKS port doesn't take a connection.
    fn connect_failed(&self, why: String) -> Fail {
        let up = self.proxy.addr().to_socket_addrs().ok().and_then(|mut a| a.next()).is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_secs(2)).is_ok());
        match up {
            true => fail(why),
            false => Fail { why: format!("Tor can't be reached at {}: {why}", self.proxy.addr()), tor: true },
        }
    }
}

/// Sends `tx` through onion peers within `budget`, a few errands at once, until a peer takes it.
/// Err when no errand wrote it: nothing was sent.
pub fn broadcast(net: bitcoin::Network, route: &ErrandRoute, proxy: &Proxy, status: &Status, tx: &Transaction, budget: Duration) -> Result<Sent, String> {
    let e = Arc::new(Errands::new(net, route, proxy, status.clone())?);
    let until = Instant::now() + budget;
    let round = Arc::new(Mutex::new(Round::default()));
    let (done, ended) = std::sync::mpsc::channel();
    let lanes = BROADCAST_AT_ONCE.min(e.peers.len());
    for _ in 0..lanes {
        let (e, round, done, tx) = (e.clone(), round.clone(), done.clone(), tx.clone());
        // A lane still out once another's peer took it ends by `until`.
        std::thread::spawn(move || {
            let _ = done.send(e.broadcast_lane(&round, &tx, until));
        });
    }
    drop(done);
    if ended.iter().any(|taken| taken) {
        let mut s = status.lock();
        s.broadcasts += 1;
        s.waiting = false;
        return Ok(Sent::Taken);
    }
    let r = round.lock();
    match r.maybe {
        true => Ok(Sent::Maybe),
        false => Err(r.last.clone().unwrap_or_else(|| "no onion peer asked for the transaction in time".into())),
    }
}

/// Whether `hash` is still Kyoto's block at `height`; a stopped node never answers, so a scan
/// isn't taken past a block it couldn't check.
async fn in_chain(requester: &Requester, height: u32, hash: BlockHash) -> bool {
    match requester.get_header(height).await {
        Ok(h) => h.is_some_and(|h| h.header.block_hash() == hash),
        Err(_) => std::future::pending().await,
    }
}

/// The block as the filter named it: its transactions and witnesses as its header commits to.
fn checked(b: Block) -> Result<Block, Fail> {
    if !b.check_merkle_root() {
        return Err(fail("the block's merkle root doesn't match its transactions"));
    }
    if !b.check_witness_commitment() {
        return Err(fail("the block's witness commitment doesn't match"));
    }
    Ok(b)
}

fn version(relay: bool) -> VersionMessage {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let local = Address::new(&std::net::SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8333), ServiceFlags::NONE);
    VersionMessage {
        version: PROTOCOL,
        services: ServiceFlags::NONE,
        timestamp: now as i64,
        receiver: local.clone(),
        sender: local,
        nonce: rand::random(),
        user_agent: USER_AGENT.to_string(),
        start_height: 0,
        relay,
    }
}

struct Pending(Status);

impl Pending {
    fn new(s: &Status) -> Pending {
        s.lock().pending += 1;
        Pending(s.clone())
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        let mut s = self.0.lock();
        s.pending = s.pending.saturating_sub(1);
    }
}

struct Conn {
    tcp: TcpStream,
    magic: Magic,
    until: Instant,
}

impl Conn {
    fn send(&mut self, m: NetworkMessage) -> Result<(), Fail> {
        self.tcp.write_all(&encode::serialize(&RawNetworkMessage::new(self.magic, m))).map_err(|e| fail(e.to_string()))
    }

    /// The next message the errand reads; one it can't parse and doesn't need is skipped.
    fn recv(&mut self) -> Result<NetworkMessage, Fail> {
        loop {
            let left = self.until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(fail("timed out"));
            }
            self.tcp.set_read_timeout(Some(left.min(TIMEOUT))).map_err(|e| fail(e.to_string()))?;
            let mut buf = vec![0u8; 24];
            self.tcp.read_exact(&mut buf).map_err(|e| fail(e.to_string()))?;
            if buf[..4] != self.magic.to_bytes() {
                return Err(fail("the peer is on another network"));
            }
            let len = u32::from_le_bytes(buf[16..20].try_into().expect("4 bytes")) as usize;
            if len > MAX_MESSAGE {
                return Err(fail("a message too large"));
            }
            let command = String::from_utf8_lossy(&buf[4..16]).trim_end_matches('\0').to_string();
            buf.resize(24 + len, 0);
            self.tcp.read_exact(&mut buf[24..]).map_err(|e| fail(e.to_string()))?;
            match encode::deserialize::<RawNetworkMessage>(&buf) {
                Ok(raw) => return Ok(raw.into_payload()),
                Err(e) if ["version", "verack", "block", "getdata", "notfound"].contains(&command.as_str()) => return Err(fail(format!("a bad {command}: {e}"))),
                Err(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::constants::genesis_block;

    #[test]
    fn a_block_must_match_its_commitments() {
        let b = genesis_block(bitcoin::Network::Regtest);
        assert!(checked(b.clone()).is_ok());
        let mut forged = b;
        forged.txdata[0].output[0].value = bitcoin::Amount::from_sat(1);
        assert!(checked(forged).unwrap_err().why.contains("merkle root"));
    }

    #[test]
    fn each_peer_is_tried_once_before_any_again() {
        let route = ErrandRoute { peers: (1..=3).map(|i| format!("127.0.0.{i}:18444")).collect(), max_delay: Duration::ZERO };
        let e = Errands::new(bitcoin::Network::Regtest, &route, &Proxy::parse("socks5h://127.0.0.1:9").unwrap(), Status::default()).unwrap();
        let mut tried = HashSet::new();
        let round: HashSet<String> = (0..3).map(|_| e.pick(&mut tried).0).collect();
        assert_eq!(round.len(), 3);
        assert_eq!(tried.len(), 3);
        e.pick(&mut tried);
        assert_eq!(tried.len(), 1, "a new round once each was tried");
    }

    #[test]
    fn tor_down_reads_as_waiting() {
        let route = ErrandRoute { peers: vec!["127.0.0.1:18444".into()], max_delay: Duration::ZERO };
        // Port 9 on loopback takes no connection: no Tor there.
        let status = Status::default();
        let tx = genesis_block(bitcoin::Network::Regtest).txdata[0].clone();
        let r = broadcast(bitcoin::Network::Regtest, &route, &Proxy::parse("socks5h://127.0.0.1:9").unwrap(), &status, &tx, Duration::from_millis(300));
        assert!(r.is_err());
        let s = status.lock().clone();
        assert!(s.waiting && s.retries >= 1 && s.broadcasts == 0, "{s:?}");
        assert!(s.last_error.unwrap().starts_with("Tor can't be reached"));
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Act {
        Take,
        Dead,
        Mute,
        DropAfterTx,
    }

    /// A SOCKS5 proxy on loopback that plays each peer itself, as `act` says for its last octet.
    fn fake_tor(act: fn(u8) -> Act) -> Proxy {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                std::thread::spawn(move || serve(s, act));
            }
        });
        Proxy::parse(&format!("socks5h://{addr}")).unwrap()
    }

    fn serve(mut s: TcpStream, act: fn(u8) -> Act) -> Result<(), String> {
        let io = |e: std::io::Error| e.to_string();
        let mut b = [0u8; 2];
        s.read_exact(&mut b).map_err(io)?;
        s.read_exact(&mut vec![0u8; b[1] as usize]).map_err(io)?;
        s.write_all(&[5, 2]).map_err(io)?;
        s.read_exact(&mut b).map_err(io)?;
        let mut user = vec![0u8; b[1] as usize + 1];
        s.read_exact(&mut user).map_err(io)?;
        s.read_exact(&mut vec![0u8; user[b[1] as usize] as usize]).map_err(io)?;
        s.write_all(&[1, 0]).map_err(io)?;
        let mut req = [0u8; 10];
        s.read_exact(&mut req).map_err(io)?;
        let act = act(req[7]);
        if act == Act::Dead {
            // Tor's reply for an onion service it can't find.
            return s.write_all(&[5, 0xf0, 0, 1, 0, 0, 0, 0, 0, 0]).map_err(io);
        }
        s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).map_err(io)?;
        let mut c = Conn { tcp: s, magic: bitcoin::Network::Regtest.magic(), until: Instant::now() + Duration::from_secs(30) };
        loop {
            match c.recv().map_err(|f| f.why)? {
                NetworkMessage::Version(_) => {
                    c.send(NetworkMessage::Version(version(true))).map_err(|f| f.why)?;
                    c.send(NetworkMessage::Verack).map_err(|f| f.why)?;
                }
                NetworkMessage::Verack => break,
                _ => {}
            }
        }
        if act == Act::Mute {
            std::thread::sleep(Duration::from_secs(30));
            return Ok(());
        }
        loop {
            if let NetworkMessage::Inv(items) = c.recv().map_err(|f| f.why)? {
                c.send(NetworkMessage::GetData(items)).map_err(|f| f.why)?;
                break;
            }
        }
        while !matches!(c.recv().map_err(|f| f.why)?, NetworkMessage::Tx(_)) {}
        if act == Act::DropAfterTx {
            return Ok(());
        }
        loop {
            if let NetworkMessage::Ping(n) = c.recv().map_err(|f| f.why)? {
                c.send(NetworkMessage::Pong(n)).map_err(|f| f.why)?;
            }
        }
    }

    fn send_via(peers: &[u8], act: fn(u8) -> Act, budget: Duration) -> (Result<Sent, String>, TorStatus, Duration) {
        let route = ErrandRoute { peers: peers.iter().map(|i| format!("127.0.0.{i}:18444")).collect(), max_delay: Duration::ZERO };
        let (status, start) = (Status::default(), Instant::now());
        let tx = genesis_block(bitcoin::Network::Regtest).txdata[0].clone();
        let r = broadcast(bitcoin::Network::Regtest, &route, &fake_tor(act), &status, &tx, budget);
        let s = status.lock().clone();
        (r, s, start.elapsed())
    }

    #[test]
    fn the_peer_that_asks_takes_it() {
        let (r, s, _) = send_via(&[1], |_| Act::Take, Duration::from_secs(10));
        assert_eq!(r, Ok(Sent::Taken));
        assert_eq!((s.broadcasts, s.retries), (1, 0));
    }

    #[test]
    fn a_transaction_written_without_a_pong_may_be_out() {
        let (r, s, _) = send_via(&[1], |_| Act::DropAfterTx, Duration::from_secs(2));
        assert_eq!(r, Ok(Sent::Maybe), "not \"nothing sent\"");
        assert_eq!(s.broadcasts, 0);
    }

    #[test]
    fn dead_and_mute_peers_dont_hold_up_one_that_takes_it() {
        let act = |i| match i {
            1 => Act::Dead,
            2 => Act::Mute,
            _ => Act::Take,
        };
        let (r, s, took) = send_via(&[1, 2, 3], act, Duration::from_secs(20));
        assert_eq!(r, Ok(Sent::Taken));
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(s.broadcasts, 1);
    }

    #[test]
    fn when_every_errand_fails_nothing_was_sent() {
        let (r, s, _) = send_via(&[1, 2], |_| Act::Dead, Duration::from_secs(1));
        assert!(r.is_err(), "{r:?}");
        assert!(s.retries >= 2 && !s.waiting, "{s:?}");
    }
}
