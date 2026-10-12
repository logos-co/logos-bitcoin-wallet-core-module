//! A Bitcoin P2P proxy for the Kyoto tests: forwards a peer, or delays its answers, goes down,
//! or forges the filter header and filter of one block, sending the forged batch several times.
//! The tests use it in process; scripts run it with a mode file it rereads every 200 ms:
//!   p2p_proxy <listen addr> <upstream addr> <mode file>
//! Modes, as JSON: {"mode":"forward"} | {"mode":"down"} |
//!   {"mode":"delay","ms":{"headers":500,"cfheaders":2000,"cfilter":5}} |
//!   {"mode":"forge","block":"<hash>","copies":3}

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::bip158::FilterHash;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::p2p::message_filter::{CFHeaders, CFilter};
use bitcoin::BlockHash;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum Mode {
    Forward,
    /// No connections: new ones are closed, live ones cut.
    Down,
    /// Holds each answer of these commands this many milliseconds.
    Delay { ms: HashMap<String, u64> },
    /// Swaps `block`'s filter for an empty one, in its filter header batch and its filter, and
    /// sends each forged batch `copies` times.
    Forge { block: BlockHash, copies: usize },
}

/// The empty BIP158 filter: no elements.
pub const FORGED_FILTER: [u8; 1] = [0];

pub fn forged_filter_hash() -> FilterHash {
    FilterHash::from_raw_hash(sha256d::Hash::hash(&FORGED_FILTER))
}

pub struct Proxy {
    pub addr: SocketAddr,
    mode: Arc<Mutex<Mode>>,
    live: Arc<Mutex<Vec<TcpStream>>>,
    /// Commands seen from upstream, and how many batches were forged.
    pub seen: Arc<Mutex<HashMap<String, usize>>>,
    /// Bytes of each command from upstream, headers included.
    pub bytes: Arc<Mutex<HashMap<String, usize>>>,
}

impl Proxy {
    pub fn start(listen: &str, upstream: SocketAddr, mode: Mode) -> Proxy {
        let listener = TcpListener::bind(listen).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let p = Proxy { addr, mode: Arc::new(Mutex::new(mode)), live: Arc::default(), seen: Arc::default(), bytes: Arc::default() };
        let (mode, live, seen, bytes) = (p.mode.clone(), p.live.clone(), p.seen.clone(), p.bytes.clone());
        std::thread::spawn(move || {
            for client in listener.incoming().flatten() {
                if *mode.lock().unwrap() == Mode::Down {
                    let _ = client.shutdown(Shutdown::Both);
                    continue;
                }
                let Ok(up) = TcpStream::connect_timeout(&upstream, Duration::from_secs(5)) else {
                    let _ = client.shutdown(Shutdown::Both);
                    continue;
                };
                live.lock().unwrap().extend([client.try_clone().unwrap(), up.try_clone().unwrap()]);
                let (c2, u2) = (client.try_clone().unwrap(), up.try_clone().unwrap());
                std::thread::spawn(move || pump(client, u2, None));
                let (m, s, b) = (mode.clone(), seen.clone(), bytes.clone());
                std::thread::spawn(move || pump(up, c2, Some((m, s, b))));
            }
        });
        p
    }

    pub fn set(&self, mode: Mode) {
        let down = mode == Mode::Down;
        *self.mode.lock().unwrap() = mode;
        if down {
            for s in self.live.lock().unwrap().drain(..) {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }

    pub fn count(&self, command: &str) -> usize {
        self.seen.lock().unwrap().get(command).copied().unwrap_or(0)
    }

    /// Messages and bytes from upstream so far, by command.
    pub fn traffic(&self) -> HashMap<String, (usize, usize)> {
        let (seen, bytes) = (self.seen.lock().unwrap(), self.bytes.lock().unwrap());
        seen.iter().map(|(c, n)| (c.clone(), (*n, bytes.get(c).copied().unwrap_or(0)))).collect()
    }
}

fn read_message(r: &mut impl Read) -> std::io::Result<([u8; 24], Vec<u8>)> {
    let mut header = [0u8; 24];
    r.read_exact(&mut header)?;
    let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    if len > 32 << 20 {
        return Err(std::io::Error::other("message too large"));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok((header, payload))
}

fn command(header: &[u8; 24]) -> String {
    String::from_utf8_lossy(&header[4..16]).trim_end_matches('\0').to_string()
}

/// The header for `payload` under `header`'s magic and command: new length and checksum.
fn reframe(header: &[u8; 24], payload: &[u8]) -> Vec<u8> {
    let mut out = header[..16].to_vec();
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&sha256d::Hash::hash(payload)[..4]);
    out.extend_from_slice(payload);
    out
}

type Watch = (Arc<Mutex<Mode>>, Arc<Mutex<HashMap<String, usize>>>, Arc<Mutex<HashMap<String, usize>>>);

/// Copies messages from `from` to `to`; upstream's, with `watch`, as the mode says.
fn pump(mut from: TcpStream, mut to: TcpStream, watch: Option<Watch>) {
    loop {
        let Ok((header, payload)) = read_message(&mut from) else { break };
        let mut copies = 1;
        let mut bytes = None;
        if let Some((mode, seen, sizes)) = &watch {
            let cmd = command(&header);
            *seen.lock().unwrap().entry(cmd.clone()).or_default() += 1;
            *sizes.lock().unwrap().entry(cmd.clone()).or_default() += header.len() + payload.len();
            let m = mode.lock().unwrap().clone();
            match m {
                Mode::Down => break,
                Mode::Delay { ms } => {
                    if let Some(d) = ms.get(&cmd) {
                        std::thread::sleep(Duration::from_millis(*d));
                    }
                }
                Mode::Forge { block, copies: n } => match cmd.as_str() {
                    "cfheaders" => {
                        if let Ok(mut h) = deserialize::<CFHeaders>(&payload) {
                            if h.stop_hash == block {
                                if let Some(last) = h.filter_hashes.last_mut() {
                                    *last = forged_filter_hash();
                                    copies = n.max(1);
                                    bytes = Some(reframe(&header, &serialize(&h)));
                                    *seen.lock().unwrap().entry("forged".into()).or_default() += 1;
                                }
                            }
                        }
                    }
                    "cfilter" => {
                        if let Ok(mut f) = deserialize::<CFilter>(&payload) {
                            if f.block_hash == block {
                                f.filter = FORGED_FILTER.to_vec();
                                bytes = Some(reframe(&header, &serialize(&f)));
                            }
                        }
                    }
                    _ => {}
                },
                Mode::Forward => {}
            }
        }
        let out = bytes.unwrap_or_else(|| reframe(&header, &payload));
        for _ in 0..copies {
            if to.write_all(&out).is_err() {
                let _ = from.shutdown(Shutdown::Both);
                return;
            }
        }
    }
    let _ = to.shutdown(Shutdown::Both);
}

#[allow(dead_code)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, listen, upstream, file] = args.as_slice() else {
        eprintln!("usage: p2p_proxy <listen addr> <upstream addr> <mode file>");
        std::process::exit(2);
    };
    let read = |f: &str| std::fs::read_to_string(f).ok().and_then(|t| serde_json::from_str::<Mode>(&t).ok()).unwrap_or(Mode::Forward);
    let p = Proxy::start(listen, upstream.parse().expect("upstream address"), read(file));
    println!("{} -> {upstream}", p.addr);
    let mut last = read(file);
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let now = read(file);
        if now != last {
            p.set(now.clone());
            last = now;
        }
    }
}
