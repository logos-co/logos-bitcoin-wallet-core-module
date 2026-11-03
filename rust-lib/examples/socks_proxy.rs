//! A SOCKS5 proxy standing in for Tor in the Kyoto tests: it takes a username and password,
//! connects onion names to the local addresses it maps them to, records each connection's
//! credentials and target, and can go down (connections refused) and come back on its port.
//!   socks_proxy <listen addr> <onion name>=<addr>...

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One connection's credentials and where it asked to go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub user: String,
    pub pass: String,
    pub target: String,
}

pub struct Socks {
    pub addr: SocketAddr,
    up: Arc<AtomicBool>,
    asked: Arc<Mutex<Vec<Asked>>>,
    accepted: Arc<AtomicUsize>,
}

impl Socks {
    /// Listens on `listen`, or only reserves its port while `up` is false.
    pub fn start(listen: &str, map: HashMap<String, SocketAddr>, up: bool) -> Socks {
        let first = TcpListener::bind(listen).expect("bind");
        let addr = first.local_addr().expect("addr");
        let s = Socks { addr, up: Arc::new(AtomicBool::new(up)), asked: Arc::default(), accepted: Arc::default() };
        let (up, asked, accepted, map) = (s.up.clone(), s.asked.clone(), s.accepted.clone(), Arc::new(map));
        std::thread::spawn(move || {
            let mut listener = Some(first);
            loop {
                if !up.load(Ordering::SeqCst) {
                    listener = None;
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                if listener.is_none() {
                    match TcpListener::bind(addr) {
                        Ok(l) => listener = Some(l),
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(50));
                            continue;
                        }
                    }
                }
                let l = listener.as_ref().expect("listening");
                l.set_nonblocking(true).expect("nonblocking");
                match l.accept() {
                    Ok((c, _)) => {
                        accepted.fetch_add(1, Ordering::SeqCst);
                        let (asked, map) = (asked.clone(), map.clone());
                        std::thread::spawn(move || {
                            let _ = serve(c, &map, &asked);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        s
    }

    pub fn set_up(&self, up: bool) {
        self.up.store(up, Ordering::SeqCst);
    }

    /// The connections that asked for a target, in order.
    pub fn asked(&self) -> Vec<Asked> {
        self.asked.lock().unwrap().clone()
    }

    /// Every TCP connection taken, a SOCKS handshake or not.
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

fn serve(mut c: TcpStream, map: &HashMap<String, SocketAddr>, asked: &Mutex<Vec<Asked>>) -> std::io::Result<()> {
    c.set_nonblocking(false)?;
    c.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut b = [0u8; 2];
    c.read_exact(&mut b)?;
    let mut methods = vec![0u8; b[1] as usize];
    c.read_exact(&mut methods)?;
    let (mut user, mut pass) = (String::new(), String::new());
    if methods.contains(&2) {
        c.write_all(&[5, 2])?;
        let mut v = [0u8; 2];
        c.read_exact(&mut v)?;
        let mut u = vec![0u8; v[1] as usize];
        c.read_exact(&mut u)?;
        let mut n = [0u8; 1];
        c.read_exact(&mut n)?;
        let mut p = vec![0u8; n[0] as usize];
        c.read_exact(&mut p)?;
        (user, pass) = (String::from_utf8_lossy(&u).into(), String::from_utf8_lossy(&p).into());
        c.write_all(&[1, 0])?;
    } else {
        c.write_all(&[5, 0])?;
    }
    let mut req = [0u8; 4];
    c.read_exact(&mut req)?;
    let host = match req[3] {
        1 => {
            let mut ip = [0u8; 4];
            c.read_exact(&mut ip)?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut n = [0u8; 1];
            c.read_exact(&mut n)?;
            let mut name = vec![0u8; n[0] as usize];
            c.read_exact(&mut name)?;
            String::from_utf8_lossy(&name).into()
        }
        _ => {
            let mut ip = [0u8; 16];
            c.read_exact(&mut ip)?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
    };
    let mut port = [0u8; 2];
    c.read_exact(&mut port)?;
    let target = format!("{host}:{}", u16::from_be_bytes(port));
    asked.lock().unwrap().push(Asked { user, pass, target });
    // Host unreachable for a name it doesn't map.
    let Some(up) = map.get(&host).and_then(|a| TcpStream::connect_timeout(a, Duration::from_secs(5)).ok()) else {
        c.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0])?;
        return Ok(());
    };
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    c.set_read_timeout(None)?;
    let (mut c2, mut u2) = (c.try_clone()?, up.try_clone()?);
    let mut up = up;
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut u2, &mut c2);
        let _ = c2.shutdown(Shutdown::Both);
    });
    let _ = std::io::copy(&mut c, &mut up);
    let _ = up.shutdown(Shutdown::Both);
    Ok(())
}

#[allow(dead_code)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(listen) = args.get(1) else {
        eprintln!("usage: socks_proxy <listen addr> <onion name>=<addr>...");
        std::process::exit(2);
    };
    let map = args[2..].iter().filter_map(|a| a.split_once('=')).map(|(n, a)| (n.to_string(), a.parse().expect("an address"))).collect();
    let s = Socks::start(listen, map, true);
    println!("socks5 on {}", s.addr);
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}
