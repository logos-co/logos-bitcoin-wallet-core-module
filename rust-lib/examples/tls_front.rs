//! A TLS front for a plain TCP server, with one fixed certificate: a self-signed Electrum server
//! as the pin tests see it. Prints the certificate's SHA-256, the pin, then forwards each
//! connection both ways.
//!   tls_front <listen host:port> <upstream host:port> <cert.der> <key.der>
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection};
use sha2::{Digest, Sha256};

#[derive(Debug)]
struct One(Arc<CertifiedKey>);

impl ResolvesServerCert for One {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Writes all of `data` to a non-blocking socket.
fn write_all(s: &mut TcpStream, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        match s.write(data) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn serve(mut client: TcpStream, upstream: &str, config: Arc<ServerConfig>) -> std::io::Result<()> {
    let mut up = TcpStream::connect(upstream)?;
    let mut conn = ServerConnection::new(config).map_err(std::io::Error::other)?;
    client.set_nonblocking(true)?;
    up.set_nonblocking(true)?;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let mut progress = false;
        match conn.read_tls(&mut client) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                progress = true;
                if let Err(e) = conn.process_new_packets() {
                    let _ = conn.write_tls(&mut client);
                    return Err(std::io::Error::other(e));
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        loop {
            match conn.reader().read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    write_all(&mut up, &buf[..n])?;
                    progress = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        match up.read(&mut buf) {
            Ok(0) => {
                conn.send_close_notify();
                let _ = conn.write_tls(&mut client);
                return Ok(());
            }
            Ok(n) => {
                conn.writer().write_all(&buf[..n])?;
                progress = true;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        while conn.wants_write() {
            match conn.write_tls(&mut client) {
                Ok(_) => progress = true,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        if !progress {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, listen, upstream, cert, key] = args.as_slice() else {
        eprintln!("usage: tls_front <listen host:port> <upstream host:port> <cert.der> <key.der>");
        std::process::exit(2);
    };
    let cert = std::fs::read(cert).expect("certificate");
    let key = std::fs::read(key).expect("key");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let signing = provider.key_provider.load_private_key(PrivateKeyDer::try_from(key).expect("a DER key")).expect("a usable key");
    let certified = Arc::new(CertifiedKey::new(vec![CertificateDer::from(cert.clone())], signing));
    let config = ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().expect("TLS versions").with_no_client_auth().with_cert_resolver(Arc::new(One(certified)));
    let config = Arc::new(config);
    let listener = TcpListener::bind(listen).expect("listen");
    println!("tls_front {} -> {upstream}: certSha256 {}", listener.local_addr().expect("address"), hex::encode(Sha256::digest(&cert)));
    for client in listener.incoming().flatten() {
        let (config, upstream) = (config.clone(), upstream.clone());
        std::thread::spawn(move || {
            if let Err(e) = serve(client, &upstream, config) {
                eprintln!("tls_front: {e}");
            }
        });
    }
}
