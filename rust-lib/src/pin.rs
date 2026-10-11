//! Electrum over TLS with a pinned end-entity certificate, for servers with self-signed ones:
//! the pin takes the place of the CAs and the name check; the handshake signature is still
//! verified against the pinned certificate's key, so a copy of the certificate proves nothing.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use bdk_electrum::electrum_client::raw_client::{ElectrumSslStream, RawClient};
use bdk_electrum::electrum_client::socks::Socks5Stream;
use bdk_electrum::electrum_client::{ElectrumApi, Param};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use sha2::{Digest, Sha256};

use crate::routes::{Isolation, Proxy};

/// Accepts exactly one certificate, by its SHA-256, whatever its version, issuer or dates.
#[derive(Debug)]
pub struct Pinned {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl Pinned {
    pub fn new(pin: [u8; 32]) -> Self {
        Self { pin, provider: Arc::new(rustls::crypto::ring::default_provider()) }
    }
}

fn general(why: &str) -> rustls::Error {
    rustls::Error::General(why.to_string())
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        if Sha256::digest(end_entity.as_ref())[..] == self.pin[..] {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(general("the server's certificate is not the pinned one"))
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify(message, cert, dss, &self.provider, false)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        if !tls13_scheme(dss.scheme) {
            return Err(rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
        }
        verify(message, cert, dss, &self.provider, true)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// The schemes TLS 1.3 signs handshakes with (RFC 8446, 4.2.3).
fn tls13_scheme(s: SignatureScheme) -> bool {
    use SignatureScheme::*;
    matches!(s, ECDSA_NISTP256_SHA256 | ECDSA_NISTP384_SHA384 | ECDSA_NISTP521_SHA512 | RSA_PSS_SHA256 | RSA_PSS_SHA384 | RSA_PSS_SHA512 | ED25519 | ED448)
}

/// The signature over the handshake, checked with the certificate's own key. The key is read
/// from the DER directly, since webpki refuses version 1 certificates outright.
fn verify(message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct, provider: &CryptoProvider, tls13: bool) -> Result<HandshakeSignatureValid, rustls::Error> {
    let spki = SubjectPublicKeyInfoDer::from(spki_of(cert.as_ref()).ok_or_else(|| general("the certificate has no readable public key"))?);
    let key = webpki::RawPublicKeyEntity::try_from(&spki).map_err(|e| general(&format!("the certificate's public key: {e}")))?;
    let algs = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(scheme, _)| *scheme == dss.scheme)
        .map(|(_, algs)| *algs)
        .ok_or(rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme)?;
    // TLS 1.3 names one algorithm per scheme; TLS 1.2 may need each candidate tried.
    let tried = if tls13 { &algs[..algs.len().min(1)] } else { algs };
    if tried.iter().any(|alg| key.verify_signature(*alg, message, dss.signature()).is_ok()) {
        Ok(HandshakeSignatureValid::assertion())
    } else {
        Err(rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))
    }
}

/// One DER element: its tag, its contents and what follows it.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)? as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    (end <= b.len()).then(|| (tag, &b[header..end], &b[end..]))
}

/// The SubjectPublicKeyInfo element of an X.509 certificate, version 1 or 3.
pub fn spki_of(cert: &[u8]) -> Option<&[u8]> {
    let (tag, certificate, _) = tlv(cert)?;
    let (tbs_tag, tbs, _) = tlv(certificate)?;
    if tag != 0x30 || tbs_tag != 0x30 {
        return None;
    }
    let mut rest = tbs;
    // The explicit [0] version is absent in version 1.
    if rest.first() == Some(&0xa0) {
        rest = tlv(rest)?.2;
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        rest = tlv(rest)?.2;
    }
    let (spki_tag, _, after) = tlv(rest)?;
    (spki_tag == 0x30).then(|| &rest[..rest.len() - after.len()])
}

/// Accepts any certificate that signs the handshake with its own key, and keeps its SHA-256:
/// what a probe would offer the person to pin, trusting it on first use.
#[derive(Debug)]
struct Capture {
    seen: std::sync::Mutex<Option<[u8; 32]>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap() = Some(Sha256::digest(end_entity.as_ref()).into());
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify(message, cert, dss, &self.provider, false)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify(message, cert, dss, &self.provider, true)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn tcp(host: &str, port: u16, proxy: Option<(&Proxy, &Isolation)>, timeout: Duration) -> Result<TcpStream, String> {
    let tcp = match proxy {
        Some((p, iso)) => Socks5Stream::connect_with_password(p.addr(), (host, port), &iso.user, &iso.pass, Some(timeout)).map_err(|e| e.to_string())?.into_inner(),
        None => {
            let addr = (host, port).to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("the server's name resolves to nothing")?;
            TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?
        }
    };
    tcp.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    Ok(tcp)
}

/// The SHA-256 of the end-entity certificate `url` presents, read in a handshake that proves
/// the server holds its key. A pin taken this way trusts the first answer.
pub fn certificate_sha256(url: &str, proxy: Option<(&Proxy, &Isolation)>, timeout: Duration) -> Result<[u8; 32], String> {
    use std::io::Write;
    let (host, port) = host_port(url)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let capture = Arc::new(Capture { seen: Default::default(), provider: provider.clone() });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(host.clone()).map_err(|_| format!("{host} is not a server name"))?;
    let session = ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    let mut stream = StreamOwned::new(session, tcp(&host, port, proxy, timeout)?);
    stream.flush().map_err(|e| e.to_string())?;
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock).map_err(|e| e.to_string())?;
    }
    let seen = *capture.seen.lock().unwrap();
    seen.ok_or_else(|| "the server presented no certificate".into())
}

fn host_port(url: &str) -> Result<(String, u16), String> {
    let rest = url.strip_prefix("ssl://").ok_or("a pinned certificate is for an ssl:// server")?;
    let rest = rest.split(['/', '?']).next().unwrap_or(rest);
    let (host, port) = rest.rsplit_once(':').ok_or("the server's URL has no port")?;
    let port = port.parse::<u16>().map_err(|_| "the server's URL has a bad port".to_string())?;
    Ok((host.trim_matches(['[', ']']).to_string(), port))
}

/// An Electrum client over TLS to `url`, accepting only the pinned certificate; through the
/// proxy with its own circuit when `proxy` is given.
pub fn connect(url: &str, pin: [u8; 32], proxy: Option<(&Proxy, &Isolation)>, timeout: Duration) -> Result<RawClient<ElectrumSslStream>, String> {
    let (host, port) = host_port(url)?;
    let tcp = tcp(&host, port, proxy, timeout)?;
    let verifier = Arc::new(Pinned::new(pin));
    let config = ClientConfig::builder_with_provider(verifier.provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let name = ServerName::try_from(host.clone()).map_err(|_| format!("{host} is not a server name"))?;
    let session = ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    let client = RawClient::from(StreamOwned::new(session, tcp));
    // Electrum asks for server.version first; electrum-client does the same on its own clients.
    let versions = vec!["1.4".to_string(), "1.6".to_string()];
    client.raw_call("server.version", vec![Param::String("bitcoin-wallet".into()), Param::StringVec(versions)]).map_err(|e| e.to_string())?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    use rustls::pki_types::PrivateKeyDer;

    const V3: &[u8] = include_bytes!("../tests/data/pin/v3.der");
    const V3_KEY: &[u8] = include_bytes!("../tests/data/pin/v3.key.der");
    const V1: &[u8] = include_bytes!("../tests/data/pin/v1.der");
    const V1_KEY: &[u8] = include_bytes!("../tests/data/pin/v1.key.der");
    const RSA: &[u8] = include_bytes!("../tests/data/pin/rsa.der");
    const RSA_KEY: &[u8] = include_bytes!("../tests/data/pin/rsa.key.der");

    /// Serves one certificate with one key, matching or not, as a misconfigured or lying server might.
    #[derive(Debug)]
    struct Fixed(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for Fixed {
        fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    /// A TLS server answering Electrum's server.version and headers.subscribe.
    fn server(cert: &'static [u8], key: &'static [u8], tls12_only: bool) -> u16 {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let signing = provider.key_provider.load_private_key(PrivateKeyDer::try_from(key).unwrap()).unwrap();
        let certified = rustls::sign::CertifiedKey::new(vec![CertificateDer::from(cert)], signing);
        let versions: &[&rustls::SupportedProtocolVersion] = if tls12_only { &[&rustls::version::TLS12] } else { rustls::DEFAULT_VERSIONS };
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(Arc::new(certified))));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = Arc::new(config);
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let conn = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut tls = StreamOwned::new(conn, tcp);
                let mut reader = BufReader::new(&mut tls);
                let mut line = String::new();
                while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
                    let result = match v["method"].as_str() {
                        Some("server.version") => serde_json::json!(["test", "1.4"]),
                        _ => serde_json::json!({"height": 7, "hex": "00".repeat(80)}),
                    };
                    let reply = serde_json::json!({"jsonrpc": "2.0", "id": v["id"], "result": result}).to_string() + "\n";
                    let tls = reader.get_mut();
                    if tls.write_all(reply.as_bytes()).and_then(|_| tls.flush()).is_err() {
                        break;
                    }
                    line.clear();
                }
            }
        });
        port
    }

    fn pin_of(cert: &[u8]) -> [u8; 32] {
        Sha256::digest(cert).into()
    }

    #[test]
    fn the_public_key_is_read_from_version_1_and_3_certificates() {
        for cert in [V3, V1, RSA] {
            let spki = spki_of(cert).expect("an SPKI");
            assert_eq!(spki[0], 0x30);
            webpki::RawPublicKeyEntity::try_from(&SubjectPublicKeyInfoDer::from(spki)).expect("a key webpki reads");
        }
        assert!(webpki::EndEntityCert::try_from(&CertificateDer::from(V1)).is_err(), "webpki refuses version 1, hence the DER walk");
        assert_eq!(spki_of(&V3[..40]), None, "a truncated certificate");
        assert_eq!(spki_of(b"\x02\x01\x00"), None);
    }

    #[test]
    fn a_pinned_certificate_is_accepted_and_any_other_refused() {
        for (cert, key, tls12) in [(V3, V3_KEY, false), (V1, V1_KEY, false), (RSA, RSA_KEY, true), (V1, V1_KEY, true)] {
            let port = server(cert, key, tls12);
            let url = format!("ssl://127.0.0.1:{port}");
            let c = connect(&url, pin_of(cert), None, Duration::from_secs(5)).unwrap_or_else(|e| panic!("tls12={tls12}: {e}"));
            let tip = c.raw_call("blockchain.headers.subscribe", vec![]).unwrap();
            assert_eq!(tip["height"], 7);
            drop(c);
            let other = connect(&url, pin_of(V3_KEY), None, Duration::from_secs(5)).err().expect("another pin is refused");
            assert!(other.contains("not the pinned one"), "{other}");
        }
    }

    #[test]
    fn a_probe_reads_the_pin_a_connection_then_accepts() {
        for (cert, key) in [(V1, V1_KEY), (V3, V3_KEY)] {
            let port = server(cert, key, false);
            let url = format!("ssl://127.0.0.1:{port}");
            let pin = certificate_sha256(&url, None, Duration::from_secs(5)).unwrap();
            assert_eq!(pin, pin_of(cert));
            connect(&url, pin, None, Duration::from_secs(5)).unwrap();
        }
        let port = server(V3, V1_KEY, false);
        assert!(certificate_sha256(&format!("ssl://127.0.0.1:{port}"), None, Duration::from_secs(5)).is_err(), "no pin from a server without the key");
    }

    #[test]
    fn a_certificate_without_its_key_is_refused() {
        // The pinned certificate served with another key: the handshake signature gives it away.
        for tls12 in [false, true] {
            let port = server(V3, V1_KEY, tls12);
            let e = connect(&format!("ssl://127.0.0.1:{port}"), pin_of(V3), None, Duration::from_secs(5)).err().expect("refused");
            assert!(e.to_lowercase().contains("signature"), "tls12={tls12}: {e}");
        }
    }
}
