//! Connections on each source's route, and an Electrum wrapper that re-hashes transactions against
//! their txids, keeps Merkle proofs for the length check, and bounds address queries. A server
//! with a pinned certificate gets its own TLS connection (see `pin`).

use std::borrow::Borrow;
use std::collections::HashMap;
use std::future::Future;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use bdk_electrum::electrum_client;
use bdk_esplora::esplora_client;
use bitcoin::consensus::encode::deserialize;
use bitcoin::{Script, Transaction, Txid};
use electrum_client::{
    Batch, BroadcastPackageRes, ElectrumApi, EstimationMode, GetBalanceRes, GetHeadersRes, GetHistoryRes, GetMerkleRes, ListUnspentRes,
    MempoolInfoRes, Param, RawHeaderNotification, ScriptStatus, ServerFeaturesRes, TxidFromPosRes,
};

use electrum_client::raw_client::{ElectrumSslStream, RawClient};

use crate::routes::{Isolation, Proxy, Route, Source};

/// A sync asking about more addresses than this is refused: a server faking history would
/// otherwise walk the wallet's addresses without end.
pub const SCRIPT_LIMIT: usize = 20_000;

/// What a call cut short by a close answers.
pub const STOPPING: &str = "stopping";

pub fn timeout_for(src: &Source) -> Duration {
    if src.route == Route::Direct { Duration::from_secs(15) } else { Duration::from_secs(45) }
}

/// The open wallet's sockets. Closing cuts them, so a call blocked on one returns at once; a
/// socket connected after the cut is shut as it connects.
#[derive(Clone, Default)]
pub struct Cancel(Arc<Mutex<Held>>);

#[derive(Default)]
struct Held {
    cut: bool,
    sockets: Vec<Weak<TcpStream>>,
}

/// A connection's copy of its socket, for the cut; it goes with the connection.
struct Socket(#[allow(dead_code)] Arc<TcpStream>);

impl Cancel {
    fn hold(&self, tcp: &TcpStream) -> Result<Socket, String> {
        let copy = Arc::new(tcp.try_clone().map_err(|e| e.to_string())?);
        let mut h = self.0.lock().unwrap();
        if h.cut {
            let _ = tcp.shutdown(Shutdown::Both);
            return Err(STOPPING.into());
        }
        h.sockets.retain(|s| s.strong_count() > 0);
        h.sockets.push(Arc::downgrade(&copy));
        Ok(Socket(copy))
    }

    pub fn cut(&self) {
        let mut h = self.0.lock().unwrap();
        h.cut = true;
        for s in h.sockets.drain(..).filter_map(|s| s.upgrade()) {
            let _ = s.shutdown(Shutdown::Both);
        }
    }

    pub fn is_cut(&self) -> bool {
        self.0.lock().unwrap().cut
    }
}

/// `f` on a thread of its own, waited for until `stop` is set; then it finishes alone. A connect
/// through Tor can take its whole timeout, and a close doesn't wait for it.
pub fn off_thread<T: Send + 'static>(stop: &AtomicBool, f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new().name("bitcoin-connect".into()).spawn(move || {
        let _ = tx.send(f());
    }).map_err(|e| e.to_string())?;
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(r) => return r,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) if stop.load(Ordering::SeqCst) => return Err(STOPPING.into()),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err("the connection attempt ended".into()),
        }
    }
}

/// `f` on the runtime until `stop` is set; then it is dropped, which ends its requests.
pub fn block_on_until<F: Future>(rt: &tokio::runtime::Handle, stop: &AtomicBool, f: F) -> Result<F::Output, String> {
    rt.block_on(async {
        tokio::select! {
            r = f => Ok(r),
            _ = async { while !stop.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(50)).await } } => Err(STOPPING.to_string()),
        }
    })
}

/// An Electrum connection: TLS checked against the CAs or a pin, or plain text, holding a copy of
/// its socket for `Cancel`.
pub struct Conn {
    link: Link,
    _socket: Socket,
}

enum Link {
    Tls(RawClient<ElectrumSslStream>),
    Plain(RawClient<TcpStream>),
}

/// `ssl://host:port`, `tcp://host:port` or `host:port`: the host, the port and whether it is TLS.
fn electrum_url(url: &str) -> Result<(String, u16, bool), String> {
    let (tls, rest) = match url.split_once("://") {
        Some(("ssl", rest)) => (true, rest),
        Some(("tcp", rest)) => (false, rest),
        Some((scheme, _)) => return Err(format!("{scheme}:// is not an Electrum URL")),
        None => (false, url),
    };
    let (host, port) = rest.rsplit_once(':').filter(|(_, p)| !p.contains(']')).ok_or("the server's URL has no port")?;
    let port = port.parse::<u16>().map_err(|_| "the server's URL has a bad port".to_string())?;
    Ok((host.trim_matches(['[', ']']).to_string(), port, tls))
}

/// electrum-client negotiates only on clients it connects itself and reads 1.6's header replies
/// only then: a client connected here asks for 1.4.
pub(crate) fn negotiate<S: std::io::Read + std::io::Write>(c: &RawClient<S>, name: &str) -> Result<(), String> {
    let versions = vec!["1.4".to_string(), "1.4".to_string()];
    c.raw_call("server.version", vec![Param::String(name.into()), Param::StringVec(versions)]).map(|_| ()).map_err(|e| e.to_string())
}

/// An Electrum client on the source's route. A Tor route without a proxy is refused. Its socket
/// is held in `cancel`.
pub fn electrum(src: &Source, proxy: Option<&Proxy>, iso: &Isolation, cancel: &Cancel) -> Result<Conn, String> {
    if let Some(d) = &src.down {
        return Err(format!("{}: {d}", src.id));
    }
    let tor = matches!(src.route, Route::Tor | Route::Onion);
    let proxy = match tor {
        true => Some(proxy.ok_or_else(|| format!("{}: routed through Tor, and no proxy is set", src.id))?),
        false => None,
    };
    let fail = |e: String| format!("{}: {e}", src.id);
    let (host, port, tls) = electrum_url(&src.url).map_err(fail)?;
    if src.pin.is_some() && !tls {
        return Err(fail("a pinned certificate is for an ssl:// or https:// server".into()));
    }
    let tcp = crate::pin::tcp(&host, port, proxy.map(|p| (p, iso)), timeout_for(src)).map_err(fail)?;
    let socket = cancel.hold(&tcp).map_err(fail)?;
    let link = match src.pin {
        Some(pin) => Link::Tls(crate::pin::over(tcp, &host, pin).map_err(fail)?),
        None if tls => Link::Tls(RawClient::new_ssl_from_stream((host.as_str(), port), true, tcp, None).map_err(|e| fail(e.to_string()))?),
        None => {
            let c = RawClient::from(tcp);
            negotiate(&c, electrum_client::raw_client::CLIENT_NAME).map_err(fail)?;
            Link::Plain(c)
        }
    };
    Ok(Conn { link, _socket: socket })
}

macro_rules! either {
    ($self:ident, $c:ident => $call:expr) => {
        match &$self.link {
            Link::Tls($c) => $call,
            Link::Plain($c) => $call,
        }
    };
}

impl ElectrumApi for Conn {
    fn raw_call(&self, method_name: &str, params: impl IntoIterator<Item = Param>) -> Res<serde_json::Value> {
        either!(self, c => c.raw_call(method_name, params))
    }
    fn batch_call(&self, batch: &Batch) -> Res<Vec<serde_json::Value>> {
        either!(self, c => c.batch_call(batch))
    }
    fn block_headers_subscribe_raw(&self) -> Res<RawHeaderNotification> {
        either!(self, c => c.block_headers_subscribe_raw())
    }
    fn block_headers_pop_raw(&self) -> Res<Option<RawHeaderNotification>> {
        either!(self, c => c.block_headers_pop_raw())
    }
    fn block_header_raw(&self, height: usize) -> Res<Vec<u8>> {
        either!(self, c => c.block_header_raw(height))
    }
    fn block_headers(&self, start_height: usize, count: usize) -> Res<GetHeadersRes> {
        either!(self, c => c.block_headers(start_height, count))
    }
    fn estimate_fee(&self, number: usize, mode: Option<EstimationMode>) -> Res<f64> {
        either!(self, c => c.estimate_fee(number, mode))
    }
    fn relay_fee(&self) -> Res<f64> {
        either!(self, c => c.relay_fee())
    }
    fn script_subscribe(&self, script: &Script) -> Res<Option<ScriptStatus>> {
        either!(self, c => c.script_subscribe(script))
    }
    fn batch_script_subscribe<'s, I>(&self, scripts: I) -> Res<Vec<Option<ScriptStatus>>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        either!(self, c => c.batch_script_subscribe(scripts))
    }
    fn script_unsubscribe(&self, script: &Script) -> Res<bool> {
        either!(self, c => c.script_unsubscribe(script))
    }
    fn script_pop(&self, script: &Script) -> Res<Option<ScriptStatus>> {
        either!(self, c => c.script_pop(script))
    }
    fn script_get_balance(&self, script: &Script) -> Res<GetBalanceRes> {
        either!(self, c => c.script_get_balance(script))
    }
    fn batch_script_get_balance<'s, I>(&self, scripts: I) -> Res<Vec<GetBalanceRes>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        either!(self, c => c.batch_script_get_balance(scripts))
    }
    fn script_get_history(&self, script: &Script) -> Res<Vec<GetHistoryRes>> {
        either!(self, c => c.script_get_history(script))
    }
    fn batch_script_get_history<'s, I>(&self, scripts: I) -> Res<Vec<Vec<GetHistoryRes>>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        either!(self, c => c.batch_script_get_history(scripts))
    }
    fn script_list_unspent(&self, script: &Script) -> Res<Vec<ListUnspentRes>> {
        either!(self, c => c.script_list_unspent(script))
    }
    fn batch_script_list_unspent<'s, I>(&self, scripts: I) -> Res<Vec<Vec<ListUnspentRes>>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        either!(self, c => c.batch_script_list_unspent(scripts))
    }
    fn transaction_get_raw(&self, txid: &Txid) -> Res<Vec<u8>> {
        either!(self, c => c.transaction_get_raw(txid))
    }
    fn batch_transaction_get_raw<'t, I>(&self, txids: I) -> Res<Vec<Vec<u8>>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'t Txid>,
    {
        either!(self, c => c.batch_transaction_get_raw(txids))
    }
    fn batch_block_header_raw<I>(&self, heights: I) -> Res<Vec<Vec<u8>>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<u32>,
    {
        either!(self, c => c.batch_block_header_raw(heights))
    }
    fn batch_estimate_fee<I>(&self, numbers: I) -> Res<Vec<f64>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<usize>,
    {
        either!(self, c => c.batch_estimate_fee(numbers))
    }
    fn transaction_broadcast_raw(&self, raw_tx: &[u8]) -> Res<Txid> {
        either!(self, c => c.transaction_broadcast_raw(raw_tx))
    }
    fn transaction_broadcast_package_raw<T: AsRef<[u8]>>(&self, raw_txs: &[T]) -> Res<BroadcastPackageRes> {
        either!(self, c => c.transaction_broadcast_package_raw(raw_txs))
    }
    fn transaction_get_merkle(&self, txid: &Txid, height: usize) -> Res<GetMerkleRes> {
        either!(self, c => c.transaction_get_merkle(txid, height))
    }
    fn batch_transaction_get_merkle<I>(&self, txids_and_heights: I) -> Res<Vec<GetMerkleRes>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<(Txid, usize)>,
    {
        either!(self, c => c.batch_transaction_get_merkle(txids_and_heights))
    }
    fn txid_from_pos(&self, height: usize, tx_pos: usize) -> Res<Txid> {
        either!(self, c => c.txid_from_pos(height, tx_pos))
    }
    fn txid_from_pos_with_merkle(&self, height: usize, tx_pos: usize) -> Res<TxidFromPosRes> {
        either!(self, c => c.txid_from_pos_with_merkle(height, tx_pos))
    }
    fn server_features(&self) -> Res<ServerFeaturesRes> {
        either!(self, c => c.server_features())
    }
    fn mempool_get_info(&self) -> Res<MempoolInfoRes> {
        either!(self, c => c.mempool_get_info())
    }
    fn ping(&self) -> Res<()> {
        either!(self, c => c.ping())
    }
    fn calls_made(&self) -> Res<usize> {
        either!(self, c => c.calls_made())
    }
}

/// An Esplora client on the source's route, with a generic user agent and, where the source
/// needs them, the credentials the node module holds.
pub fn esplora(src: &Source, proxy: Option<&Proxy>, iso: &Isolation, credentials: Option<&(String, String)>) -> Result<esplora_client::AsyncClient, String> {
    if let Some(d) = &src.down {
        return Err(format!("{}: {d}", src.id));
    }
    let mut b = esplora_client::Builder::new(src.url.trim_end_matches('/')).timeout(timeout_for(src).as_secs());
    if let Some((user, pass)) = credentials {
        use base64::Engine;
        let token = zeroize::Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}")));
        b = b.header("Authorization", &format!("Basic {}", token.as_str()));
    }
    let mut socks = None;
    if matches!(src.route, Route::Tor | Route::Onion) {
        let p = proxy.ok_or_else(|| format!("{}: routed through Tor, and no proxy is set", src.id))?;
        socks = Some(format!("socks5h://{}:{}@{}", iso.user, iso.pass, p.addr()));
    }
    let Some(pin) = src.pin else {
        if let Some(s) = &socks {
            b = b.proxy(s);
        }
        return b.header("User-Agent", "bitcoin-wallet").build_async().map_err(|e| format!("{}: {e}", src.id));
    };
    // Pinned: esplora-client over a reqwest client of ours, whose TLS accepts only the pin.
    let fail = |e: String| format!("{}: {e}", src.id);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::USER_AGENT, reqwest::header::HeaderValue::from_static("bitcoin-wallet"));
    for (k, v) in &b.headers {
        let name = reqwest::header::HeaderName::from_bytes(k.to_ascii_lowercase().as_bytes()).map_err(|e| fail(e.to_string()))?;
        let mut value = reqwest::header::HeaderValue::from_str(v).map_err(|e| fail(e.to_string()))?;
        value.set_sensitive(true);
        headers.insert(name, value);
    }
    let mut c = reqwest::Client::builder().use_preconfigured_tls(crate::pin::client_config(pin).map_err(fail)?).timeout(timeout_for(src)).default_headers(headers);
    if let Some(s) = &socks {
        c = c.proxy(reqwest::Proxy::all(s.as_str()).map_err(|e| fail(e.to_string()))?);
    }
    let client = c.build().map_err(|e| fail(e.to_string()))?;
    Ok(esplora_client::AsyncClient::from_client(src.url.trim_end_matches('/').to_string(), client))
}

/// An error as status and the log show it: script hashes and txids in a failed request's URL
/// would name the wallet's addresses and payments, so runs of 40 or more hex digits are elided.
pub fn redact(e: &str) -> String {
    let mut out = String::with_capacity(e.len());
    let mut run = String::new();
    for c in e.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_hexdigit() {
            run.push(c);
            continue;
        }
        out.push_str(if run.len() >= 40 { "…" } else { &run });
        run.clear();
        out.push(c);
    }
    out.pop();
    out
}

#[derive(Default, Debug)]
pub struct Record {
    /// Requested txid → the txid its bytes hash to, when they differ.
    pub mismatched: HashMap<Txid, Txid>,
    pub proofs: HashMap<(Txid, usize), GetMerkleRes>,
    pub scripts_asked: usize,
}

/// Wraps an Electrum client for BDK; see the module comment.
pub struct Checked<E> {
    pub inner: E,
    pub record: Mutex<Record>,
}

impl<E> Checked<E> {
    pub fn new(inner: E) -> Self {
        Self { inner, record: Mutex::default() }
    }

    pub fn take(&self) -> Record {
        std::mem::take(&mut *self.record.lock().unwrap())
    }

    fn check_tx(&self, asked: Txid, raw: &[u8]) {
        let got = deserialize::<Transaction>(raw).map(|t| t.compute_txid());
        let got = match got {
            Ok(t) if t == asked => return,
            Ok(t) => t,
            // Bytes that don't even parse: recorded against themselves so the anchor is dropped too.
            Err(_) => asked,
        };
        self.record.lock().unwrap().mismatched.insert(asked, got);
    }

    fn count_scripts(&self, n: usize) -> Result<(), electrum_client::Error> {
        let mut r = self.record.lock().unwrap();
        r.scripts_asked += n;
        if r.scripts_asked > SCRIPT_LIMIT {
            return Err(electrum_client::Error::Message(format!("asked about more than {SCRIPT_LIMIT} addresses in one sync")));
        }
        Ok(())
    }
}

type Res<T> = Result<T, electrum_client::Error>;

impl<E: ElectrumApi> ElectrumApi for Checked<E> {
    fn raw_call(&self, method_name: &str, params: impl IntoIterator<Item = Param>) -> Res<serde_json::Value> {
        self.inner.raw_call(method_name, params)
    }
    fn batch_call(&self, batch: &Batch) -> Res<Vec<serde_json::Value>> {
        self.inner.batch_call(batch)
    }
    fn block_headers_subscribe_raw(&self) -> Res<RawHeaderNotification> {
        self.inner.block_headers_subscribe_raw()
    }
    fn block_headers_pop_raw(&self) -> Res<Option<RawHeaderNotification>> {
        self.inner.block_headers_pop_raw()
    }
    fn block_header_raw(&self, height: usize) -> Res<Vec<u8>> {
        self.inner.block_header_raw(height)
    }
    fn block_headers(&self, start_height: usize, count: usize) -> Res<GetHeadersRes> {
        self.inner.block_headers(start_height, count)
    }
    fn estimate_fee(&self, number: usize, mode: Option<EstimationMode>) -> Res<f64> {
        self.inner.estimate_fee(number, mode)
    }
    fn relay_fee(&self) -> Res<f64> {
        self.inner.relay_fee()
    }
    fn script_subscribe(&self, script: &Script) -> Res<Option<ScriptStatus>> {
        self.inner.script_subscribe(script)
    }
    fn batch_script_subscribe<'s, I>(&self, scripts: I) -> Res<Vec<Option<ScriptStatus>>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        self.inner.batch_script_subscribe(scripts)
    }
    fn script_unsubscribe(&self, script: &Script) -> Res<bool> {
        self.inner.script_unsubscribe(script)
    }
    fn script_pop(&self, script: &Script) -> Res<Option<ScriptStatus>> {
        self.inner.script_pop(script)
    }
    fn script_get_balance(&self, script: &Script) -> Res<GetBalanceRes> {
        self.inner.script_get_balance(script)
    }
    fn batch_script_get_balance<'s, I>(&self, scripts: I) -> Res<Vec<GetBalanceRes>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        self.inner.batch_script_get_balance(scripts)
    }
    fn script_get_history(&self, script: &Script) -> Res<Vec<GetHistoryRes>> {
        self.count_scripts(1)?;
        self.inner.script_get_history(script)
    }
    fn batch_script_get_history<'s, I>(&self, scripts: I) -> Res<Vec<Vec<GetHistoryRes>>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        self.count_scripts(scripts.clone().into_iter().count())?;
        self.inner.batch_script_get_history(scripts)
    }
    fn script_list_unspent(&self, script: &Script) -> Res<Vec<ListUnspentRes>> {
        self.inner.script_list_unspent(script)
    }
    fn batch_script_list_unspent<'s, I>(&self, scripts: I) -> Res<Vec<Vec<ListUnspentRes>>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        self.inner.batch_script_list_unspent(scripts)
    }
    fn transaction_get_raw(&self, txid: &Txid) -> Res<Vec<u8>> {
        let raw = self.inner.transaction_get_raw(txid)?;
        self.check_tx(*txid, &raw);
        Ok(raw)
    }
    fn batch_transaction_get_raw<'t, I>(&self, txids: I) -> Res<Vec<Vec<u8>>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'t Txid>,
    {
        let asked: Vec<Txid> = txids.clone().into_iter().map(|t| **t.borrow()).collect();
        let raws = self.inner.batch_transaction_get_raw(txids)?;
        for (t, raw) in asked.iter().zip(&raws) {
            self.check_tx(*t, raw);
        }
        Ok(raws)
    }
    fn batch_block_header_raw<I>(&self, heights: I) -> Res<Vec<Vec<u8>>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<u32>,
    {
        self.inner.batch_block_header_raw(heights)
    }
    fn batch_estimate_fee<I>(&self, numbers: I) -> Res<Vec<f64>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<usize>,
    {
        self.inner.batch_estimate_fee(numbers)
    }
    fn transaction_broadcast_raw(&self, raw_tx: &[u8]) -> Res<Txid> {
        self.inner.transaction_broadcast_raw(raw_tx)
    }
    fn transaction_broadcast_package_raw<T: AsRef<[u8]>>(&self, raw_txs: &[T]) -> Res<BroadcastPackageRes> {
        self.inner.transaction_broadcast_package_raw(raw_txs)
    }
    fn transaction_get_merkle(&self, txid: &Txid, height: usize) -> Res<GetMerkleRes> {
        let r = self.inner.transaction_get_merkle(txid, height)?;
        self.record.lock().unwrap().proofs.insert((*txid, height), r.clone());
        Ok(r)
    }
    fn batch_transaction_get_merkle<I>(&self, txids_and_heights: I) -> Res<Vec<GetMerkleRes>>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<(Txid, usize)>,
    {
        let asked: Vec<(Txid, usize)> = txids_and_heights.clone().into_iter().map(|p| *p.borrow()).collect();
        let res = self.inner.batch_transaction_get_merkle(txids_and_heights)?;
        let mut r = self.record.lock().unwrap();
        for (k, proof) in asked.into_iter().zip(&res) {
            r.proofs.insert(k, proof.clone());
        }
        Ok(res)
    }
    fn txid_from_pos(&self, height: usize, tx_pos: usize) -> Res<Txid> {
        self.inner.txid_from_pos(height, tx_pos)
    }
    fn txid_from_pos_with_merkle(&self, height: usize, tx_pos: usize) -> Res<TxidFromPosRes> {
        self.inner.txid_from_pos_with_merkle(height, tx_pos)
    }
    fn server_features(&self) -> Res<ServerFeaturesRes> {
        self.inner.server_features()
    }
    fn mempool_get_info(&self) -> Res<MempoolInfoRes> {
        self.inner.mempool_get_info()
    }
    fn ping(&self) -> Res<()> {
        self.inner.ping()
    }
    fn calls_made(&self) -> Res<usize> {
        self.inner.calls_made()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{Kind, Route};

    #[test]
    fn errors_name_no_script_hash_or_txid() {
        let e = "esplora-0: Reqwest(reqwest::Error { url: \"https://h:1/scripthash/90954fa8865a517697fd98bc4248654082a383c1ed6722c1dadeb803b13dd571/txs\" })";
        assert_eq!(redact(e), "esplora-0: Reqwest(reqwest::Error { url: \"https://h:1/scripthash/…/txs\" })");
        assert_eq!(redact("timed out after 15 s at deadbeef"), "timed out after 15 s at deadbeef", "short hex stays");
    }

    fn src(url: &str, route: Route, down: Option<&str>) -> Source {
        Source { id: "s".into(), url: url.into(), operator: "op".into(), route, kind: Kind::Electrum, down: down.map(str::to_string), credentials: false, pin: None, encrypted: true }
    }

    #[test]
    fn tor_routes_never_go_direct() {
        let iso = Isolation::fresh();
        let e = electrum(&src("ssl://electrum.example:50002", Route::Tor, None), None, &iso, &Cancel::default()).err().unwrap();
        assert!(e.contains("no proxy"), "{e}");
        let e = esplora(&src("https://esplora.example/api", Route::Tor, None), None, &iso, None).err().unwrap();
        assert!(e.contains("no proxy"), "{e}");
        let e = electrum(&src("tcp://x:1", Route::Direct, Some("down for a reason")), None, &iso, &Cancel::default()).err().unwrap();
        assert!(e.contains("down for a reason"));
    }

    /// An Electrum server that answers server.version and then nothing; each connection's end
    /// is reported on `ended`.
    fn mute_server(ended: std::sync::mpsc::Sender<()>) -> u16 {
        use std::io::{BufRead, BufReader, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let ended = ended.clone();
                std::thread::spawn(move || {
                    let mut w = c.try_clone().unwrap();
                    for line in BufReader::new(c).lines().map_while(Result::ok) {
                        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
                        if v["method"] == "server.version" {
                            let _ = w.write_all(format!("{}\n", serde_json::json!({"jsonrpc": "2.0", "id": v["id"], "result": ["mute", "1.4"]})).as_bytes());
                        }
                    }
                    let _ = ended.send(());
                });
            }
        });
        port
    }

    #[test]
    fn a_cut_ends_a_call_blocked_on_a_server_and_refuses_new_ones() {
        let (ended, gone) = std::sync::mpsc::channel();
        let s = src(&format!("tcp://127.0.0.1:{}", mute_server(ended)), Route::Direct, None);
        let cancel = Cancel::default();
        let c = electrum(&s, None, &Isolation::fresh(), &cancel).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let t = std::time::Instant::now();
            let r = c.block_headers(0, 2016);
            tx.send((r.is_err(), t.elapsed())).unwrap();
        });
        std::thread::sleep(Duration::from_millis(300));
        assert!(rx.try_recv().is_err(), "the server never answers");
        cancel.cut();
        let (failed, took) = rx.recv_timeout(Duration::from_secs(5)).expect("the call returned");
        assert!(failed && took < Duration::from_secs(2), "{took:?}");
        gone.recv_timeout(Duration::from_secs(5)).expect("the server saw the connection end");
        let e = electrum(&s, None, &Isolation::fresh(), &cancel).err().unwrap();
        assert!(e.contains(STOPPING), "{e}");
        gone.recv_timeout(Duration::from_secs(5)).expect("a connection after the cut is shut at once");
    }

    #[test]
    fn a_dropped_connection_takes_its_copy_of_the_socket_along() {
        let (ended, gone) = std::sync::mpsc::channel();
        let s = src(&format!("tcp://127.0.0.1:{}", mute_server(ended)), Route::Direct, None);
        let cancel = Cancel::default();
        drop(electrum(&s, None, &Isolation::fresh(), &cancel).unwrap());
        gone.recv_timeout(Duration::from_secs(5)).expect("the server saw the connection end");
        assert!(cancel.0.lock().unwrap().sockets.iter().all(|w| w.strong_count() == 0));
    }

    #[test]
    fn waits_end_when_the_wallet_closes() {
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            s2.store(true, Ordering::SeqCst);
        });
        let t = std::time::Instant::now();
        let r: Result<(), String> = off_thread(&stop, || {
            std::thread::sleep(Duration::from_secs(10));
            Ok(())
        });
        assert_eq!(r, Err(STOPPING.to_string()));
        assert!(t.elapsed() < Duration::from_secs(2));
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        let t = std::time::Instant::now();
        assert_eq!(block_on_until(rt.handle(), &stop, async { tokio::time::sleep(Duration::from_secs(10)).await }), Err(STOPPING.to_string()));
        assert!(t.elapsed() < Duration::from_secs(2));
        assert_eq!(block_on_until(rt.handle(), &AtomicBool::new(false), async { 7 }), Ok(7));
    }

    #[test]
    fn electrum_urls() {
        assert_eq!(electrum_url("ssl://h.example:50002"), Ok(("h.example".into(), 50002, true)));
        assert_eq!(electrum_url("tcp://127.0.0.1:60601"), Ok(("127.0.0.1".into(), 60601, false)));
        assert_eq!(electrum_url("[::1]:50001"), Ok(("::1".into(), 50001, false)));
        assert!(electrum_url("ssl://h.example").is_err());
        assert!(electrum_url("https://h.example:443").is_err());
    }

    #[test]
    fn a_dead_proxy_fails_without_a_direct_fallback() {
        // Port 9 on loopback refuses: the connection must fail rather than skip the proxy.
        let p = Proxy::parse("socks5h://127.0.0.1:9").unwrap();
        let r = electrum(&src("ssl://electrum.example:50002", Route::Tor, None), Some(&p), &Isolation::fresh(), &Cancel::default());
        assert!(r.is_err());
    }
}
