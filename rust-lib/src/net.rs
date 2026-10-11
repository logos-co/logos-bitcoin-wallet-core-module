//! Connections on each source's route, and an Electrum wrapper that re-hashes transactions against
//! their txids, keeps Merkle proofs for the length check, and bounds address queries. A server
//! with a pinned certificate gets its own TLS connection (see `pin`).

use std::borrow::Borrow;
use std::collections::HashMap;
use std::sync::Mutex;
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

pub fn timeout_for(src: &Source) -> Duration {
    if src.route == Route::Direct { Duration::from_secs(15) } else { Duration::from_secs(45) }
}

/// An Electrum connection: electrum-client's own, checked against the CAs, or ours with a pin.
pub enum Conn {
    Std(electrum_client::Client),
    Pinned(RawClient<ElectrumSslStream>),
}

/// An Electrum client on the source's route. A Tor route without a proxy is refused.
pub fn electrum(src: &Source, proxy: Option<&Proxy>, iso: &Isolation) -> Result<Conn, String> {
    if let Some(d) = &src.down {
        return Err(format!("{}: {d}", src.id));
    }
    let tor = matches!(src.route, Route::Tor | Route::Onion);
    let proxy = match tor {
        true => Some(proxy.ok_or_else(|| format!("{}: routed through Tor, and no proxy is set", src.id))?),
        false => None,
    };
    if let Some(pin) = src.pin {
        return crate::pin::connect(&src.url, pin, proxy.map(|p| (p, iso)), timeout_for(src)).map(Conn::Pinned).map_err(|e| format!("{}: {e}", src.id));
    }
    let mut b = electrum_client::ConfigBuilder::new().timeout(Some(timeout_for(src))).retry(0).validate_domain(true);
    if let Some(p) = proxy {
        b = b.socks5(Some(electrum_client::Socks5Config::with_credentials(p.addr(), iso.user.clone(), iso.pass.clone())));
    }
    electrum_client::Client::from_config(&src.url, b.build()).map(Conn::Std).map_err(|e| format!("{}: {e}", src.id))
}

macro_rules! either {
    ($self:ident, $c:ident => $call:expr) => {
        match $self {
            Conn::Std($c) => $call,
            Conn::Pinned($c) => $call,
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
        let e = electrum(&src("ssl://electrum.example:50002", Route::Tor, None), None, &iso).err().unwrap();
        assert!(e.contains("no proxy"), "{e}");
        let e = esplora(&src("https://esplora.example/api", Route::Tor, None), None, &iso, None).err().unwrap();
        assert!(e.contains("no proxy"), "{e}");
        let e = electrum(&src("tcp://x:1", Route::Direct, Some("down for a reason")), None, &iso).err().unwrap();
        assert!(e.contains("down for a reason"));
    }

    #[test]
    fn a_dead_proxy_fails_without_a_direct_fallback() {
        // Port 9 on loopback refuses: the connection must fail rather than skip the proxy.
        let p = Proxy::parse("socks5h://127.0.0.1:9").unwrap();
        let r = electrum(&src("ssl://electrum.example:50002", Route::Tor, None), Some(&p), &Isolation::fresh());
        assert!(r.is_err());
    }
}
