//! Remote Core transport. No redirects or ambient proxies; credentials never appear in errors.
use crate::{
    node::NodeRpc,
    routes::{Isolation, Proxy, Route, Source},
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub struct RemoteRpc {
    client: reqwest::Client,
    url: String,
    rt: tokio::runtime::Handle,
    next: AtomicU64,
    creds: Option<zeroize::Zeroizing<(String, String)>>,
    stop: Option<Arc<AtomicBool>>,
}
impl RemoteRpc {
    pub fn new(
        src: &Source,
        proxy: Option<&Proxy>,
        iso: &Isolation,
        creds: Option<(String, String)>,
        rt: tokio::runtime::Handle,
    ) -> Result<Self, String> {
        if let Some(e) = &src.down {
            return Err(e.clone());
        }
        let mut b = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(crate::net::timeout_for(src))
            .user_agent("bitcoin-wallet");
        if let Some(pin) = src.pin {
            b = b.use_preconfigured_tls(crate::pin::client_config(pin)?);
        } else {
            b = b.tls_built_in_root_certs(true);
        }
        if matches!(src.route, Route::Tor | Route::Onion) {
            let p = proxy.ok_or("Tor proxy is not configured")?;
            let proxy = reqwest::Proxy::all(format!("socks5h://{}", p.addr()))
                .map_err(|_| "invalid proxy")?
                .basic_auth(&iso.user, &iso.pass);
            b = b.proxy(proxy);
        }
        let client = b.build().map_err(|_| "could not create RPC connection")?;
        Ok(Self {
            client,
            url: src.url.clone(),
            rt,
            next: AtomicU64::new(1),
            creds: creds.map(zeroize::Zeroizing::new),
            stop: None,
        })
    }
    /// Requests end, with an error, once `stop` is set: a closing wallet doesn't wait for them.
    pub fn until(mut self, stop: Arc<AtomicBool>) -> Self {
        self.stop = Some(stop);
        self
    }
    fn request(&self, body: Value) -> Result<Value, String> {
        let call = async {
            let mut req = self
                .client
                .post(&self.url)
                .header("Content-Type", "application/json")
                .body(body.to_string());
            if let Some(c) = &self.creds {
                req = req.basic_auth(&c.0, Some(&c.1));
            }
            let mut resp = req.send().await.map_err(|e| {
                if e.is_timeout() {
                    "RPC request timed out"
                } else {
                    "RPC connection failed (check address, TLS and proxy)"
                }
            })?;
            let status = resp.status();
            if !status.is_success() && status.as_u16() != 500 {
                return Err(format!("RPC HTTP {}", status.as_u16()));
            }
            // A maximum-sized raw Bitcoin block fits in 8 MB of hex. Leave room for mempool replies.
            const MAX: usize = 32 * 1024 * 1024;
            if resp.content_length().is_some_and(|n| n > MAX as u64) {
                return Err("RPC response exceeds 32 MiB".into());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = resp.chunk().await.map_err(|_| "incomplete RPC response")? {
                if bytes.len() + chunk.len() > MAX {
                    return Err("RPC response exceeds 32 MiB".into());
                }
                bytes.extend_from_slice(&chunk);
            }
            serde_json::from_slice(&bytes).map_err(|_| "RPC response is not JSON".into())
        };
        match &self.stop {
            Some(stop) => crate::net::block_on_until(&self.rt, stop, call)?,
            None => self.rt.block_on(call),
        }
    }
}
impl NodeRpc for RemoteRpc {
    fn remote(&self) -> bool {
        true
    }
    fn batch(&self, method: &str, params: &[Value]) -> Result<Vec<String>, String> {
        if params.is_empty() {
            return Ok(vec![]);
        }
        let first = self.next.fetch_add(params.len() as u64, Ordering::Relaxed);
        let calls: Vec<_> = params
            .iter()
            .enumerate()
            .map(|(i, p)| json!({"jsonrpc":"2.0","id":first+i as u64,"method":method,"params":p}))
            .collect();
        let response = self.request(Value::Array(calls))?;
        // Core and PublicNode support batches. An explicit batch refusal can use single calls.
        if response["error"]["code"] == -32600 {
            return params
                .iter()
                .map(|p| self.rpc(method, &p.to_string()))
                .collect();
        }
        let replies = response.as_array().ok_or("invalid RPC batch response")?;
        if replies.len() != params.len() {
            return Err("incomplete RPC batch response".into());
        }
        let mut ordered = vec![None; params.len()];
        for v in replies {
            let i = v["id"]
                .as_u64()
                .and_then(|id| id.checked_sub(first))
                .filter(|i| *i < params.len() as u64)
                .ok_or("RPC batch ID mismatch")? as usize;
            if ordered[i].is_some() || (v.get("result").is_none() && v["error"].is_null()) {
                return Err("invalid RPC batch envelope".into());
            }
            ordered[i] = Some(v.to_string());
        }
        ordered
            .into_iter()
            .map(|v| v.ok_or_else(|| "missing RPC batch result".into()))
            .collect()
    }
    fn rpc(&self, method: &str, params: &str) -> Result<String, String> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let params: Value = serde_json::from_str(params).map_err(|_| "invalid RPC parameters")?;
        let v = self.request(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        if v["id"] != id || (!v.get("result").is_some() && v["error"].is_null()) {
            return Err("invalid RPC response envelope".into());
        }
        Ok(v.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{resolve, Entry};
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    fn server(
        reply: impl Fn(Value, String) -> (u16, Value) + Send + 'static,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0; 4096];
            let (head, end, len) = loop {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8(bytes[..end].to_vec()).unwrap();
                    let len = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    break (head, end + 4, len);
                }
            };
            while bytes.len() < end + len {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
            }
            let request = serde_json::from_slice(&bytes[end..end + len]).unwrap();
            let (status, body) = reply(request, head);
            let body = body.to_string();
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        (url, task)
    }
    fn source(url: String) -> Source {
        resolve(
            &Entry {
                id: "rpc".into(),
                url,
                operator: "test".into(),
                route: Route::Direct,
                kind: Some("rpc".into()),
                credentials: false,
                cert_sha256: None,
                user_added: true,
            },
            None,
        )
        .unwrap()
    }
    #[test]
    fn batch_orders_responses_and_uses_basic_auth() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (url, task) = server(|v, head| {
            assert!(head.to_ascii_lowercase().contains(
                "authorization: basic dxnlcjpwYXNz"
                    .to_ascii_lowercase()
                    .as_str()
            ));
            let replies: Vec<_> = v
                .as_array()
                .unwrap()
                .iter()
                .rev()
                .map(|v| json!({"id":v["id"],"result":v["params"][0]}))
                .collect();
            (200, json!(replies))
        });
        let c = RemoteRpc::new(
            &source(url),
            None,
            &Isolation::fresh(),
            Some(("user".into(), "pass".into())),
            rt.handle().clone(),
        )
        .unwrap();
        let replies = c.batch("getblockhash", &[json!([1]), json!([2])]).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&replies[0]).unwrap()["result"],
            1
        );
        assert_eq!(
            serde_json::from_str::<Value>(&replies[1]).unwrap()["result"],
            2
        );
        task.join().unwrap();
    }
    #[test]
    fn rejects_duplicate_batch_ids_and_http_errors_without_echoing_body() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (url, task) = server(|v, _| {
            (
                200,
                json!([{"id":v[0]["id"],"result":1},{"id":v[0]["id"],"result":2}]),
            )
        });
        let c = RemoteRpc::new(
            &source(url),
            None,
            &Isolation::fresh(),
            None,
            rt.handle().clone(),
        )
        .unwrap();
        assert!(c
            .batch("getblockhash", &[json!([1]), json!([2])])
            .unwrap_err()
            .contains("envelope"));
        task.join().unwrap();
        let (url, task) = server(|_, _| (401, json!({"password":"should-not-appear"})));
        let c = RemoteRpc::new(
            &source(url),
            None,
            &Isolation::fresh(),
            None,
            rt.handle().clone(),
        )
        .unwrap();
        assert_eq!(
            c.rpc("getblockchaininfo", "[]").unwrap_err(),
            "RPC HTTP 401"
        );
        task.join().unwrap();
        let mut s = source("https://rpc.example".into());
        s.route = Route::Tor;
        assert!(RemoteRpc::new(&s, None, &Isolation::fresh(), None, rt.handle().clone()).is_err());
    }
}
