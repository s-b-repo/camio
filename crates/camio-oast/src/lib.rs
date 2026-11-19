//! `camio-oast` — a self-hosted out-of-band application security testing (OAST)
//! collector.
//!
//! This is Camio's local-first analog of Burp's Collaborator: a small HTTP
//! listener that records every inbound request and correlates it to an
//! **injection token** you planted in a payload. When a target performs a blind
//! callback — an SSRF fetch, a blind XXE, a log4shell-style lookup, a webhook —
//! to a URL carrying that token, the hit lands here and you can tie it back to
//! the exact test that caused it.
//!
//! Unlike a hosted collaborator this runs on infrastructure you control and
//! keeps the data local. The trade-off is honest: it only sees callbacks that
//! can actually reach the address you bind, so it suits internal engagements and
//! lab targets rather than arbitrary internet egress.
//!
//! The collector is transport-agnostic about *where* interactions are shown:
//! [`OastServer`] records into a [`Collector`] and optionally calls a hook, so a
//! CLI can log them live and a GUI can poll [`Collector::all`].

use camio_core::{Body, HeaderList};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_HEAD: usize = 32 * 1024;
const MAX_BODY: usize = 1024 * 1024;

/// One recorded out-of-band interaction.
#[derive(Debug, Clone)]
pub struct Interaction {
    /// Monotonic id assigned by the collector.
    pub id: u64,
    /// The correlation token parsed from the path or host, if any.
    pub token: Option<String>,
    pub method: String,
    /// The request target as received (path + query).
    pub target: String,
    /// The `Host` header value, if present.
    pub host: Option<String>,
    /// Peer address the callback came from.
    pub source: String,
    /// Unix epoch millis when the interaction was recorded.
    pub received_at_ms: i64,
    pub headers: HeaderList,
    pub body: Body,
}

/// Records interactions and mints/correlates tokens. Cheap to share via `Arc`.
pub struct Collector {
    base: String,
    items: Mutex<Vec<Interaction>>,
    next_id: AtomicU64,
    token_seed: AtomicU64,
}

impl Collector {
    /// `base` is the authority (`host:port`) callbacks will target, used to build
    /// callback URLs. It does not have to resolve publicly — it is whatever the
    /// target can reach the collector at.
    pub fn new(base: impl Into<String>) -> Arc<Self> {
        Arc::new(Collector {
            base: base.into(),
            items: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
            token_seed: AtomicU64::new(0),
        })
    }

    /// The configured callback authority (`host:port`).
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Mint a fresh, hard-to-guess correlation token.
    pub fn new_token(&self) -> String {
        let seed = self.token_seed.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut hasher = Sha256::new();
        hasher.update(nanos.to_le_bytes());
        hasher.update(seed.to_le_bytes());
        hasher.update(std::process::id().to_le_bytes());
        let digest = hasher.finalize();
        // 14 hex chars is plenty of entropy for correlation and keeps URLs short.
        digest.iter().take(7).map(|b| format!("{b:02x}")).collect()
    }

    /// A path-style callback URL: `http://<base>/<token>`. Works whenever the
    /// target can reach the bound address directly.
    pub fn callback_url(&self, token: &str) -> String {
        format!("http://{}/{token}", self.base)
    }

    /// A DNS-style callback URL: `http://<token>.<base>`. Useful when a wildcard
    /// hostname resolves to the collector (so the token survives host-only
    /// exfiltration, like a DNS lookup).
    pub fn dns_callback_url(&self, token: &str) -> String {
        format!("http://{token}.{}", self.base)
    }

    fn push(
        &self,
        method: String,
        target: String,
        host: Option<String>,
        source: String,
        headers: HeaderList,
        body: Body,
    ) -> Interaction {
        let token = extract_token(&target, host.as_deref());
        let interaction = Interaction {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            token,
            method,
            target,
            host,
            source,
            received_at_ms: now_ms(),
            headers,
            body,
        };
        self.items
            .lock()
            .expect("oast collector poisoned")
            .push(interaction.clone());
        interaction
    }

    /// All interactions recorded so far.
    pub fn all(&self) -> Vec<Interaction> {
        self.items.lock().expect("oast collector poisoned").clone()
    }

    /// Interactions whose token matches `token`.
    pub fn for_token(&self, token: &str) -> Vec<Interaction> {
        self.items
            .lock()
            .expect("oast collector poisoned")
            .iter()
            .filter(|i| i.token.as_deref() == Some(token))
            .cloned()
            .collect()
    }

    /// How many interactions have been recorded.
    pub fn len(&self) -> usize {
        self.items.lock().expect("oast collector poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

type Hook = Box<dyn Fn(&Interaction) + Send + Sync>;

/// A tiny HTTP server that records every request into a [`Collector`].
pub struct OastServer {
    collector: Arc<Collector>,
    on_hit: Option<Hook>,
}

impl OastServer {
    pub fn new(collector: Arc<Collector>) -> Self {
        OastServer {
            collector,
            on_hit: None,
        }
    }

    /// Register a callback run for each recorded interaction (e.g. a live log).
    pub fn on_interaction<F: Fn(&Interaction) + Send + Sync + 'static>(mut self, hook: F) -> Self {
        self.on_hit = Some(Box::new(hook));
        self
    }

    /// Bind and serve forever (blocking).
    pub fn serve(self, addr: impl ToSocketAddrs) -> io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        self.serve_with_listener(listener)
    }

    /// Serve on an already-bound listener (blocking).
    pub fn serve_with_listener(self, listener: TcpListener) -> io::Result<()> {
        let server = Arc::new(self);
        server.accept_loop(&listener, None);
        Ok(())
    }

    /// Spawn on a background thread; the handle stops it.
    pub fn spawn(self, listener: TcpListener) -> io::Result<OastHandle> {
        let local_addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        let server = Arc::new(self);
        let join = std::thread::Builder::new()
            .name("camio-oast".into())
            .spawn(move || server.accept_loop(&listener, Some(flag)))?;
        Ok(OastHandle {
            shutdown,
            local_addr,
            join: Some(join),
        })
    }

    fn accept_loop(self: &Arc<Self>, listener: &TcpListener, shutdown: Option<Arc<AtomicBool>>) {
        let polling = shutdown.is_some();
        if polling {
            let _ = listener.set_nonblocking(true);
        }
        loop {
            if let Some(flag) = &shutdown {
                if flag.load(Ordering::Acquire) {
                    break;
                }
            }
            match listener.accept() {
                Ok((stream, peer)) => {
                    let _ = stream.set_nonblocking(false);
                    let server = self.clone();
                    std::thread::spawn(move || server.handle(stream, peer));
                }
                Err(ref e) if polling && e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => {
                    if !polling {
                        continue;
                    }
                }
            }
        }
    }

    fn handle(self: &Arc<Self>, mut stream: TcpStream, peer: SocketAddr) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let Some((method, target, host, headers, body)) = read_request(&mut stream) else {
            return;
        };
        let interaction =
            self.collector
                .push(method, target, host, peer.ip().to_string(), headers, body);
        if let Some(hook) = &self.on_hit {
            hook(&interaction);
        }
        // A minimal, non-identifying 200 so the callback "succeeds".
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        );
        let _ = stream.flush();
    }
}

/// A handle to a running OAST server (from [`OastServer::spawn`]).
pub struct OastHandle {
    shutdown: Arc<AtomicBool>,
    local_addr: SocketAddr,
    join: Option<std::thread::JoinHandle<()>>,
}

impl OastHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn is_running(&self) -> bool {
        !self.shutdown.load(Ordering::Acquire)
    }
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
    pub fn stop_and_join(mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for OastHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

/// Extract a correlation token from the request: the first path segment, else
/// the leftmost host label (so `http://<token>.collector/` and
/// `http://collector/<token>` both correlate).
fn extract_token(target: &str, host: Option<&str>) -> Option<String> {
    let path = target.split('?').next().unwrap_or(target);
    if let Some(seg) = path.trim_start_matches('/').split('/').next() {
        if is_token(seg) {
            return Some(seg.to_ascii_lowercase());
        }
    }
    if let Some(h) = host {
        let hostname = h.split(':').next().unwrap_or(h);
        if let Some(label) = hostname.split('.').next() {
            if is_token(label) {
                return Some(label.to_ascii_lowercase());
            }
        }
    }
    None
}

/// A token is a run of hex-ish chars of a plausible length; this keeps random
/// scans and favicons from being misread as correlations.
fn is_token(s: &str) -> bool {
    let len = s.len();
    (8..=64).contains(&len) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Read one HTTP/1 request: method, target, Host, headers, and a
/// Content-Length body (bounded). `None` on malformed input or EOF.
fn read_request(
    stream: &mut TcpStream,
) -> Option<(String, String, Option<String>, HeaderList, Body)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
        match stream.read(&mut tmp) {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => return None,
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(&buf[..head_end]).ok()?.is_partial() {
        return None;
    }
    let method = req.method?.to_string();
    let target = req.path?.to_string();
    let mut hl = HeaderList::new();
    let mut host = None;
    let mut content_length = 0usize;
    for h in req.headers.iter() {
        let value = String::from_utf8_lossy(h.value).into_owned();
        if h.name.eq_ignore_ascii_case("host") {
            host = Some(value.clone());
        }
        if h.name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().unwrap_or(0);
        }
        hl.push(h.name, value);
    }

    let mut body = buf[head_end..].to_vec();
    let want = content_length.min(MAX_BODY);
    while body.len() < want {
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
        }
    }
    body.truncate(want);
    Some((method, target, host, hl, Body::from_bytes(body)))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpStream;

    #[test]
    fn tokens_are_opaque_and_unique() {
        let c = Collector::new("oast.local:8888");
        let a = c.new_token();
        let b = c.new_token();
        assert_ne!(a, b);
        assert!(is_token(&a), "token should look like a token: {a}");
        assert_eq!(c.callback_url(&a), format!("http://oast.local:8888/{a}"));
        assert_eq!(
            c.dns_callback_url(&a),
            format!("http://{a}.oast.local:8888")
        );
    }

    #[test]
    fn extracts_token_from_path_and_host() {
        let tok = "deadbeefcafe12";
        assert_eq!(extract_token(&format!("/{tok}/x"), None), Some(tok.into()));
        assert_eq!(
            extract_token("/", Some(&format!("{tok}.oast.local"))),
            Some(tok.into())
        );
        assert_eq!(extract_token("/favicon.ico", Some("host")), None);
    }

    #[test]
    fn records_and_correlates_a_live_callback() {
        let collector = Collector::new("127.0.0.1");
        let token = collector.new_token();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = OastServer::new(collector.clone()).spawn(listener).unwrap();

        // Simulate a target's blind callback carrying the token in the path.
        let mut s = TcpStream::connect(addr).unwrap();
        let req =
            format!("GET /{token}/leak?x=1 HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: victim\r\n\r\n");
        s.write_all(req.as_bytes()).unwrap();
        let mut resp = Vec::new();
        let _ = s.read_to_end(&mut resp);
        assert!(String::from_utf8_lossy(&resp).contains("200 OK"));

        // The interaction is recorded and correlates to the token.
        let hits = collector.for_token(&token);
        assert_eq!(hits.len(), 1, "all: {:?}", collector.all());
        assert_eq!(hits[0].method, "GET");
        assert_eq!(hits[0].target, format!("/{token}/leak?x=1"));
        assert_eq!(hits[0].headers.get("user-agent"), Some("victim"));
        handle.stop_and_join();
    }

    #[test]
    fn records_post_body() {
        let collector = Collector::new("127.0.0.1");
        let token = collector.new_token();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = OastServer::new(collector.clone()).spawn(listener).unwrap();

        let mut s = TcpStream::connect(addr).unwrap();
        let body = "stolen=data";
        let req = format!(
            "POST /{token} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut resp = Vec::new();
        let _ = s.read_to_end(&mut resp);

        let hits = collector.for_token(&token);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].body.as_text(), "stolen=data");
        handle.stop_and_join();
    }
}
