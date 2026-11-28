//! Minimal, bounded HTTP/1.x wire reader/writer for the intercepting proxy.
//!
//! This is deliberately *not* a general HTTP stack: it reads one client request
//! at a time off a blocking stream (plain TCP or a terminated-TLS stream),
//! enforces hard size limits so a hostile client cannot exhaust memory, and
//! writes a response back with hop-by-hop and content-coding headers stripped
//! (the upstream engine already decoded the body, plan §6.1). Header order and
//! casing are preserved on the way in so the captured [`HttpRequest`] matches
//! what the client actually sent.

use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion};
use std::io::{self, Read, Write};

/// Default cap on request header bytes (request line + headers). 64 KiB is well
/// above any real browser request and stops an unbounded header flood.
pub const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;

/// Default cap on a single request body. 64 MiB covers uploads a tester would
/// reasonably replay while bounding memory per connection.
pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

const MAX_HEADERS: usize = 256;

/// A request line + headers read from the wire, before the body.
#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: String,
    /// The request-target exactly as sent (absolute-form for a plain proxy
    /// request, origin-form after a CONNECT tunnel, or `host:port` for CONNECT).
    pub target: String,
    pub version: HttpVersion,
    pub headers: HeaderList,
}

impl RequestHead {
    /// First value of a header, matched case-insensitively.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }

    /// How the message body is framed, per RFC 9112 §6.
    fn body_mode(&self) -> BodyMode {
        if let Some(te) = self.header("transfer-encoding") {
            if te
                .to_ascii_lowercase()
                .split(',')
                .any(|t| t.trim() == "chunked")
            {
                return BodyMode::Chunked;
            }
        }
        if let Some(cl) = self.header("content-length") {
            if let Ok(n) = cl.trim().parse::<usize>() {
                return BodyMode::Length(n);
            }
        }
        BodyMode::None
    }
}

enum BodyMode {
    None,
    Length(usize),
    Chunked,
}

/// A bounded buffered reader that keeps any bytes read past the current message
/// available, so a CONNECT tunnel can hand leftover handshake bytes to the next
/// stage without losing them.
pub struct Conn<S: Read + Write> {
    inner: S,
    buf: Vec<u8>,
    start: usize,
    filled: usize,
}

impl<S: Read + Write> Conn<S> {
    pub fn new(inner: S) -> Self {
        Conn {
            inner,
            buf: vec![0u8; 8192],
            start: 0,
            filled: 0,
        }
    }

    /// Mutable access to the underlying stream, for writing responses.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// The bytes already buffered (for preface detection before a full read).
    pub fn peek(&self) -> &[u8] {
        self.available()
    }

    /// Read once so the first bytes of the connection are available to
    /// [`Conn::peek`] without consuming a message.
    pub fn prime(&mut self) -> std::io::Result<()> {
        if self.available().is_empty() {
            self.fill()?;
        }
        Ok(())
    }

    /// Consume this reader, returning the stream and any bytes already buffered
    /// past the last consumed message (needed for a blind CONNECT relay).
    pub fn into_parts(self) -> (S, Vec<u8>) {
        let leftover = self.buf[self.start..self.filled].to_vec();
        (self.inner, leftover)
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.start..self.filled]
    }

    fn consume(&mut self, n: usize) {
        self.start += n;
        debug_assert!(self.start <= self.filled);
    }

    /// Compact consumed bytes out, grow if full, then read more from the stream.
    fn fill(&mut self) -> io::Result<usize> {
        if self.start > 0 {
            self.buf.copy_within(self.start..self.filled, 0);
            self.filled -= self.start;
            self.start = 0;
        }
        if self.filled == self.buf.len() {
            let new_len = (self.buf.len() * 2).max(16 * 1024);
            self.buf.resize(new_len, 0);
        }
        let n = self.inner.read(&mut self.buf[self.filled..])?;
        self.filled += n;
        Ok(n)
    }

    /// Read a full request (head + framed body). Returns `Ok(None)` on a clean
    /// EOF before any byte (the client closed an idle keep-alive connection).
    pub fn read_request(
        &mut self,
        max_header_bytes: usize,
        max_body_bytes: usize,
    ) -> io::Result<Option<(RequestHead, Body)>> {
        let head_bytes = match self.read_head(max_header_bytes)? {
            Some(b) => b,
            None => return Ok(None),
        };
        let head = parse_head(&head_bytes)?;
        let body = match head.body_mode() {
            BodyMode::None => Body::empty(),
            BodyMode::Length(n) => {
                if n > max_body_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request body exceeds limit",
                    ));
                }
                Body::from_bytes(self.read_exact_n(n)?)
            }
            BodyMode::Chunked => Body::from_bytes(self.read_chunked(max_body_bytes)?),
        };
        Ok(Some((head, body)))
    }

    /// Read up to the `\r\n\r\n` header terminator. `Ok(None)` on clean EOF.
    fn read_head(&mut self, max: usize) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(idx) = find_subslice(self.available(), b"\r\n\r\n") {
                let end = idx + 4;
                if end > max {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request header exceeds limit",
                    ));
                }
                let head = self.available()[..end].to_vec();
                self.consume(end);
                return Ok(Some(head));
            }
            if self.available().len() > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request header exceeds limit",
                ));
            }
            let n = self.fill()?;
            if n == 0 {
                if self.available().is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed mid-header",
                ));
            }
        }
    }

    fn read_exact_n(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n.min(1 << 20));
        while out.len() < n {
            if self.available().is_empty() {
                let got = self.fill()?;
                if got == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed mid-body",
                    ));
                }
            }
            let want = n - out.len();
            let take = want.min(self.available().len());
            out.extend_from_slice(&self.available()[..take]);
            self.consume(take);
        }
        Ok(out)
    }

    fn read_chunked(&mut self, max: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let line = self.read_crlf_line(64)?;
            let size_str = line.trim();
            // A chunk-size may carry extensions after ';'.
            let hex = size_str.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(hex, 16)
                // `ParseIntError` for a hex chunk size only means "not a
                // number"; the replacement says which field was wrong.
                // audit-allow: B7
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                // Consume trailing headers up to the final blank line.
                loop {
                    let t = self.read_crlf_line(8 * 1024)?;
                    if t.is_empty() {
                        break;
                    }
                }
                break;
            }
            if out.len() + size > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "chunked body exceeds limit",
                ));
            }
            let chunk = self.read_exact_n(size)?;
            out.extend_from_slice(&chunk);
            // Each chunk is followed by CRLF.
            let _ = self.read_crlf_line(2)?;
        }
        Ok(out)
    }

    /// Read a single CRLF-terminated line (without the CRLF), bounded by `max`.
    fn read_crlf_line(&mut self, max: usize) -> io::Result<String> {
        loop {
            if let Some(idx) = find_subslice(self.available(), b"\r\n") {
                let line = self.available()[..idx].to_vec();
                self.consume(idx + 2);
                return String::from_utf8(line)
                    // The `Utf8Error` only carries byte offsets; the message
                    // states the framing rule that was violated.
                    // audit-allow: B7
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 line"));
            }
            if self.available().len() > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "line exceeds limit",
                ));
            }
            let n = self.fill()?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed mid-line",
                ));
            }
        }
    }
}

/// Parse a raw head block (request line + headers + terminator) with httparse.
fn parse_head(bytes: &[u8]) -> io::Result<RequestHead> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    let parsed = req
        .parse(bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad request: {e}")))?;
    if parsed.is_partial() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete request head",
        ));
    }
    let method = req
        .method
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?
        .to_string();
    let target = req
        .path
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request target"))?
        .to_string();
    let version = match req.version {
        Some(0) => HttpVersion::Http10,
        _ => HttpVersion::Http11,
    };
    let mut hl = HeaderList::new();
    for h in req.headers.iter() {
        hl.push(h.name, String::from_utf8_lossy(h.value).into_owned());
    }
    Ok(RequestHead {
        method,
        target,
        version,
        headers: hl,
    })
}

/// Write an HTTP/1.1 response to the client. Hop-by-hop headers and content
/// codings are dropped (the upstream body is already decoded) and an accurate
/// `Content-Length` plus the chosen `Connection` disposition are written.
pub fn write_response<W: Write>(
    w: &mut W,
    resp: &HttpResponse,
    keep_alive: bool,
) -> io::Result<()> {
    let mut head = String::with_capacity(256);
    let reason = resp
        .reason
        .as_deref()
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| reason_phrase(resp.status));
    // `push_str(&format!(…))`: building a String cannot fail, so no result is
    // produced to be ignored.
    head.push_str(&format!("HTTP/1.1 {} {}\r\n", resp.status, reason));
    for h in resp.headers.iter() {
        if is_dropped_response_header(&h.name) {
            continue;
        }
        head.push_str(&format!("{}: {}\r\n", h.name, h.value));
    }
    head.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    head.push_str(&format!(
        "Connection: {}\r\n",
        if keep_alive { "keep-alive" } else { "close" }
    ));
    head.push_str("\r\n");
    w.write_all(head.as_bytes())?;
    w.write_all(resp.body.as_bytes())?;
    w.flush()
}

/// Build an absolute request URL from a request head and the tunnel context.
///
/// `connect_authority` is `Some("host:port")` when this request arrived inside a
/// CONNECT tunnel (so the target is origin-form and the scheme is https);
/// `None` for a plain forward-proxy request whose target is already absolute.
pub fn absolute_url(head: &RequestHead, connect_authority: Option<&str>) -> Option<String> {
    if let Some(authority) = connect_authority {
        // Origin-form target inside an https tunnel.
        let (host, _port) = split_authority(authority);
        // `host` is unused because only the port half matters here; binding it
        // keeps the destructuring readable.
        let _unused_host = host;
        let path = if head.target.starts_with('/') {
            head.target.clone()
        } else {
            format!("/{}", head.target)
        };
        // Drop a default :443 for a clean, canonical URL.
        let auth = authority.strip_suffix(":443").unwrap_or(authority);
        return Some(format!("https://{auth}{path}"));
    }
    // Forward-proxy request: absolute-form already.
    if head.target.starts_with("http://") || head.target.starts_with("https://") {
        return Some(head.target.clone());
    }
    // Origin-form to a plain proxy: reconstruct from the Host header as http.
    if let Some(host) = head.headers.get("host") {
        let path = if head.target.starts_with('/') {
            head.target.clone()
        } else {
            format!("/{}", head.target)
        };
        return Some(format!("http://{host}{path}"));
    }
    None
}

/// Turn a request head + body into a canonical [`HttpRequest`].
pub fn to_http_request(head: &RequestHead, body: Body, url: String) -> HttpRequest {
    HttpRequest {
        method: head.method.clone(),
        url,
        version: head.version,
        headers: strip_request_hop_headers(&head.headers),
        body,
    }
}

/// Whether this request is a WebSocket upgrade handshake (RFC 6455): a GET with
/// `Connection: Upgrade` (token, possibly among others) and `Upgrade: websocket`.
/// Whether the buffered bytes begin an HTTP/2 connection (the RFC 7540 §3.5
/// connection preface, `PRI * HTTP/2.0`).
///
/// A client that speaks HTTP/2 with *prior knowledge* never sends it, so the
/// proxy must recognise the preface itself and answer with an explicit
/// disposition rather than dropping the connection as a malformed HTTP/1
/// request. The intercepted path reads HTTP/1.1 by design: the real HTTP/2
/// fingerprint is reproduced by the matched engine toward the target, which is
/// what the plan's transport model requires.
pub fn is_http2_preface(available: &[u8]) -> bool {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0";
    available.len() >= PREFACE.len() && &available[..PREFACE.len()] == PREFACE
}

pub fn is_websocket_upgrade(head: &RequestHead) -> bool {
    if !head.method.eq_ignore_ascii_case("GET") {
        return false;
    }
    let conn_upgrade = head.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("connection")
            && h.value
                .to_ascii_lowercase()
                .split(',')
                .any(|t| t.trim() == "upgrade")
    });
    let upgrade_ws = head
        .headers
        .get("upgrade")
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    conn_upgrade && upgrade_ws
}

/// The origin-form request target (path + query) from a request head, whether it
/// arrived absolute-form (forward proxy) or origin-form (inside a tunnel).
pub fn origin_form_target(head: &RequestHead) -> String {
    let t = head.target.as_str();
    for scheme in ["http://", "https://"] {
        if let Some(rest) = t.strip_prefix(scheme) {
            return match rest.find('/') {
                Some(i) => rest[i..].to_string(),
                None => "/".to_string(),
            };
        }
    }
    if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{t}")
    }
}

/// Reconstruct the raw upgrade handshake bytes to replay to the origin,
/// preserving the `Upgrade`/`Connection`/`Sec-WebSocket-*` headers (which the
/// normal forwarding path strips) and dropping only proxy-specific headers.
pub fn reconstruct_upgrade_request(head: &RequestHead, body: &Body) -> Vec<u8> {
    let mut out = String::with_capacity(256);
    out.push_str(&head.method);
    out.push(' ');
    out.push_str(&origin_form_target(head));
    out.push_str(" HTTP/1.1\r\n");
    for h in head.headers.iter() {
        if h.name.eq_ignore_ascii_case("proxy-connection")
            || h.name.eq_ignore_ascii_case("proxy-authorization")
        {
            continue;
        }
        out.push_str(&h.name);
        out.push_str(": ");
        out.push_str(&h.value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

/// Split `host:port` (or bare `host`) into its parts, defaulting the port to 443.
pub fn split_authority(authority: &str) -> (String, u16) {
    // Handle bracketed IPv6 literals: [::1]:443
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(443);
            return (format!("[{host}]"), port);
        }
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(443)),
        None => (authority.to_string(), 443),
    }
}

fn strip_request_hop_headers(headers: &HeaderList) -> HeaderList {
    let mut out = HeaderList::new();
    for h in headers.iter() {
        if is_request_hop_header(&h.name) {
            continue;
        }
        out.push(h.name.clone(), h.value.clone());
    }
    out
}

fn is_request_hop_header(name: &str) -> bool {
    const HOP: &[&str] = &[
        "proxy-connection",
        "connection",
        "keep-alive",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "upgrade",
        // The proxy re-frames the body: the engine sets its own
        // Content-Length, so forwarding the client's (now stale after a
        // Match & Replace rewrite) value would desynchronize the origin.
        "content-length",
        "transfer-encoding",
    ];
    HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

fn is_dropped_response_header(name: &str) -> bool {
    const DROP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "content-length",
        // The upstream engine already decompressed the body.
        "content-encoding",
        "te",
        "trailer",
        "upgrade",
    ];
    DROP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Canonical reason phrase for common status codes (used when the upstream
/// omitted one).
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A byte stream that reads from a cursor and discards writes, for driving
    /// the reader in tests.
    struct TestIo {
        reader: Cursor<Vec<u8>>,
        pub written: Vec<u8>,
    }

    impl TestIo {
        fn new(data: &[u8]) -> Self {
            TestIo {
                reader: Cursor::new(data.to_vec()),
                written: Vec::new(),
            }
        }
    }

    impl Read for TestIo {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reader.read(buf)
        }
    }
    impl Write for TestIo {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn parses_simple_get() {
        let raw =
            b"GET http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\nX-Test: v\r\n\r\n";
        let mut conn = Conn::new(TestIo::new(raw));
        let (head, body) = conn
            .read_request(DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_BODY_BYTES)
            .unwrap()
            .unwrap();
        assert_eq!(head.method, "GET");
        assert_eq!(head.target, "http://example.com/a?b=1");
        assert_eq!(head.headers.get("host"), Some("example.com"));
        assert!(body.is_empty());
        let url = absolute_url(&head, None).unwrap();
        assert_eq!(url, "http://example.com/a?b=1");
    }

    #[test]
    fn reads_content_length_body() {
        let raw = b"POST http://h/p HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello";
        let mut conn = Conn::new(TestIo::new(raw));
        let (head, body) = conn
            .read_request(DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_BODY_BYTES)
            .unwrap()
            .unwrap();
        assert_eq!(head.method, "POST");
        assert_eq!(body.as_bytes(), b"hello");
    }

    #[test]
    fn reads_chunked_body() {
        let raw = b"POST http://h/p HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut conn = Conn::new(TestIo::new(raw));
        let (_head, body) = conn
            .read_request(DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_BODY_BYTES)
            .unwrap()
            .unwrap();
        assert_eq!(body.as_text(), "hello world");
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut conn = Conn::new(TestIo::new(b""));
        let got = conn
            .read_request(DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_BODY_BYTES)
            .unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn oversized_header_is_rejected() {
        let big = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(2000));
        let mut conn = Conn::new(TestIo::new(big.as_bytes()));
        let err = conn.read_request(1024, DEFAULT_MAX_BODY_BYTES).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn connect_tunnel_builds_https_url() {
        let raw = b"GET /secret?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut conn = Conn::new(TestIo::new(raw));
        let (head, _body) = conn
            .read_request(DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_BODY_BYTES)
            .unwrap()
            .unwrap();
        let url = absolute_url(&head, Some("example.com:443")).unwrap();
        assert_eq!(url, "https://example.com/secret?x=1");
    }

    #[test]
    fn writes_response_with_content_length() {
        let mut io = TestIo::new(b"");
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: {
                let mut h = HeaderList::new();
                h.push("Content-Type", "text/plain");
                h.push("Content-Encoding", "gzip"); // must be dropped
                h.push("Connection", "keep-alive"); // hop-by-hop, dropped
                h
            },
            body: Body::from_text("hi"),
        };
        write_response(&mut io, &resp, false).unwrap();
        let out = String::from_utf8_lossy(&io.written);
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(out.contains("Content-Type: text/plain\r\n"));
        assert!(!out.to_ascii_lowercase().contains("content-encoding"));
        assert!(out.contains("Content-Length: 2\r\n"));
        assert!(out.contains("Connection: close\r\n"));
        assert!(out.ends_with("\r\n\r\nhi"));
    }

    #[test]
    fn splits_authority_variants() {
        assert_eq!(split_authority("h:8443"), ("h".to_string(), 8443));
        assert_eq!(split_authority("h"), ("h".to_string(), 443));
        assert_eq!(split_authority("[::1]:9000"), ("[::1]".to_string(), 9000));
    }

    #[test]
    fn detects_websocket_upgrade() {
        let raw = b"GET http://h/ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: abc\r\n\r\n";
        let mut conn = Conn::new(TestIo::new(raw));
        let (head, _b) = conn
            .read_request(DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_BODY_BYTES)
            .unwrap()
            .unwrap();
        assert!(is_websocket_upgrade(&head));
        assert_eq!(origin_form_target(&head), "/ws");
        let bytes = reconstruct_upgrade_request(&head, &Body::empty());
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("GET /ws HTTP/1.1\r\n"));
        // Upgrade/Connection/Sec-WebSocket headers are preserved for the origin.
        assert!(text.contains("Upgrade: websocket\r\n"));
        assert!(text.contains("Connection: keep-alive, Upgrade\r\n"));
        assert!(text.contains("Sec-WebSocket-Key: abc\r\n"));
    }

    #[test]
    fn plain_get_is_not_upgrade() {
        let raw = b"GET http://h/ HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut conn = Conn::new(TestIo::new(raw));
        let (head, _b) = conn
            .read_request(DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_BODY_BYTES)
            .unwrap()
            .unwrap();
        assert!(!is_websocket_upgrade(&head));
    }

    #[test]
    fn strips_hop_by_hop_on_request() {
        let raw = b"GET http://h/ HTTP/1.1\r\nHost: h\r\nProxy-Connection: keep-alive\r\nConnection: close\r\nX-Keep: yes\r\n\r\n";
        let mut conn = Conn::new(TestIo::new(raw));
        let (head, body) = conn
            .read_request(DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_BODY_BYTES)
            .unwrap()
            .unwrap();
        let req = to_http_request(&head, body, absolute_url(&head, None).unwrap());
        assert!(req.headers.get("proxy-connection").is_none());
        assert!(req.headers.get("connection").is_none());
        assert_eq!(req.headers.get("x-keep"), Some("yes"));
        assert_eq!(req.headers.get("host"), Some("h"));
    }
}

#[cfg(test)]
mod h2_tests {
    use super::*;

    #[test]
    fn the_http2_preface_is_recognised() {
        assert!(is_http2_preface(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
        assert!(!is_http2_preface(b"GET / HTTP/1.1\r\n"));
        // A shorter buffer is not a preface.
        assert!(!is_http2_preface(b"PRI"));
        assert!(!is_http2_preface(b""));
    }

    #[test]
    fn conn_peeks_buffered_bytes() {
        let mut conn = Conn::new(std::io::Cursor::new(
            b"PRI * HTTP/2.0\r\nSM\r\n\r\n".to_vec(),
        ));
        conn.prime().unwrap();
        assert!(is_http2_preface(conn.peek()));
    }
}
