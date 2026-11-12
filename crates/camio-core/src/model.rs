//! The canonical Camio domain model (plan §13, "Core data objects").
//!
//! One representation of an HTTP exchange, project, scope decision, and finding,
//! shared by the UI, MCP server, request engine, proxy, and storage so none of
//! them can disagree about a request's destination or contents (plan §16: "one
//! canonical parser and scope-decision path per request").
//!
//! Design rules enforced here:
//!   * **Raw bytes and structured views are kept separately** and never silently
//!     rewritten (plan §13). Header order and casing are preserved exactly
//!     (plan §6.1 item 3) — we never alphabetize or canonicalize.
//!   * **One URL parser.** All host/port/path/scope decisions go through
//!     [`HttpRequest::parsed_url`] (the `url` crate), so a smuggled or malformed
//!     target cannot be read two ways.
//!   * Every exchange records its [`Source`] and the fingerprint profile used,
//!     so all automated traffic is attributable (plan §16).

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use url::Url;

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

macro_rules! id_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name(pub i64);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        impl From<i64> for $name {
            fn from(v: i64) -> Self { $name(v) }
        }
    };
}

id_newtype!(
    /// Primary key of a stored [`HttpExchange`].
    ExchangeId
);
id_newtype!(
    /// Primary key of a [`Project`].
    ProjectId
);
id_newtype!(
    /// Primary key of a [`Finding`].
    FindingId
);
id_newtype!(
    /// Primary key of a [`Task`].
    TaskId
);

// ---------------------------------------------------------------------------
// HTTP primitives
// ---------------------------------------------------------------------------

/// Wire protocol version. Kept explicit because the HTTP/2 fingerprint differs
/// from HTTP/1.1 (plan §6.1 item 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HttpVersion {
    Http10,
    #[default]
    Http11,
    H2,
    H3,
}

impl HttpVersion {
    pub fn wire_token(self) -> &'static str {
        match self {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
            HttpVersion::H2 => "HTTP/2",
            HttpVersion::H3 => "HTTP/3",
        }
    }
}

/// Where an exchange came from. Every exchange carries this so automated traffic
/// is attributable and scope/rate policy can be applied per origin (plan §16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Organic browser traffic captured at the browser layer (fingerprint-true).
    Browser,
    /// Replay/Repeater surface.
    Replay,
    /// Automate/Intruder fuzzing campaigns.
    Automate,
    /// Passive or active scanner.
    Scanner,
    /// Crawler/discovery.
    Crawler,
    /// The optional external-client MITM proxy (fingerprint-changing).
    Proxy,
    /// Imported from a Burp/Caido project or file.
    Import,
    /// Issued via the MCP server.
    Mcp,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Browser => "browser",
            Source::Replay => "replay",
            Source::Automate => "automate",
            Source::Scanner => "scanner",
            Source::Crawler => "crawler",
            Source::Proxy => "proxy",
            Source::Import => "import",
            Source::Mcp => "mcp",
        }
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single header, preserving the exact name casing seen/sent on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Header {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// An ordered list of headers that preserves order, casing, and duplicates
/// (plan §6.1 item 3: "preserves exact order and casing on the wire and never
/// alphabetizes/normalizes outbound").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderList(pub Vec<Header>);

impl HeaderList {
    pub fn new() -> Self {
        HeaderList(Vec::new())
    }

    pub fn push(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.push(Header::new(name, value));
    }

    /// First value for `name`, matched case-insensitively (HTTP header names are
    /// case-insensitive even though we preserve the original casing).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Every value for `name` (headers may legitimately repeat).
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.0
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Header> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A message body. Stored as raw bytes; serialized as base64 so arbitrary binary
/// survives JSON round-trips without being rewritten.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body(#[serde(with = "b64")] pub Vec<u8>);

impl Body {
    pub fn empty() -> Self {
        Body(Vec::new())
    }

    pub fn from_bytes(b: impl Into<Vec<u8>>) -> Self {
        Body(b.into())
    }

    pub fn from_text(s: impl Into<String>) -> Self {
        Body(s.into().into_bytes())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Lossy UTF-8 view for text matching and display.
    pub fn as_text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }
}

/// base64 (de)serialization for [`Body`].
mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// An HTTP request as captured or constructed. `url` is absolute so scope and
/// host/port derive from one place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    /// Method token. A `String` (not an enum) so custom/approved and malformed
    /// methods for smuggling tests round-trip exactly (plan §10 method matrix).
    pub method: String,
    /// Absolute request URL.
    pub url: String,
    pub version: HttpVersion,
    pub headers: HeaderList,
    pub body: Body,
}

impl HttpRequest {
    pub fn get(url: impl Into<String>) -> Self {
        HttpRequest {
            method: "GET".to_string(),
            url: url.into(),
            version: HttpVersion::Http11,
            headers: HeaderList::new(),
            body: Body::empty(),
        }
    }

    /// Parse the absolute URL through the one canonical parser.
    pub fn parsed_url(&self) -> Option<Url> {
        Url::parse(&self.url).ok()
    }

    pub fn host(&self) -> Option<String> {
        self.parsed_url()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
    }

    /// Port, falling back to the scheme's default (443 for https, 80 for http).
    pub fn port(&self) -> Option<u16> {
        self.parsed_url().and_then(|u| u.port_or_known_default())
    }

    pub fn scheme(&self) -> Option<String> {
        self.parsed_url().map(|u| u.scheme().to_string())
    }

    pub fn path(&self) -> String {
        self.parsed_url()
            .map(|u| u.path().to_string())
            .unwrap_or_default()
    }

    pub fn query(&self) -> Option<String> {
        self.parsed_url()
            .and_then(|u| u.query().map(|s| s.to_string()))
    }

    /// File extension of the last path segment, **including the leading dot**
    /// (so it matches Caido/HTTPQL `req.ext.eq:".js"`). `None` if there is none.
    pub fn extension(&self) -> Option<String> {
        let path = self.path();
        let last = path.rsplit('/').next()?;
        let dot = last.rfind('.')?;
        if dot == 0 {
            return None; // dotfile, no extension
        }
        Some(last[dot..].to_ascii_lowercase())
    }

    /// Origin-form target (path + query) for the request line.
    pub fn request_target(&self) -> String {
        match (self.parsed_url(), self.query()) {
            (Some(u), _) => {
                let mut t = u.path().to_string();
                if let Some(q) = u.query() {
                    t.push('?');
                    t.push_str(q);
                }
                t
            }
            (None, _) => self.url.clone(),
        }
    }

    /// Reconstruct the raw request as text (request line + headers + blank line +
    /// body). Lossy for non-UTF-8 bodies; used for `req.raw` matching and display.
    pub fn raw(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.method);
        out.push(' ');
        out.push_str(&self.request_target());
        out.push(' ');
        out.push_str(self.version.wire_token());
        out.push_str("\r\n");
        for h in self.headers.iter() {
            out.push_str(&h.name);
            out.push_str(": ");
            out.push_str(&h.value);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out.push_str(&self.body.as_text());
        out
    }
}

/// An HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub version: HttpVersion,
    pub reason: Option<String>,
    pub headers: HeaderList,
    pub body: Body,
}

impl HttpResponse {
    pub fn raw(&self) -> String {
        let mut out = String::new();
        out.push_str(self.version.wire_token());
        out.push(' ');
        out.push_str(&self.status.to_string());
        if let Some(r) = &self.reason {
            out.push(' ');
            out.push_str(r);
        }
        out.push_str("\r\n");
        for h in self.headers.iter() {
            out.push_str(&h.name);
            out.push_str(": ");
            out.push_str(&h.value);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out.push_str(&self.body.as_text());
        out
    }
}

/// Per-exchange timing in milliseconds from send start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timings {
    /// Unix epoch millis when the request was sent.
    pub started_at_ms: i64,
    /// Round-trip time: send start → last response byte, in ms.
    pub roundtrip_ms: i64,
}

/// The decision made by the scope engine for an exchange's destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDecision {
    /// In scope: tools may send here.
    InScope,
    /// Explicitly excluded or not matched by any include rule.
    OutOfScope,
    /// Blocked by an SSRF/safety guard (loopback, link-local, metadata).
    Blocked,
}

impl ScopeDecision {
    pub fn is_sendable(self) -> bool {
        matches!(self, ScopeDecision::InScope)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            ScopeDecision::InScope => "in_scope",
            ScopeDecision::OutOfScope => "out_of_scope",
            ScopeDecision::Blocked => "blocked",
        }
    }
}

/// A full request/response exchange — the central record in Camio.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpExchange {
    /// Assigned by the store; `0` before persistence.
    pub id: ExchangeId,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub timings: Option<Timings>,
    pub source: Source,
    pub scope: Option<ScopeDecision>,
    /// Name of the [`crate::FingerprintProfile`] used to send this exchange, so
    /// a tester can prove what fingerprint any request went out on (plan §16).
    pub fingerprint_used: Option<String>,
    /// Unix epoch millis when this exchange was recorded.
    pub created_at_ms: i64,
    /// Optional free-text note.
    pub note: Option<String>,
}

impl HttpExchange {
    pub fn new(request: HttpRequest, source: Source) -> Self {
        HttpExchange {
            id: ExchangeId(0),
            request,
            response: None,
            timings: None,
            source,
            scope: None,
            fingerprint_used: None,
            created_at_ms: 0,
            note: None,
        }
    }

    pub fn with_response(mut self, response: HttpResponse) -> Self {
        self.response = Some(response);
        self
    }
}

// ---------------------------------------------------------------------------
// Project, findings, tasks
// ---------------------------------------------------------------------------

/// A testing project (plan §13). Owns targets, scope, profiles, history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    pub id: ProjectId,
    pub name: String,
    /// Name of the attached browser/fingerprint profile, if any.
    pub profile: Option<String>,
    pub created_at_ms: i64,
}

/// A discovered or declared target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub scheme: String,
}

/// Finding severity (plan §8 Scan row).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Finding confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Tentative,
    Firm,
    Certain,
}

/// A security finding with evidence linking back to exchanges (plan §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Markdown notes / description.
    pub detail: String,
    /// Exchanges that are evidence for this finding.
    pub evidence: Vec<ExchangeId>,
    pub created_at_ms: i64,
}

/// Lifecycle state of a long-running task (plan §11: "Long tasks return IDs with
/// status/cancel/results").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Pending,
    Running,
    Paused,
    Completed,
    Cancelled,
    Failed,
}

/// A bounded, cancellable unit of automated work (crawl, campaign, scan).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: TaskId,
    pub kind: String,
    pub state: TaskState,
    /// Requests issued so far (for budget display, plan §10).
    pub requests_sent: u64,
    /// Request budget ceiling; `None` = unbounded (discouraged).
    pub request_budget: Option<u64>,
    pub created_at_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> HttpRequest {
        let mut req = HttpRequest::get("https://example.com:8443/app/login.PHP?next=/home");
        req.headers.push("Host", "example.com:8443");
        req.headers.push("User-Agent", "Mozilla/5.0");
        req.headers.push("X-Custom", "one");
        req.headers.push("X-Custom", "two");
        req
    }

    #[test]
    fn url_parts_derive_from_one_parser() {
        let r = sample_request();
        assert_eq!(r.host().as_deref(), Some("example.com"));
        assert_eq!(r.port(), Some(8443));
        assert_eq!(r.scheme().as_deref(), Some("https"));
        assert_eq!(r.path(), "/app/login.PHP");
        assert_eq!(r.query().as_deref(), Some("next=/home"));
    }

    #[test]
    fn extension_includes_dot_and_lowercases() {
        let r = sample_request();
        assert_eq!(r.extension().as_deref(), Some(".php"));
        // No extension for a directory path.
        let r2 = HttpRequest::get("https://x.test/a/b/");
        assert_eq!(r2.extension(), None);
        // Dotfiles are not extensions.
        let r3 = HttpRequest::get("https://x.test/.env");
        assert_eq!(r3.extension(), None);
    }

    #[test]
    fn default_port_falls_back_to_scheme() {
        let r = HttpRequest::get("https://x.test/");
        assert_eq!(r.port(), Some(443));
        let r = HttpRequest::get("http://x.test/");
        assert_eq!(r.port(), Some(80));
    }

    #[test]
    fn headers_preserve_order_casing_and_duplicates() {
        let r = sample_request();
        // Case-insensitive lookup, original casing preserved in storage.
        assert_eq!(r.headers.get("user-agent"), Some("Mozilla/5.0"));
        assert_eq!(r.headers.0[1].name, "User-Agent");
        // Duplicate headers both retained, in order.
        let all: Vec<_> = r.headers.get_all("X-Custom").collect();
        assert_eq!(all, vec!["one", "two"]);
    }

    #[test]
    fn raw_request_has_request_line_and_blank_line() {
        let r = sample_request();
        let raw = r.raw();
        assert!(raw.starts_with("GET /app/login.PHP?next=/home HTTP/1.1\r\n"));
        assert!(raw.contains("\r\nUser-Agent: Mozilla/5.0\r\n"));
        assert!(raw.contains("\r\n\r\n"));
    }

    #[test]
    fn body_base64_roundtrips_binary() {
        let body = Body::from_bytes(vec![0u8, 159, 146, 150, 255]);
        let s = serde_json::to_string(&body).unwrap();
        // Non-UTF8 bytes must survive as base64, not be mangled.
        let back: Body = serde_json::from_str(&s).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn exchange_roundtrips_json() {
        let ex = HttpExchange::new(sample_request(), Source::Replay);
        let s = serde_json::to_string(&ex).unwrap();
        let back: HttpExchange = serde_json::from_str(&s).unwrap();
        assert_eq!(ex, back);
    }
}
