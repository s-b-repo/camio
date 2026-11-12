//! The request-engine trait and fingerprint-preserving header handling.
//!
//! All tool-originated traffic (Replay, Automate, Scanner, MCP) goes through a
//! [`RequestEngine`]. The engine stamps every [`HttpExchange`] with the
//! fingerprint profile used, so automated traffic is attributable (plan §16),
//! and emits headers in the browser's canonical order and casing without ever
//! alphabetizing (plan §6.1 item 3).

use crate::spec::FingerprintSpec;
use camio_core::{HeaderList, HttpExchange, HttpRequest, Source};
use std::fmt;

/// An error from the request engine.
#[derive(Debug)]
pub enum RequestError {
    /// The request URL could not be parsed.
    InvalidUrl(String),
    /// The scheme is not supported by this engine.
    UnsupportedScheme(String),
    /// A transport/IO/TLS error while sending.
    Transport(String),
    /// The engine backend is not available in this build.
    Unavailable(String),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestError::InvalidUrl(s) => write!(f, "invalid URL: {s}"),
            RequestError::UnsupportedScheme(s) => write!(f, "unsupported scheme: {s}"),
            RequestError::Transport(s) => write!(f, "transport error: {s}"),
            RequestError::Unavailable(s) => write!(f, "engine unavailable: {s}"),
        }
    }
}

impl std::error::Error for RequestError {}

/// A client that sends an [`HttpRequest`] and returns the completed
/// [`HttpExchange`].
pub trait RequestEngine {
    /// Human-readable engine label for the status bar / audit log.
    fn label(&self) -> String;

    /// Whether this engine reproduces the browser's JA3/JA4/HTTP-2 fingerprint.
    /// The status indicator shows this honestly (plan §6.3): a `false` here is a
    /// visible "fingerprint not matched" warning, never hidden.
    fn is_fingerprint_matched(&self) -> bool;

    /// The fingerprint spec this engine targets.
    fn spec(&self) -> &FingerprintSpec;

    /// An optional one-line caveat for the status indicator (e.g. the emulation
    /// preset lags the browser version, so parity must be measured). `None` when
    /// there is nothing to warn about. Never claims invisibility (plan §6.3).
    fn parity_note(&self) -> Option<String> {
        None
    }

    /// Send the request and return the exchange, with `fingerprint_used` and
    /// `source` populated.
    fn send(&self, req: HttpRequest, source: Source) -> Result<HttpExchange, RequestError>;
}

/// Compute the value of the `Host` header for a request URL, including the port
/// only when it is not the scheme default.
pub fn host_header_value(req: &HttpRequest) -> Option<String> {
    let url = req.parsed_url()?;
    let host = url.host_str()?;
    // `url.port()` is the explicit port only (None when omitted). Include it in
    // the Host header only when present and not the scheme default.
    match url.port() {
        Some(p) if Some(p) != default_port(url.scheme()) => Some(format!("{host}:{p}")),
        _ => Some(host.to_string()),
    }
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

/// Reorder a request's headers into the browser's canonical order (plan §6.1
/// item 3). Headers named in the spec come first in that order; any remaining
/// headers keep their original relative order afterwards. Duplicates and casing
/// are preserved exactly — nothing is normalized or dropped.
pub fn order_headers(headers: &HeaderList, spec: &FingerprintSpec) -> HeaderList {
    let mut out = HeaderList::new();
    let mut emitted = vec![false; headers.0.len()];

    for want in &spec.header_order {
        for (i, h) in headers.0.iter().enumerate() {
            if !emitted[i] && h.name.eq_ignore_ascii_case(want) {
                out.push(h.name.clone(), h.value.clone());
                emitted[i] = true;
            }
        }
    }
    // Append any headers not mentioned in the spec, in their original order.
    for (i, h) in headers.0.iter().enumerate() {
        if !emitted[i] {
            out.push(h.name.clone(), h.value.clone());
        }
    }
    out
}

/// Fill in default headers a real browser would send (without overwriting any
/// the caller set explicitly), then order them per the spec. Returns a request
/// ready for the wire.
pub fn prepare_request(mut req: HttpRequest, spec: &FingerprintSpec) -> HttpRequest {
    let has = |h: &HttpRequest, name: &str| h.headers.get(name).is_some();

    if !has(&req, "Host") {
        if let Some(v) = host_header_value(&req) {
            req.headers.push("Host", v);
        }
    }
    if !has(&req, "User-Agent") {
        req.headers.push("User-Agent", spec.user_agent.clone());
    }
    if !has(&req, "Accept") {
        req.headers.push("Accept", "*/*");
    }
    if !has(&req, "Accept-Language") {
        req.headers
            .push("Accept-Language", spec.accept_language.clone());
    }
    if !has(&req, "Accept-Encoding") {
        req.headers.push("Accept-Encoding", "gzip, deflate, br");
    }
    if spec.send_dnt && !has(&req, "DNT") {
        req.headers.push("DNT", "1");
    }

    req.headers = order_headers(&req.headers, spec);
    req
}

/// A no-network engine: it prepares the request (headers, ordering, fingerprint
/// stamp) and returns an exchange with no response. Used for `--dry-run`, tests,
/// and environments without the impersonating backend. It reports
/// `is_fingerprint_matched() == false` so nothing is ever claimed falsely.
pub struct DryRunEngine {
    spec: FingerprintSpec,
}

impl DryRunEngine {
    pub fn new(spec: FingerprintSpec) -> Self {
        DryRunEngine { spec }
    }
}

impl RequestEngine for DryRunEngine {
    fn label(&self) -> String {
        format!("dry-run ({})", self.spec.target_label())
    }

    fn is_fingerprint_matched(&self) -> bool {
        false
    }

    fn spec(&self) -> &FingerprintSpec {
        &self.spec
    }

    fn send(&self, req: HttpRequest, source: Source) -> Result<HttpExchange, RequestError> {
        if req.parsed_url().is_none() {
            return Err(RequestError::InvalidUrl(req.url.clone()));
        }
        let prepared = prepare_request(req, &self.spec);
        let mut ex = HttpExchange::new(prepared, source);
        ex.fingerprint_used = Some(self.spec.profile_name.clone());
        Ok(ex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::FingerprintProfile;

    fn spec() -> FingerprintSpec {
        FingerprintSpec::from_profile(&FingerprintProfile::new("p", "158.0.1-beta.41"))
    }

    #[test]
    fn header_ordering_follows_spec_then_extras() {
        let mut headers = HeaderList::new();
        // Deliberately out of browser order, with an extra header.
        headers.push("Accept-Encoding", "gzip");
        headers.push("X-Extra", "1");
        headers.push("User-Agent", "UA");
        headers.push("Host", "example.com");

        let ordered = order_headers(&headers, &spec());
        let names: Vec<&str> = ordered.iter().map(|h| h.name.as_str()).collect();
        // Host, then User-Agent, then Accept-Encoding (per Firefox order), then
        // the unknown X-Extra last — never alphabetized.
        assert_eq!(
            names,
            vec!["Host", "User-Agent", "Accept-Encoding", "X-Extra"]
        );
    }

    #[test]
    fn ordering_preserves_duplicates_and_casing() {
        let mut headers = HeaderList::new();
        headers.push("set-cookie", "a=1"); // unusual casing preserved
        headers.push("Set-Cookie", "b=2");
        let ordered = order_headers(&headers, &spec());
        assert_eq!(ordered.0.len(), 2);
        assert_eq!(ordered.0[0].name, "set-cookie");
        assert_eq!(ordered.0[1].name, "Set-Cookie");
    }

    #[test]
    fn prepare_adds_defaults_without_overwriting() {
        let mut req = HttpRequest::get("https://example.com:8443/x");
        req.headers.push("User-Agent", "MyScanner/1.0"); // explicit — must survive
        let prepared = prepare_request(req, &spec());

        assert_eq!(prepared.headers.get("User-Agent"), Some("MyScanner/1.0"));
        assert_eq!(prepared.headers.get("Host"), Some("example.com:8443"));
        assert!(prepared.headers.get("Accept-Language").is_some());
        // Host is first (Firefox order).
        assert_eq!(prepared.headers.0[0].name, "Host");
    }

    #[test]
    fn host_header_omits_default_port() {
        let req = HttpRequest::get("https://example.com/x");
        assert_eq!(host_header_value(&req).as_deref(), Some("example.com"));
        let req = HttpRequest::get("https://example.com:8443/x");
        assert_eq!(host_header_value(&req).as_deref(), Some("example.com:8443"));
    }

    #[test]
    fn dry_run_stamps_fingerprint_and_sets_source() {
        let engine = DryRunEngine::new(spec());
        let ex = engine
            .send(HttpRequest::get("https://example.com/"), Source::Replay)
            .unwrap();
        assert_eq!(ex.source, Source::Replay);
        assert_eq!(ex.fingerprint_used.as_deref(), Some("p"));
        assert!(!engine.is_fingerprint_matched());
    }
}
