//! Passive check implementations and the small shared helpers they lean on
//! (plan §8 "Scan & crawl" row: "Passive checks first … evidence,
//! severity/confidence, dedup"; plan §15 Phase 4: "Passive checks first").
//!
//! Every check in this module is a zero-sized unit struct implementing
//! [`crate::PassiveCheck`]; the registry in [`crate`] wires them together. The
//! helpers here keep the checks honest about the plan's invariants:
//!   * header lookups are case-insensitive but **never** reorder or canonicalize
//!     headers (plan §6.1 item 3) — we only ever *read* through
//!     [`camio_core::HeaderList::get`]/`get_all`;
//!   * findings are built with `id = FindingId(0)` and `created_at_ms = 0`
//!     because the store assigns those on persistence (plan §13);
//!   * regexes are compiled at most once, lazily, and a (practically
//!     impossible) compile failure degrades a check to "no finding" rather than
//!     panicking — this crate contains no `unwrap`/`expect`/`panic!` outside
//!     tests.

use camio_core::{
    Confidence, ExchangeId, Finding, FindingId, HttpExchange, HttpResponse, Severity,
};
use regex::Regex;
use std::sync::OnceLock;

mod banner;
mod basic_auth;
mod cookies;
mod cors;
mod directory_listing;
mod mixed_content;
mod reflected_input;
mod security_headers;
mod sensitive_url;
mod verbose_error;

pub use banner::ServerBannerDisclosure;
pub use basic_auth::BasicAuthOverHttp;
pub use cookies::InsecureCookies;
pub use cors::CorsMisconfig;
pub use directory_listing::DirectoryListing;
pub use mixed_content::MixedContent;
pub use reflected_input::ReflectedInput;
pub use security_headers::MissingSecurityHeaders;
pub use sensitive_url::SensitiveDataInUrl;
pub use verbose_error::VerboseError;

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------

/// Build a passive [`Finding`] for one exchange.
///
/// `id` is always [`FindingId`]`(0)` and `created_at_ms` is `0`: the store
/// assigns real values when the finding is persisted (plan §13). Evidence is
/// the single originating exchange; [`crate::scan_all`] unions evidence across
/// exchanges during deduplication.
pub(crate) fn finding(
    title: impl Into<String>,
    severity: Severity,
    confidence: Confidence,
    detail: impl Into<String>,
    evidence: ExchangeId,
) -> Finding {
    Finding {
        id: FindingId(0),
        title: title.into(),
        severity,
        confidence,
        detail: detail.into(),
        evidence: vec![evidence],
        created_at_ms: 0,
    }
}

// ---------------------------------------------------------------------------
// Response / request shape helpers
// ---------------------------------------------------------------------------

/// The response `Content-Type` value, if present (case-insensitive lookup).
pub(crate) fn content_type(resp: &HttpResponse) -> Option<&str> {
    resp.headers.get("Content-Type")
}

/// `true` for a `2xx` status.
pub(crate) fn is_2xx(resp: &HttpResponse) -> bool {
    (200..=299).contains(&resp.status)
}

/// `true` when the response declares an HTML content type (`text/html`,
/// `application/xhtml+xml`, …).
pub(crate) fn is_html(resp: &HttpResponse) -> bool {
    content_type(resp)
        .map(|ct| ct.to_ascii_lowercase().contains("html"))
        .unwrap_or(false)
}

/// `true` when the response declares an HTML-or-text content type. Security
/// headers only meaningfully protect documents the browser renders, so the
/// header check gates on this (plan §8 Scan row).
pub(crate) fn is_html_or_text(resp: &HttpResponse) -> bool {
    content_type(resp)
        .map(|ct| {
            let ct = ct.to_ascii_lowercase();
            ct.starts_with("text/") || ct.contains("html")
        })
        .unwrap_or(false)
}

/// `true` when the request URL scheme is `https` (via the one canonical URL
/// parser in [`camio_core`]).
pub(crate) fn request_is_https(ex: &HttpExchange) -> bool {
    ex.request.scheme().as_deref() == Some("https")
}

// ---------------------------------------------------------------------------
// application/x-www-form-urlencoded parsing (hand-rolled; plan §14 "prefer std")
// ---------------------------------------------------------------------------

/// Decode one `application/x-www-form-urlencoded` component: `+` becomes space
/// and `%XX` becomes the decoded byte. Invalid escapes are kept verbatim.
/// Undecodable byte sequences fall back to lossy UTF-8 so this never fails.
pub(crate) fn percent_plus_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push((hi << 4) | lo);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse `a=b&c=d` into decoded `(key, value)` pairs. A component with no `=`
/// yields an empty value. Empty components are skipped. Used for both the URL
/// query string and urlencoded request bodies so decoding is identical in both.
pub(crate) fn form_pairs(input: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in input.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        out.push((percent_plus_decode(k), percent_plus_decode(v)));
    }
    out
}

// ---------------------------------------------------------------------------
// Lazily-compiled regexes (compiled at most once, process-wide)
// ---------------------------------------------------------------------------

/// Query-key names that should never travel in a URL (plan §8/§16: secrets must
/// not leak into history, proxy logs or the `Referer` header).
pub(crate) fn sensitive_key_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    // Anchored to whole key tokens (start/separator on both sides) so
    // separator-joined names (`api_key`, `csrf_token`, `X-Api-Key`) still match
    // while benign keys that merely *contain* a sensitive word (`secretary`,
    // `passwordless`, `tokenizer`) do not.
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:^|[-_])(?:password|passwd|pwd|token|api[_-]?key|secret|access_key|sessionid)(?:$|[-_=])",
        )
        .ok()
    })
    .as_ref()
}

/// A cleartext `http://` subresource on a page: any `src=` attribute, or a
/// `<link … href=>` (stylesheet/preload). Navigational `href` on `<a>`/`<area>`/
/// `<base>` is deliberately excluded — it is not a subresource the browser loads
/// into the page, so it is not mixed content. Capture group 1 is the URL.
pub(crate) fn http_resource_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:\bsrc\s*=\s*["']?|<link\b[^>]*?\bhref\s*=\s*["']?)(http://[^"'\s>]+)"#)
            .ok()
    })
    .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{HttpRequest, Source};

    #[test]
    fn percent_plus_decode_handles_escapes_and_plus() {
        assert_eq!(percent_plus_decode("a+b"), "a b");
        assert_eq!(percent_plus_decode("%3Cscript%3E"), "<script>");
        assert_eq!(percent_plus_decode("plain"), "plain");
    }

    #[test]
    fn percent_plus_decode_keeps_invalid_escapes_literal() {
        // Trailing/short escape and non-hex digits are left verbatim, not lost.
        assert_eq!(percent_plus_decode("100%"), "100%");
        assert_eq!(percent_plus_decode("a%zzb"), "a%zzb");
        assert_eq!(percent_plus_decode("x%2"), "x%2");
    }

    #[test]
    fn form_pairs_splits_and_decodes() {
        let p = form_pairs("q=hello+world&token=%41bc&flag");
        assert_eq!(
            p,
            vec![
                ("q".to_string(), "hello world".to_string()),
                ("token".to_string(), "Abc".to_string()),
                ("flag".to_string(), "".to_string()),
            ]
        );
    }

    #[test]
    fn form_pairs_skips_empty_components() {
        assert_eq!(
            form_pairs("&&a=1&&"),
            vec![("a".to_string(), "1".to_string())]
        );
        assert!(form_pairs("").is_empty());
    }

    #[test]
    fn content_type_helpers() {
        let mut resp = camio_core::HttpResponse {
            status: 200,
            version: camio_core::HttpVersion::Http11,
            reason: None,
            headers: camio_core::HeaderList::new(),
            body: camio_core::Body::empty(),
        };
        resp.headers
            .push("Content-Type", "text/html; charset=utf-8");
        assert!(is_html(&resp));
        assert!(is_html_or_text(&resp));
        assert!(is_2xx(&resp));

        resp.headers = camio_core::HeaderList::new();
        resp.headers.push("Content-Type", "application/json");
        assert!(!is_html(&resp));
        assert!(!is_html_or_text(&resp));

        resp.status = 404;
        assert!(!is_2xx(&resp));
    }

    #[test]
    fn request_scheme_detection() {
        let https = HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner);
        let http = HttpExchange::new(HttpRequest::get("http://x.test/"), Source::Scanner);
        assert!(request_is_https(&https));
        assert!(!request_is_https(&http));
    }

    #[test]
    fn sensitive_key_regex_matches_expected_keys() {
        let re = sensitive_key_re().expect("regex compiles");
        for k in [
            "password",
            "passwd",
            "pwd",
            "token",
            "api_key",
            "api-key",
            "apikey",
            "secret",
            "access_key",
            "sessionid",
            "X-Api-Key",
            "csrf_token",
            "user_password",
        ] {
            assert!(re.is_match(k), "expected `{k}` to match");
        }
        // Benign keys that merely *contain* a sensitive word must NOT match.
        for k in [
            "user",
            "page",
            "id",
            "lang",
            "secretary",
            "passwordless",
            "tokenizer",
            "accessKeyboard",
        ] {
            assert!(!re.is_match(k), "expected `{k}` not to match");
        }
    }

    #[test]
    fn http_resource_regex_captures_subresources_not_navigation() {
        let re = http_resource_re().expect("regex compiles");
        let caps = re
            .captures(r#"<img src="http://cdn.test/a.js">"#)
            .expect("match");
        assert_eq!(&caps[1], "http://cdn.test/a.js");
        assert!(!re.is_match(r#"<img src="https://cdn.test/a.js">"#));
        // <link href> is a subresource and must match.
        assert!(re.is_match(r#"<link rel="stylesheet" href="http://cdn.test/s.css">"#));
        // Navigational <a href>/<base href> are NOT mixed content → must not match.
        assert!(!re.is_match(r#"<a href="http://external.test/page">go</a>"#));
        assert!(!re.is_match(r#"<base href="http://external.test/">"#));
    }
}
