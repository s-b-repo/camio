//! Raw HTTP message parsing shared by the importers (plan §7.4 migration, §13
//! "one canonical parser").
//!
//! Burp item exports and (optionally) other sources carry the request/response
//! as the raw wire message. These helpers turn those bytes into the canonical
//! [`HttpRequest`]/[`HttpResponse`] **without canonicalizing** them: header
//! order, casing, and duplicates are preserved exactly (plan §6.1 item 3 —
//! "preserves exact order and casing on the wire and never alphabetizes"), and
//! the body is kept as raw bytes. A body we cannot safely rewrite (e.g.
//! `Transfer-Encoding: chunked`) is left verbatim; the caller records a warning.
//!
//! The parsers are deliberately tolerant: they accept CRLF or bare-LF line
//! endings and never panic — a malformed message yields a typed
//! [`ImportError`](crate::ImportError) instead.

use crate::ImportError;
use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion};

/// Parse a raw HTTP request message (request line + headers + body).
///
/// The method and version come from the request line; `url` is used verbatim as
/// the absolute [`HttpRequest::url`] (the raw request only carries an origin-form
/// target, so the absolute URL must be supplied by the caller). Header order,
/// casing, and duplicates are preserved exactly.
pub fn parse_raw_request(bytes: &[u8], url: &str) -> Result<HttpRequest, ImportError> {
    let (head, body) = split_head_body(bytes);
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split('\n').map(strip_cr);

    let request_line = lines.next().unwrap_or("").trim();
    if request_line.is_empty() {
        return Err(ImportError::Parse("empty request line".to_string()));
    }

    let mut tokens = request_line.split_whitespace();
    let method = tokens.next().unwrap_or("").to_string();
    if method.is_empty() {
        return Err(ImportError::Parse(format!(
            "missing method in request line: {request_line:?}"
        )));
    }
    // The last whitespace-separated token is the HTTP version (if present); the
    // middle token is the origin-form target, which we ignore in favour of `url`.
    let rest: Vec<&str> = tokens.collect();
    let version = rest.last().map(|t| map_http_version(t)).unwrap_or_default();

    let headers = parse_header_lines(lines);

    Ok(HttpRequest {
        method,
        url: url.to_string(),
        version,
        headers,
        body: Body::from_bytes(body.to_vec()),
    })
}

/// Parse a raw HTTP response message (status line + headers + body).
///
/// Header order, casing, and duplicates are preserved exactly.
pub fn parse_raw_response(bytes: &[u8]) -> Result<HttpResponse, ImportError> {
    let (head, body) = split_head_body(bytes);
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split('\n').map(strip_cr);

    let status_line = lines.next().unwrap_or("").trim();
    if status_line.is_empty() {
        return Err(ImportError::Parse("empty status line".to_string()));
    }

    let mut tokens = status_line.split_whitespace();
    let version = map_http_version(tokens.next().unwrap_or(""));
    let status_token = tokens.next().unwrap_or("");
    let status: u16 = status_token
        .parse()
        .map_err(|_| ImportError::Parse(format!("invalid status code: {status_token:?}")))?;
    let reason_text = tokens.collect::<Vec<_>>().join(" ");
    let reason = {
        let trimmed = reason_text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    };

    let headers = parse_header_lines(lines);

    Ok(HttpResponse {
        status,
        version,
        reason,
        headers,
        body: Body::from_bytes(body.to_vec()),
    })
}

/// Map an HTTP version token (wire form or ALPN id) to [`HttpVersion`].
/// Unknown tokens fall back to HTTP/1.1, the common importer default.
pub(crate) fn map_http_version(token: &str) -> HttpVersion {
    let t = token.trim();
    if t.eq_ignore_ascii_case("HTTP/1.0") {
        HttpVersion::Http10
    } else if t.eq_ignore_ascii_case("HTTP/1.1") {
        HttpVersion::Http11
    } else if t.eq_ignore_ascii_case("HTTP/2")
        || t.eq_ignore_ascii_case("HTTP/2.0")
        || t.eq_ignore_ascii_case("h2")
    {
        HttpVersion::H2
    } else if t.eq_ignore_ascii_case("HTTP/3")
        || t.eq_ignore_ascii_case("HTTP/3.0")
        || t.eq_ignore_ascii_case("h3")
    {
        HttpVersion::H3
    } else {
        HttpVersion::Http11
    }
}

/// True if any `Transfer-Encoding` header advertises `chunked`. Importers use
/// this to warn that a chunked body was kept raw rather than de-chunked.
pub(crate) fn header_has_chunked(headers: &HeaderList) -> bool {
    headers.get_all("Transfer-Encoding").any(|v| {
        v.split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
    })
}

/// Find the first index of `needle` in `haystack` (byte substring search).
pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Split a raw message into head (request/status line + headers) and body at the
/// first blank line. Accepts CRLF (`\r\n\r\n`) or bare-LF (`\n\n`) separators;
/// with neither, the whole input is the head and the body is empty.
///
/// It splits at the **earliest** of the two separators, not whichever style is
/// searched for first: a bare-LF-framed message whose body legitimately contains
/// a `\r\n\r\n` (common in HTML, multipart, or nested-HTTP bodies) must terminate
/// its headers at the real bare-LF boundary — otherwise body bytes would be
/// forged into headers and the body truncated.
fn split_head_body(bytes: &[u8]) -> (&[u8], &[u8]) {
    let crlf = find_subslice(bytes, b"\r\n\r\n");
    let lf = find_subslice(bytes, b"\n\n");
    match (crlf, lf) {
        (Some(c), Some(l)) if c <= l => (&bytes[..c], &bytes[c + 4..]),
        (Some(_), Some(l)) => (&bytes[..l], &bytes[l + 2..]),
        (Some(c), None) => (&bytes[..c], &bytes[c + 4..]),
        (None, Some(l)) => (&bytes[..l], &bytes[l + 2..]),
        (None, None) => (bytes, &[]),
    }
}

/// Drop a single trailing carriage return so CRLF and bare-LF lines parse alike.
fn strip_cr(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

/// Parse header lines into a [`HeaderList`], preserving order, casing, and
/// duplicates. Only the optional leading whitespace after the colon is removed
/// (RFC 7230 OWS); the name is kept byte-for-byte. Lines without a colon are
/// tolerated and skipped.
fn parse_header_lines<'a>(lines: impl Iterator<Item = &'a str>) -> HeaderList {
    let mut headers = HeaderList::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim_start_matches([' ', '\t']);
            headers.push(name, value);
        }
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_preserves_lowercase_and_duplicate_headers() {
        let raw = b"POST /submit HTTP/1.1\r\n\
            Host: example.com\r\n\
            x-custom: alpha\r\n\
            X-Dup: one\r\n\
            X-Dup: two\r\n\
            Content-Length: 5\r\n\
            \r\n\
            hello";
        let req = parse_raw_request(raw, "https://example.com/submit").unwrap();

        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "https://example.com/submit");
        assert_eq!(req.version, HttpVersion::Http11);

        // Lowercase header name is preserved exactly (never canonicalized)...
        assert_eq!(req.headers.0[1].name, "x-custom");
        // ...while case-insensitive lookup still finds it.
        assert_eq!(req.headers.get("X-Custom"), Some("alpha"));

        // Duplicate headers are both retained, in order.
        let dups: Vec<&str> = req.headers.get_all("X-Dup").collect();
        assert_eq!(dups, vec!["one", "two"]);

        // Full order is preserved — never alphabetized.
        let names: Vec<&str> = req.headers.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["Host", "x-custom", "X-Dup", "X-Dup", "Content-Length"]
        );

        assert_eq!(req.body.as_bytes(), b"hello");
    }

    #[test]
    fn response_parses_status_reason_headers_and_body() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\
            Content-Type: text/html\r\n\
            X-Lower: v\r\n\
            \r\n\
            <h1>nope</h1>";
        let resp = parse_raw_response(raw).unwrap();

        assert_eq!(resp.status, 404);
        assert_eq!(resp.reason.as_deref(), Some("Not Found"));
        assert_eq!(resp.version, HttpVersion::Http11);
        assert_eq!(resp.headers.get("content-type"), Some("text/html"));
        assert_eq!(resp.headers.0[1].name, "X-Lower");
        assert_eq!(resp.body.as_text(), "<h1>nope</h1>");
    }

    #[test]
    fn tolerates_bare_lf_line_endings() {
        let raw = b"GET / HTTP/2\nHost: h\n\nbody";
        let req = parse_raw_request(raw, "https://h/").unwrap();
        assert_eq!(req.version, HttpVersion::H2);
        assert_eq!(req.headers.get("Host"), Some("h"));
        assert_eq!(req.body.as_bytes(), b"body");
    }

    #[test]
    fn response_without_reason_phrase() {
        let resp = parse_raw_response(b"HTTP/1.1 204\r\n\r\n").unwrap();
        assert_eq!(resp.status, 204);
        assert_eq!(resp.reason, None);
        assert!(resp.body.is_empty());
    }

    #[test]
    fn header_value_leading_ows_trimmed_tabs_too() {
        let req =
            parse_raw_request(b"GET / HTTP/1.1\r\nX-A:\tvalue\r\n\r\n", "https://h/").unwrap();
        assert_eq!(req.headers.get("X-A"), Some("value"));
    }

    #[test]
    fn version_mapping_covers_known_tokens() {
        assert_eq!(map_http_version("HTTP/1.0"), HttpVersion::Http10);
        assert_eq!(map_http_version("HTTP/1.1"), HttpVersion::Http11);
        assert_eq!(map_http_version("HTTP/2"), HttpVersion::H2);
        assert_eq!(map_http_version("h2"), HttpVersion::H2);
        assert_eq!(map_http_version("HTTP/3"), HttpVersion::H3);
        assert_eq!(map_http_version("h3"), HttpVersion::H3);
        // Unknown falls back to HTTP/1.1.
        assert_eq!(map_http_version("SPDY/3"), HttpVersion::Http11);
    }

    #[test]
    fn empty_input_is_a_typed_error() {
        assert!(matches!(
            parse_raw_request(b"", "https://x/"),
            Err(ImportError::Parse(_))
        ));
        assert!(matches!(
            parse_raw_response(b""),
            Err(ImportError::Parse(_))
        ));
    }

    #[test]
    fn invalid_status_code_is_a_typed_error() {
        assert!(matches!(
            parse_raw_response(b"HTTP/1.1 notnum Oops\r\n\r\n"),
            Err(ImportError::Parse(_))
        ));
    }

    #[test]
    fn chunked_detection() {
        let resp = parse_raw_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        )
        .unwrap();
        assert!(header_has_chunked(&resp.headers));
        // Body kept verbatim (not de-chunked).
        assert_eq!(resp.body.as_text(), "5\r\nhello\r\n0\r\n\r\n");
    }

    #[test]
    fn bare_lf_header_boundary_wins_over_crlfcrlf_in_body() {
        // Bare-LF framed headers; the BODY contains a CRLFCRLF. The real header
        // boundary is the earlier `\n\n`, so Set-Cookie stays in the body and is
        // NOT forged into a header.
        let raw = b"HTTP/1.1 200 OK\nX-Real: 1\n\nSet-Cookie: pwned=1\r\n\r\nactual body";
        let resp = parse_raw_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("X-Real"), Some("1"));
        assert_eq!(
            resp.headers.get("Set-Cookie"),
            None,
            "body bytes must not become headers"
        );
        assert!(resp.body.as_text().starts_with("Set-Cookie: pwned=1"));
    }

    #[test]
    fn find_subslice_basic() {
        assert_eq!(find_subslice(b"abcdef", b"cd"), Some(2));
        assert_eq!(find_subslice(b"abcdef", b"xy"), None);
        assert_eq!(find_subslice(b"ab", b""), Some(0));
    }
}
