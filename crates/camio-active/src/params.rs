//! Parameter discovery and rewriting for probe construction (plan §10
//! "Automatic input discovery and test matrix").
//!
//! Active checks target one input at a time: they clone the base request and
//! replace a single query or body parameter's value with a probe, preserving
//! every other part of the request byte-for-byte. The rewriting is hand-rolled
//! (plan §14 "prefer std / hand-rolling") so it keeps the original ordering and
//! percent-encoding of the untouched parameters and never canonicalizes the URL.

use camio_automate::{discover_inputs, InputKind};
use camio_core::{Body, HttpRequest};

/// Enumerate a request's injectable query and body parameters as `(kind, name)`
/// pairs — a thin wrapper over [`camio_automate::discover_inputs`] filtered to
/// [`InputKind::QueryParam`] and [`InputKind::BodyParam`].
///
/// Cookies, headers and JSON fields are intentionally excluded: the built-in
/// active checks probe only the query string and `application/x-www-form-
/// urlencoded` body. Order follows `discover_inputs` (query params first, then
/// body params); duplicates are not collapsed here (callers that send probes
/// de-duplicate before sending).
pub fn discovered_params(base: &HttpRequest) -> Vec<(InputKind, String)> {
    discover_inputs(base)
        .into_iter()
        .filter(|i| matches!(i.kind, InputKind::QueryParam | InputKind::BodyParam))
        .map(|i| (i.kind, i.name))
        .collect()
}

/// Replace the value of query parameter `name` in `url` with `value`, or append
/// `name=value` if it is not already present. The `value` is percent-encoded.
///
/// Everything else is preserved: the scheme/host/path, the URL fragment, and the
/// original text (including the original percent-encoding) of every other query
/// parameter. The first occurrence of `name` is the one replaced; any later
/// same-named pairs are left untouched. Matching is done on the URL-decoded key,
/// so an encoded key (`na%6de`) still matches `name`.
///
/// ```
/// use camio_active::set_query_param;
/// assert_eq!(
///     set_query_param("https://x.test/s?q=hello&p=2", "q", "new value"),
///     "https://x.test/s?q=new%20value&p=2"
/// );
/// assert_eq!(
///     set_query_param("https://x.test/s?q=hello", "r", "v"),
///     "https://x.test/s?q=hello&r=v"
/// );
/// ```
pub fn set_query_param(url: &str, name: &str, value: &str) -> String {
    let (before_fragment, fragment) = split_fragment(url);
    let (base, query) = split_query(before_fragment);
    let rebuilt = replace_or_append_pairs(query.unwrap_or(""), name, value);

    let mut out = String::with_capacity(url.len() + value.len() + 3);
    out.push_str(base);
    if !rebuilt.is_empty() {
        out.push('?');
        out.push_str(&rebuilt);
    }
    out.push_str(fragment);
    out
}

/// Clone `base` and set the parameter `(kind, name)` to `value`, rebuilding the
/// URL query or the urlencoded body as appropriate. Any other [`InputKind`] is
/// returned as an unmodified clone (the active checks only pass query/body
/// inputs). Headers — including `Content-Type` — and their order are preserved.
pub(crate) fn with_param(
    base: &HttpRequest,
    kind: InputKind,
    name: &str,
    value: &str,
) -> HttpRequest {
    let mut req = base.clone();
    match kind {
        InputKind::QueryParam => {
            req.url = set_query_param(&base.url, name, value);
        }
        InputKind::BodyParam => {
            let rebuilt = replace_or_append_pairs(&base.body.as_text(), name, value);
            req.body = Body::from_text(rebuilt);
        }
        InputKind::Cookie | InputKind::Header | InputKind::JsonField => {}
    }
    req
}

/// De-duplicate `(kind, name)` pairs, preserving first-seen order. Checks use
/// this so a parameter that appears twice (`?q=1&q=2`) is probed only once,
/// keeping the per-input probe budget honest (plan §15).
pub(crate) fn dedup_params(params: Vec<(InputKind, String)>) -> Vec<(InputKind, String)> {
    let mut seen: Vec<(InputKind, String)> = Vec::new();
    for p in params {
        if !seen.contains(&p) {
            seen.push(p);
        }
    }
    seen
}

// ---------------------------------------------------------------------------
// Internal string surgery
// ---------------------------------------------------------------------------

/// Split a URL into `(before_fragment, fragment)` at the first `#`. The returned
/// fragment includes the `#`, or is `""` when there is none.
fn split_fragment(url: &str) -> (&str, &str) {
    match url.find('#') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, ""),
    }
}

/// Split a fragment-free URL into `(base, query)` at the first `?`. The query (if
/// present) excludes the `?`.
fn split_query(s: &str) -> (&str, Option<&str>) {
    match s.find('?') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

/// Rebuild a `k=v&k2=v2` pair string, replacing the first pair whose decoded key
/// equals `name` (its key text is kept verbatim, its value replaced with the
/// percent-encoded `value`) or appending `encode(name)=encode(value)` if absent.
/// Other pairs are copied verbatim; empty segments are dropped.
fn replace_or_append_pairs(pairs: &str, name: &str, value: &str) -> String {
    let encoded_value = percent_encode(value);
    let mut segments: Vec<String> = Vec::new();
    let mut replaced = false;
    for seg in pairs.split('&') {
        if seg.is_empty() {
            continue;
        }
        let key = match seg.split_once('=') {
            Some((k, _)) => k,
            None => seg,
        };
        if !replaced && decode_component(key) == name {
            segments.push(format!("{key}={encoded_value}"));
            replaced = true;
        } else {
            segments.push(seg.to_string());
        }
    }
    if !replaced {
        segments.push(format!("{}={}", percent_encode(name), encoded_value));
    }
    segments.join("&")
}

/// Percent-encode a query/body component: unreserved characters
/// (`A-Za-z0-9-._~`) pass through, every other byte becomes upper-case `%XX`.
/// Spaces become `%20` (not `+`), so the encoding is unambiguous when later
/// decoded by either convention.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(hex_digit(b >> 4));
                out.push(hex_digit(b & 0x0f));
            }
        }
    }
    out
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'A' + (n - 10)) as char,
    }
}

/// Decode an `application/x-www-form-urlencoded` component for key comparison:
/// `+` becomes a space and `%XX` becomes its byte; invalid escapes are kept
/// verbatim. This mirrors [`camio_automate::discover_inputs`]' decoding so a
/// discovered parameter name matches the key it was discovered from.
fn decode_component(s: &str) -> String {
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
            c => {
                out.push(c);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_existing_query_param() {
        assert_eq!(
            set_query_param("https://x.test/s?q=hello&p=2", "q", "NEW"),
            "https://x.test/s?q=NEW&p=2"
        );
        // Replacing a later-positioned param keeps the earlier ones verbatim.
        assert_eq!(
            set_query_param("https://x.test/s?a=1&q=hello", "q", "NEW"),
            "https://x.test/s?a=1&q=NEW"
        );
    }

    #[test]
    fn appends_absent_query_param() {
        assert_eq!(
            set_query_param("https://x.test/s?q=hello", "r", "v"),
            "https://x.test/s?q=hello&r=v"
        );
        // No query string at all -> introduce one.
        assert_eq!(
            set_query_param("https://x.test/s", "r", "v"),
            "https://x.test/s?r=v"
        );
    }

    #[test]
    fn percent_encodes_the_value() {
        assert_eq!(
            set_query_param("https://x.test/s", "x", "a b<>\""),
            "https://x.test/s?x=a%20b%3C%3E%22"
        );
        // The full XSS probe round-trips to a valid, fully-encoded value.
        assert_eq!(
            set_query_param(
                "https://x.test/s?q=1",
                "q",
                "camioX55\"'><svg/onload=camio>"
            ),
            "https://x.test/s?q=camioX55%22%27%3E%3Csvg%2Fonload%3Dcamio%3E"
        );
    }

    #[test]
    fn preserves_fragment_and_other_param_encoding() {
        // Fragment is kept, and the untouched `a=%20` keeps its original encoding.
        assert_eq!(
            set_query_param("https://x.test/s?a=%20&q=1#frag", "q", "2"),
            "https://x.test/s?a=%20&q=2#frag"
        );
    }

    #[test]
    fn matches_encoded_key() {
        // `na%6de` decodes to `name`, so it is the pair that gets replaced.
        assert_eq!(
            set_query_param("https://x.test/s?na%6de=old", "name", "new"),
            "https://x.test/s?na%6de=new"
        );
    }

    #[test]
    fn replaces_only_the_first_duplicate() {
        assert_eq!(
            set_query_param("https://x.test/s?q=1&q=2", "q", "X"),
            "https://x.test/s?q=X&q=2"
        );
    }

    #[test]
    fn discovered_params_keeps_query_and_body_only() {
        let mut req = HttpRequest::get("https://x.test/search?q=1&page=2");
        req.method = "POST".into();
        req.headers
            .push("Content-Type", "application/x-www-form-urlencoded");
        req.headers.push("Cookie", "sid=abc");
        req.headers.push("User-Agent", "Mozilla/5.0");
        req.body = Body::from_text("a=1&b=2");
        let params = discovered_params(&req);
        assert!(params.contains(&(InputKind::QueryParam, "q".to_string())));
        assert!(params.contains(&(InputKind::QueryParam, "page".to_string())));
        assert!(params.contains(&(InputKind::BodyParam, "a".to_string())));
        assert!(params.contains(&(InputKind::BodyParam, "b".to_string())));
        // Cookies and headers are excluded.
        assert!(!params.iter().any(|(k, _)| *k == InputKind::Cookie));
        assert!(!params.iter().any(|(k, _)| *k == InputKind::Header));
    }

    #[test]
    fn with_param_rewrites_query_without_touching_headers() {
        let mut base = HttpRequest::get("https://x.test/s?q=hello");
        base.headers.push("User-Agent", "UA");
        base.headers.push("Accept", "*/*");
        let req = with_param(&base, InputKind::QueryParam, "q", "PROBE");
        assert_eq!(req.url, "https://x.test/s?q=PROBE");
        // Headers preserved, in order.
        assert_eq!(req.headers.0[0].name, "User-Agent");
        assert_eq!(req.headers.0[1].name, "Accept");
    }

    #[test]
    fn with_param_rewrites_urlencoded_body() {
        let mut base = HttpRequest::get("https://x.test/login");
        base.method = "POST".into();
        base.headers
            .push("Content-Type", "application/x-www-form-urlencoded");
        base.body = Body::from_text("user=admin&pass=secret");
        let req = with_param(&base, InputKind::BodyParam, "pass", "PROBE");
        assert_eq!(req.body.as_text(), "user=admin&pass=PROBE");
        // URL untouched.
        assert_eq!(req.url, "https://x.test/login");
    }

    #[test]
    fn dedup_params_collapses_repeats_in_order() {
        let input = vec![
            (InputKind::QueryParam, "q".to_string()),
            (InputKind::QueryParam, "q".to_string()),
            (InputKind::BodyParam, "q".to_string()),
            (InputKind::QueryParam, "p".to_string()),
        ];
        let out = dedup_params(input);
        assert_eq!(
            out,
            vec![
                (InputKind::QueryParam, "q".to_string()),
                (InputKind::BodyParam, "q".to_string()),
                (InputKind::QueryParam, "p".to_string()),
            ]
        );
    }

    #[test]
    fn percent_encode_leaves_unreserved_untouched() {
        assert_eq!(percent_encode("aZ09-._~"), "aZ09-._~");
        assert_eq!(percent_encode("a/b?c=d&e"), "a%2Fb%3Fc%3Dd%26e");
    }

    #[test]
    fn decode_component_matches_discovery_semantics() {
        assert_eq!(decode_component("a+b"), "a b");
        assert_eq!(decode_component("%41%42"), "AB");
        assert_eq!(decode_component("a%2z"), "a%2z"); // invalid escape kept
    }
}
