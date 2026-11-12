//! Input discovery (plan §8 "Input/API campaigns"; plan §10 "Automatic input
//! discovery and test matrix").
//!
//! Given a captured [`HttpRequest`], enumerate the places a campaign could
//! inject payloads: URL query parameters, URL-encoded body parameters, cookies,
//! a few notable request headers, and the top-level keys of a JSON body. This is
//! pure parsing — it reads a request and reports structure, it does not mutate or
//! send anything.

use camio_core::HttpRequest;
use serde::{Deserialize, Serialize};

/// The kind of input an insertion point was discovered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    /// A `key=value` pair in the URL query string.
    QueryParam,
    /// A `key=value` pair in an `application/x-www-form-urlencoded` body.
    BodyParam,
    /// A cookie from the `Cookie` request header.
    Cookie,
    /// A notable request header (`User-Agent`, `Referer`, `X-Forwarded-For`).
    Header,
    /// A top-level scalar field of an `application/json` body.
    JsonField,
}

/// A single discovered input: where it lives, its name, and its current value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredInput {
    pub kind: InputKind,
    pub name: String,
    pub value: String,
}

impl DiscoveredInput {
    fn new(kind: InputKind, name: impl Into<String>, value: impl Into<String>) -> Self {
        DiscoveredInput {
            kind,
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Request headers worth testing on their own (plan §10: headers are an input
/// surface). Named explicitly rather than fuzzing every header.
const NOTABLE_HEADERS: [&str; 3] = ["User-Agent", "Referer", "X-Forwarded-For"];

/// Enumerate the injectable inputs of `req`, in a stable order: query params,
/// then URL-encoded body params, then cookies, then notable headers, then
/// top-level JSON fields. Query and body names/values are URL-decoded; cookie
/// and header values are reported verbatim.
pub fn discover_inputs(req: &HttpRequest) -> Vec<DiscoveredInput> {
    let mut out = Vec::new();

    // 1. URL query string.
    if let Some(query) = req.query() {
        for (name, value) in parse_pairs(&query) {
            out.push(DiscoveredInput::new(InputKind::QueryParam, name, value));
        }
    }

    let content_type = req.headers.get("Content-Type").unwrap_or("");

    // 2. URL-encoded body.
    if content_type_is(content_type, "application/x-www-form-urlencoded") {
        let body = req.body.as_text();
        for (name, value) in parse_pairs(&body) {
            out.push(DiscoveredInput::new(InputKind::BodyParam, name, value));
        }
    }

    // 3. Cookies (verbatim — cookie values are not URL-encoded).
    if let Some(cookie_header) = req.headers.get("Cookie") {
        for part in cookie_header.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match part.split_once('=') {
                Some((name, value)) => {
                    out.push(DiscoveredInput::new(InputKind::Cookie, name.trim(), value));
                }
                None => out.push(DiscoveredInput::new(InputKind::Cookie, part, "")),
            }
        }
    }

    // 4. Notable headers.
    for name in NOTABLE_HEADERS {
        if let Some(value) = req.headers.get(name) {
            out.push(DiscoveredInput::new(InputKind::Header, name, value));
        }
    }

    // 5. Top-level JSON scalar fields.
    if content_type_is(content_type, "application/json") {
        let body = req.body.as_text();
        if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(&body)
        {
            for (key, value) in map {
                if let Some(scalar) = scalar_to_string(&value) {
                    out.push(DiscoveredInput::new(InputKind::JsonField, key, scalar));
                }
            }
        }
    }

    out
}

/// Match a `Content-Type` header value against a bare media type, ignoring any
/// `; charset=…` parameters and case.
fn content_type_is(ct: &str, want: &str) -> bool {
    ct.split(';')
        .next()
        .map(|media| media.trim().eq_ignore_ascii_case(want))
        .unwrap_or(false)
}

/// Parse `k=v&k2=v2` pairs, URL-decoding both names and values. Pairs with no
/// `=` are reported with an empty value; empty segments are skipped.
fn parse_pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

/// Percent-decode an `application/x-www-form-urlencoded` token: `%XX` escapes
/// become their byte, `+` becomes a space, everything else is literal. Invalid
/// escapes are left as-is. Decoded bytes are interpreted as UTF-8 (lossy), so
/// multi-byte characters survive.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push(hi * 16 + lo);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
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

/// Stringify a JSON scalar; non-scalars (objects/arrays) return `None` so only
/// flat top-level fields are discovered.
fn scalar_to_string(value: &serde_json::Value) -> Option<String> {
    use serde_json::Value;
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some("null".to_string()),
        Value::Object(_) | Value::Array(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::Body;

    fn find<'a>(inputs: &'a [DiscoveredInput], kind: InputKind, name: &str) -> &'a DiscoveredInput {
        inputs
            .iter()
            .find(|i| i.kind == kind && i.name == name)
            .unwrap_or_else(|| panic!("no {kind:?} named {name}"))
    }

    #[test]
    fn discovers_query_params_url_decoded() {
        let req = HttpRequest::get("https://x.test/s?q=hello+world&p=a%2Fb&flag");
        let inputs = discover_inputs(&req);
        assert_eq!(
            find(&inputs, InputKind::QueryParam, "q").value,
            "hello world"
        );
        assert_eq!(find(&inputs, InputKind::QueryParam, "p").value, "a/b");
        assert_eq!(find(&inputs, InputKind::QueryParam, "flag").value, "");
    }

    #[test]
    fn discovers_cookies() {
        let mut req = HttpRequest::get("https://x.test/");
        req.headers
            .push("Cookie", "session=abc123; theme=dark; flag");
        let inputs = discover_inputs(&req);
        assert_eq!(find(&inputs, InputKind::Cookie, "session").value, "abc123");
        assert_eq!(find(&inputs, InputKind::Cookie, "theme").value, "dark");
        assert_eq!(find(&inputs, InputKind::Cookie, "flag").value, "");
    }

    #[test]
    fn discovers_notable_headers_only() {
        let mut req = HttpRequest::get("https://x.test/");
        req.headers.push("User-Agent", "Mozilla/5.0");
        req.headers.push("Referer", "https://ref.test/");
        req.headers.push("X-Forwarded-For", "10.0.0.1");
        req.headers.push("Accept", "*/*"); // not notable
        let inputs = discover_inputs(&req);
        assert_eq!(
            find(&inputs, InputKind::Header, "User-Agent").value,
            "Mozilla/5.0"
        );
        assert_eq!(
            find(&inputs, InputKind::Header, "Referer").value,
            "https://ref.test/"
        );
        assert_eq!(
            find(&inputs, InputKind::Header, "X-Forwarded-For").value,
            "10.0.0.1"
        );
        assert!(!inputs.iter().any(|i| i.name == "Accept"));
    }

    #[test]
    fn discovers_urlencoded_body_params() {
        let mut req = HttpRequest::get("https://x.test/login");
        req.method = "POST".into();
        req.headers
            .push("Content-Type", "application/x-www-form-urlencoded");
        req.body = Body::from_text("user=admin&pass=p%40ss+word");
        let inputs = discover_inputs(&req);
        assert_eq!(find(&inputs, InputKind::BodyParam, "user").value, "admin");
        assert_eq!(
            find(&inputs, InputKind::BodyParam, "pass").value,
            "p@ss word"
        );
    }

    #[test]
    fn discovers_json_scalar_fields_but_not_nested() {
        let mut req = HttpRequest::get("https://x.test/api");
        req.method = "POST".into();
        req.headers
            .push("Content-Type", "application/json; charset=utf-8");
        req.body = Body::from_text(
            r#"{"name":"bob","age":30,"active":true,"opt":null,"nested":{"a":1},"list":[1,2]}"#,
        );
        let inputs = discover_inputs(&req);
        assert_eq!(find(&inputs, InputKind::JsonField, "name").value, "bob");
        assert_eq!(find(&inputs, InputKind::JsonField, "age").value, "30");
        assert_eq!(find(&inputs, InputKind::JsonField, "active").value, "true");
        assert_eq!(find(&inputs, InputKind::JsonField, "opt").value, "null");
        // Nested object and array are not flat scalars.
        assert!(!inputs.iter().any(|i| i.name == "nested"));
        assert!(!inputs.iter().any(|i| i.name == "list"));
    }

    #[test]
    fn combined_request_with_query_cookies_and_json() {
        let mut req = HttpRequest::get("https://x.test/api?debug=1");
        req.method = "POST".into();
        req.headers.push("Content-Type", "application/json");
        req.headers.push("Cookie", "sid=xyz");
        req.body = Body::from_text(r#"{"q":"search term"}"#);
        let inputs = discover_inputs(&req);
        assert_eq!(find(&inputs, InputKind::QueryParam, "debug").value, "1");
        assert_eq!(find(&inputs, InputKind::Cookie, "sid").value, "xyz");
        assert_eq!(
            find(&inputs, InputKind::JsonField, "q").value,
            "search term"
        );
    }

    #[test]
    fn body_not_parsed_without_matching_content_type() {
        let mut req = HttpRequest::get("https://x.test/");
        req.method = "POST".into();
        // No Content-Type: neither urlencoded nor JSON parsing fires.
        req.body = Body::from_text("a=1&b=2");
        let inputs = discover_inputs(&req);
        assert!(!inputs.iter().any(|i| i.kind == InputKind::BodyParam));
        assert!(!inputs.iter().any(|i| i.kind == InputKind::JsonField));
    }

    #[test]
    fn malformed_json_body_yields_no_json_fields() {
        let mut req = HttpRequest::get("https://x.test/");
        req.method = "POST".into();
        req.headers.push("Content-Type", "application/json");
        req.body = Body::from_text("{not valid json");
        let inputs = discover_inputs(&req);
        assert!(!inputs.iter().any(|i| i.kind == InputKind::JsonField));
    }

    #[test]
    fn percent_decode_handles_invalid_escapes() {
        assert_eq!(percent_decode("a%2z"), "a%2z"); // bad hex left literal
        assert_eq!(percent_decode("x%"), "x%"); // trailing percent
        assert_eq!(percent_decode("%41%42"), "AB");
    }

    #[test]
    fn content_type_match_ignores_params_and_case() {
        assert!(content_type_is(
            "Application/JSON; charset=utf-8",
            "application/json"
        ));
        assert!(content_type_is(
            "application/x-www-form-urlencoded",
            "application/x-www-form-urlencoded"
        ));
        assert!(!content_type_is("text/html", "application/json"));
    }

    #[test]
    fn discovered_input_serde_roundtrips() {
        let di = DiscoveredInput::new(InputKind::QueryParam, "q", "v");
        let json = serde_json::to_string(&di).unwrap();
        let back: DiscoveredInput = serde_json::from_str(&json).unwrap();
        assert_eq!(di, back);
        // snake_case tag on the kind.
        assert!(json.contains("query_param"));
    }
}
