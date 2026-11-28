//! Input discovery (plan §8 "Input/API campaigns"; plan §10 "Automatic input
//! discovery and test matrix").
//!
//! Given a captured [`HttpRequest`], enumerate the places a campaign could
//! inject payloads: URL query parameters, URL-encoded body parameters, cookies,
//! a few notable request headers, and the top-level keys of a JSON body. This is
//! pure parsing — it reads a request and reports structure, it does not mutate or
//! send anything.

use crate::encoding::InputContext;
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
    /// The text content of an element in an `application/xml` / `text/xml` body,
    /// addressed by its element path (`root.item`).
    XmlText,
    /// An attribute value of an element in an XML body, addressed as
    /// `path@attr`.
    XmlAttr,
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

    /// Smart-detect the [`InputContext`] for this input given its containing
    /// request. Used by the dynamic encoded-payload expander to pick the right
    /// encoding set.
    ///
    /// Heuristics:
    /// * `QueryParam` → `UrlQuery`
    /// * `BodyParam` → `FormUrlencoded`
    /// * `Cookie` → `HttpCookie`
    /// * `Header` → `HttpHeaderValue`
    /// * `JsonField` → `JsonString`, unless the value parses as a number →
    ///   `JsonNumber`
    // The request is not needed to classify the input position, and the
    // signature is fixed by the campaign API.
    // audit-allow: B13
    pub fn detect_context(&self, _req: &HttpRequest) -> InputContext {
        match self.kind {
            InputKind::QueryParam => InputContext::UrlQuery,
            InputKind::BodyParam => InputContext::FormUrlencoded,
            InputKind::Cookie => InputContext::HttpCookie,
            InputKind::Header => InputContext::HttpHeaderValue,
            InputKind::JsonField => {
                // Only a *strict* integer is a JSON number: `f64::parse` also
                // accepts "inf", "NaN", "1e5" and "30" in a string slot, which
                // would send an XSS payload into a JSON string with no string
                // escaping (invalid JSON, wasted probe).
                if is_strict_integer(&self.value) {
                    InputContext::JsonNumber
                } else {
                    InputContext::JsonString
                }
            }
            InputKind::XmlText => InputContext::XmlText,
            InputKind::XmlAttr => InputContext::XmlAttribute,
        }
    }
}

/// A strict JSON integer: optional `-`, then digits only. Not `f64`-parseable
/// strings ("inf", "NaN", "1e5", "1.5") and not string slots that happen to
/// contain digits.
fn is_strict_integer(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Smart context detection from the request alone — for callers that don't
/// have a [`DiscoveredInput`] yet. Inspects `Content-Type` and known XML/JSON/
/// GraphQL hints.
pub fn detect_body_context(req: &HttpRequest) -> InputContext {
    let ct = req
        .headers
        .get("Content-Type")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if ct.contains("application/json") || ct.contains("+json") {
        return InputContext::JsonString;
    }
    if ct.contains("application/xml") || ct.contains("text/xml") || ct.contains("+xml") {
        return InputContext::XmlText;
    }
    if ct.contains("application/x-www-form-urlencoded") {
        return InputContext::FormUrlencoded;
    }
    if ct.contains("multipart/form-data") {
        return InputContext::Multipart;
    }
    if ct.contains("application/graphql") || req.url.contains("/graphql") {
        return InputContext::GraphqlString;
    }
    if ct.contains("text/html") {
        return InputContext::HtmlBody;
    }
    InputContext::Raw
}

/// Request headers worth testing on their own (plan §10: headers are an input
/// surface). Named explicitly rather than fuzzing every header.
const NOTABLE_HEADERS: [&str; 4] = ["User-Agent", "Referer", "X-Forwarded-For", "Authorization"];

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

    // 2b. Multipart form: parse the boundary and each part's name/value (a
    // multipart upload form previously yielded no inputs at all).
    if content_type_is(content_type, "multipart/form-data") {
        if let Some(boundary) = multipart_boundary(content_type) {
            for (name, value) in parse_multipart(&req.body.as_text(), &boundary) {
                out.push(DiscoveredInput::new(InputKind::BodyParam, name, value));
            }
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

    // 4. Notable headers — every value of a repeated header, not just the first
    // (each is a distinct input position).
    for name in NOTABLE_HEADERS {
        for value in req.headers.get_all(name) {
            out.push(DiscoveredInput::new(InputKind::Header, name, value));
        }
    }

    // 5. JSON fields, including arrays of objects (`[{...},{...}]` — a REST
    // collection body) and nested objects of scalars. Elements are addressed
    // with `items.0.id`-style paths so their location is preserved.
    if content_type_is(content_type, "application/json") {
        let body = req.body.as_text();
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(value) => collect_json_fields(&value, "", &mut out),
            // A JSON body that does not parse is unusual and means this whole
            // input-context class was missed.
            Err(e) => eprintln!(
                "camio: {} declares JSON but its body did not parse: {e}",
                req.url
            ),
        }
    }

    // 6. XML element text and attribute values (SOAP, XML-RPC, REST+XML). Each
    // injection point is addressed by its nested element path (`order.item`) with
    // attributes as `order.item@sku`, so a campaign can target a precise node.
    if content_type_is(content_type, "application/xml")
        || content_type_is(content_type, "text/xml")
        || content_type.contains("+xml")
    {
        collect_xml_inputs(&req.body.as_text(), &mut out);
    }

    out
}

/// Enumerate XML element text and attribute values as injection points. Uses the
/// hardened `quick-xml` reader (entity/CDATA aware); a parse error simply stops
/// enumeration rather than panicking (a malformed XML body is the caller's to
/// report, not this function's). Repeated sibling elements of the same name get a
/// positional suffix (`item`, `item.1`) so each node is addressable.
fn collect_xml_inputs(body: &str, out: &mut Vec<DiscoveredInput>) {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(body);
    reader.config_mut().trim_text(true);
    // `path` is the stack of open element segments; `seen` counts same-name
    // siblings per depth so repeated nodes get distinct addresses.
    let mut path: Vec<String> = Vec::new();
    let mut seen: Vec<std::collections::HashMap<String, usize>> = vec![Default::default()];
    let mut buf = Vec::new();

    // Compute the addressable segment for an element at the current depth and
    // advance the sibling counter.
    fn next_segment(
        seen: &mut [std::collections::HashMap<String, usize>],
        name: String,
    ) -> String {
        let depth_seen = seen.last_mut().expect("a depth frame is always present");
        let n = depth_seen.entry(name.clone()).or_insert(0);
        let seg = if *n == 0 {
            name
        } else {
            format!("{name}.{n}")
        };
        *n += 1;
        seg
    }

    // Emit every attribute of an element as an `XmlAttr` input at `elem_path`.
    fn emit_attrs(
        e: &quick_xml::events::BytesStart<'_>,
        elem_path: &str,
        out: &mut Vec<DiscoveredInput>,
    ) {
        for attr in e.attributes().flatten() {
            let attr_name =
                String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
            // Raw attribute value (charset-lossy). Attribute values rarely carry
            // entities and are used here as a current-value label, so a lossy
            // decode is sufficient and avoids borrowing the reader's decoder.
            let value = String::from_utf8_lossy(attr.value.as_ref()).to_string();
            out.push(DiscoveredInput::new(
                InputKind::XmlAttr,
                format!("{elem_path}@{attr_name}"),
                value,
            ));
        }
    }

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                let seg = next_segment(&mut seen, name);
                let elem_path = join_path(&path.join("."), &seg);
                emit_attrs(&e, &elem_path, out);
                // A Start element opens a frame; its text and children follow.
                path.push(seg);
                seen.push(Default::default());
            }
            Ok(Event::Empty(e)) => {
                // Self-closing `<x a="1"/>`: attributes only, no text, and it
                // does NOT open a frame (there is no matching End).
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                let seg = next_segment(&mut seen, name);
                let elem_path = join_path(&path.join("."), &seg);
                emit_attrs(&e, &elem_path, out);
            }
            Ok(Event::Text(t)) => {
                // `xml10_content` decodes the charset and resolves XML entities
                // (quick-xml 0.41 replaced `BytesText::unescape` with this).
                let text = t.xml10_content().map(|v| v.to_string()).unwrap_or_default();
                if !text.trim().is_empty() && !path.is_empty() {
                    out.push(DiscoveredInput::new(InputKind::XmlText, path.join("."), text));
                }
            }
            Ok(Event::CData(c)) => {
                let text = String::from_utf8_lossy(c.as_ref()).to_string();
                if !text.trim().is_empty() && !path.is_empty() {
                    out.push(DiscoveredInput::new(InputKind::XmlText, path.join("."), text));
                }
            }
            Ok(Event::End(_)) => {
                path.pop();
                seen.pop();
            }
            Ok(Event::Eof) => break,
            Err(_) => break, // tolerant: stop enumerating on malformed XML
            _ => {}
        }
        buf.clear();
    }
}

/// Rewrite one XML injection point in `body` and return the new document, or
/// `None` if the body is not parseable XML or the addressed node does not exist
/// (so a failed rewrite sends the base request unchanged rather than a corrupted
/// one — the same contract as [`crate::params`]-style JSON rewriting).
///
/// `name` is the address [`discover_inputs`] produced: an element path
/// (`order.item`) targets that element's text, and a `path@attr` form
/// (`order.item@sku`) targets that attribute's value. The payload is XML-escaped
/// by the writer; every other byte of structure is echoed faithfully.
pub fn set_xml_input(body: &str, name: &str, value: &str) -> Option<String> {
    use quick_xml::events::{BytesCData, BytesStart, BytesText, Event};
    use quick_xml::{Reader, Writer};

    let (target_path, target_attr) = match name.split_once('@') {
        Some((p, a)) => (p.to_string(), Some(a.to_string())),
        None => (name.to_string(), None),
    };

    let mut reader = Reader::from_str(body);
    let mut writer = Writer::new(Vec::new());
    let mut path: Vec<String> = Vec::new();
    let mut seen: Vec<std::collections::HashMap<String, usize>> = vec![Default::default()];
    let mut buf = Vec::new();
    let mut replaced = false;

    // The addressable segment for an element at the current depth (advances the
    // sibling counter) — must match `collect_xml_inputs` exactly.
    fn next_segment(
        seen: &mut [std::collections::HashMap<String, usize>],
        name: String,
    ) -> String {
        let depth_seen = seen.last_mut().expect("a depth frame is always present");
        let n = depth_seen.entry(name.clone()).or_insert(0);
        let seg = if *n == 0 { name } else { format!("{name}.{n}") };
        *n += 1;
        seg
    }

    // Rebuild a start/empty element, replacing one attribute's value if this is
    // the targeted element and attribute.
    let rebuild_with_attr =
        |e: &BytesStart<'_>, attr: &str, value: &str| -> Option<BytesStart<'static>> {
            let attrs: Vec<_> = e.attributes().collect::<Result<_, _>>().ok()?;
            let mut owned = e.to_owned();
            owned.clear_attributes();
            let mut hit = false;
            for a in &attrs {
                let local = String::from_utf8_lossy(a.key.local_name().as_ref()).to_string();
                let key = String::from_utf8_lossy(a.key.as_ref()).to_string();
                if local == attr {
                    owned.push_attribute((key.as_str(), value));
                    hit = true;
                } else {
                    let v = String::from_utf8_lossy(a.value.as_ref()).to_string();
                    owned.push_attribute((key.as_str(), v.as_str()));
                }
            }
            hit.then_some(owned)
        };

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let tag = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                let seg = next_segment(&mut seen, tag);
                let elem_path = join_path(&path.join("."), &seg);
                if !replaced {
                    if let Some(attr) = &target_attr {
                        if elem_path == target_path {
                            if let Some(rebuilt) = rebuild_with_attr(&e, attr, value) {
                                writer.write_event(Event::Start(rebuilt)).ok()?;
                                replaced = true;
                                path.push(seg);
                                seen.push(Default::default());
                                buf.clear();
                                continue;
                            }
                        }
                    }
                }
                writer.write_event(Event::Start(e.into_owned())).ok()?;
                path.push(seg);
                seen.push(Default::default());
            }
            Ok(Event::Empty(e)) => {
                let tag = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                let seg = next_segment(&mut seen, tag);
                let elem_path = join_path(&path.join("."), &seg);
                if !replaced && target_attr.is_some() && elem_path == target_path {
                    if let Some(rebuilt) =
                        rebuild_with_attr(&e, target_attr.as_deref().unwrap(), value)
                    {
                        writer.write_event(Event::Empty(rebuilt)).ok()?;
                        replaced = true;
                        buf.clear();
                        continue;
                    }
                }
                writer.write_event(Event::Empty(e.into_owned())).ok()?;
            }
            Ok(Event::Text(t)) => {
                let raw = t.xml10_content().map(|v| v.to_string()).unwrap_or_default();
                if !replaced
                    && target_attr.is_none()
                    && !raw.trim().is_empty()
                    && path.join(".") == target_path
                {
                    writer.write_event(Event::Text(BytesText::new(value))).ok()?;
                    replaced = true;
                } else {
                    writer.write_event(Event::Text(t.into_owned())).ok()?;
                }
            }
            Ok(Event::CData(c)) => {
                let raw = String::from_utf8_lossy(c.as_ref());
                if !replaced
                    && target_attr.is_none()
                    && !raw.trim().is_empty()
                    && path.join(".") == target_path
                {
                    writer.write_event(Event::CData(BytesCData::new(value))).ok()?;
                    replaced = true;
                } else {
                    writer.write_event(Event::CData(c.into_owned())).ok()?;
                }
            }
            Ok(Event::End(e)) => {
                path.pop();
                seen.pop();
                writer.write_event(Event::End(e.into_owned())).ok()?;
            }
            Ok(Event::Eof) => break,
            Ok(other) => {
                writer.write_event(other.into_owned()).ok()?;
            }
            Err(_) => return None, // malformed XML: don't ship a half-rewritten body
        }
        buf.clear();
    }

    if !replaced {
        return None;
    }
    String::from_utf8(writer.into_inner()).ok()
}

/// Collect scalar JSON fields (and arrays/nested objects of them) as inputs,
/// preserving location with dotted paths (`user.name`, `items.0.id`).
fn collect_json_fields(value: &serde_json::Value, prefix: &str, out: &mut Vec<DiscoveredInput>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                let path = join_path(prefix, key);
                match value {
                    serde_json::Value::Array(items) => {
                        for (i, item) in items.iter().enumerate() {
                            collect_json_fields(item, &join_path(&path, &i.to_string()), out);
                        }
                    }
                    serde_json::Value::Object(_) => {
                        collect_json_fields(value, &path, out);
                    }
                    other => {
                        if let Some(scalar) = scalar_to_string(other) {
                            out.push(DiscoveredInput::new(InputKind::JsonField, path, scalar));
                        }
                    }
                }
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                collect_json_fields(item, &join_path(prefix, &i.to_string()), out);
            }
        }
        other => {
            if let Some(scalar) = scalar_to_string(other) {
                out.push(DiscoveredInput::new(
                    InputKind::JsonField,
                    prefix.to_string(),
                    scalar,
                ));
            }
        }
    }
}

fn join_path(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}.{key}")
    }
}

/// Match a `Content-Type` header value against a bare media type, ignoring any
/// `; charset=…` parameters and case.
/// Extract the `boundary` parameter from a `multipart/form-data` Content-Type.
fn multipart_boundary(content_type: &str) -> Option<String> {
    for param in content_type.split(';').skip(1) {
        let Some((key, value)) = param.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("boundary") {
            let value = value.trim().trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Parse `multipart/form-data` parts into `(name, value)` pairs.
///
/// Reads each part's `Content-Disposition` `name` (and `filename` as a
/// file-upload input position) and its text body. A part whose headers or name
/// cannot be read is skipped rather than guessed at; a file part's testable
/// position is its filename, not its bytes.
fn parse_multipart(body: &str, boundary: &str) -> Vec<(String, String)> {
    let delimiter = format!("--{boundary}");
    let mut out = Vec::new();
    for section in body.split(&delimiter) {
        let section = section.trim_start_matches("\r\n");
        if section.is_empty() || section.starts_with("--") {
            continue; // preamble / closing delimiter
        }
        let Some((head, value)) = section.split_once("\r\n\r\n") else {
            continue;
        };
        let mut name = None;
        let mut filename = None;
        for line in head.split("\r\n") {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if !key.trim().eq_ignore_ascii_case("content-disposition") {
                continue;
            }
            for param in value.split(';') {
                let Some((k, v)) = param.split_once('=') else {
                    continue;
                };
                let v = v.trim().trim_matches('"');
                match k.trim().to_ascii_lowercase().as_str() {
                    "name" => name = Some(v.to_string()),
                    "filename" => filename = Some(v.to_string()),
                    _ => {}
                }
            }
        }
        let Some(name) = name else {
            continue;
        };
        let value = value.trim_end_matches("\r\n");
        out.push((name, filename.unwrap_or_else(|| value.to_string())));
    }
    out
}

fn content_type_is(ct: &str, want: &str) -> bool {
    ct.split(';')
        .next()
        .map(|media| media.trim().eq_ignore_ascii_case(want))
        .unwrap_or(false)
}

/// Parse `k=v&k2=v2` pairs, URL-decoding both names and values. Pairs with no
/// `=` are reported with an empty value; empty segments are skipped.
fn parse_pairs(s: &str) -> Vec<(String, String)> {
    // Legacy form encoders separate pairs with `;` as well as `&`; splitting on
    // `&` alone turns `a=1;b=2` into one unusable pair.
    s.split(['&', ';'])
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
    fn discovers_xml_text_and_attribute_inputs() {
        let mut req = HttpRequest::get("https://x.test/soap");
        req.method = "POST".into();
        req.headers.push("Content-Type", "application/xml");
        req.body = Body::from_text(
            r#"<order id="7"><item sku="A1">Widget</item><item sku="B2">Gadget</item><note>see notes</note></order>"#,
        );
        let inputs = discover_inputs(&req);
        // Attributes addressed as path@attr, with repeated siblings disambiguated.
        assert_eq!(find(&inputs, InputKind::XmlAttr, "order@id").value, "7");
        assert_eq!(find(&inputs, InputKind::XmlAttr, "order.item@sku").value, "A1");
        assert_eq!(
            find(&inputs, InputKind::XmlAttr, "order.item.1@sku").value,
            "B2"
        );
        // Element text addressed by its element path.
        assert_eq!(find(&inputs, InputKind::XmlText, "order.item").value, "Widget");
        assert_eq!(
            find(&inputs, InputKind::XmlText, "order.item.1").value,
            "Gadget"
        );
        assert_eq!(find(&inputs, InputKind::XmlText, "order.note").value, "see notes");
        // XML text picks the XmlText encoding context; attrs pick XmlAttribute.
        assert_eq!(
            find(&inputs, InputKind::XmlText, "order.item").detect_context(&req),
            InputContext::XmlText
        );
        assert_eq!(
            find(&inputs, InputKind::XmlAttr, "order@id").detect_context(&req),
            InputContext::XmlAttribute
        );
    }

    #[test]
    fn xml_cdata_and_empty_elements_are_handled() {
        let mut req = HttpRequest::get("https://x.test/rpc");
        req.method = "POST".into();
        req.headers.push("Content-Type", "text/xml");
        req.body = Body::from_text(
            r#"<root><script><![CDATA[alert(1)]]></script><flag on="yes"/></root>"#,
        );
        let inputs = discover_inputs(&req);
        assert_eq!(
            find(&inputs, InputKind::XmlText, "root.script").value,
            "alert(1)"
        );
        // A self-closing element contributes only its attribute, no stray frame.
        assert_eq!(find(&inputs, InputKind::XmlAttr, "root.flag@on").value, "yes");
        assert!(!inputs.iter().any(|i| i.name == "root.flag.anything"));
    }

    #[test]
    fn set_xml_input_rewrites_text_and_attributes_by_path() {
        let body =
            r#"<order id="7"><item sku="A1">Widget</item><item sku="B2">Gadget</item></order>"#;
        // Replace the second item's text.
        let out = set_xml_input(body, "order.item.1", "PAYLOAD").unwrap();
        assert!(out.contains(">PAYLOAD<"));
        assert!(out.contains(">Widget<")); // the first item is untouched
        // Replace an attribute value by path.
        let out2 = set_xml_input(body, "order@id", "99").unwrap();
        assert!(out2.contains("id=\"99\""));
        // The rewritten body re-parses and now carries the injected value at the
        // same address — discovery and injection agree.
        let mut req = HttpRequest::get("https://x.test/");
        req.method = "POST".into();
        req.headers.push("Content-Type", "application/xml");
        req.body = Body::from_text(out.clone());
        let inputs = discover_inputs(&req);
        assert_eq!(
            find(&inputs, InputKind::XmlText, "order.item.1").value,
            "PAYLOAD"
        );
    }

    #[test]
    fn set_xml_input_returns_none_for_unknown_path_or_bad_xml() {
        let body = r#"<order><item>x</item></order>"#;
        assert!(set_xml_input(body, "order.missing", "p").is_none());
        assert!(set_xml_input(body, "order.item@nope", "p").is_none());
        assert!(set_xml_input("<broken", "order", "p").is_none());
    }

    #[test]
    fn malformed_xml_is_tolerated_without_panicking() {
        let mut req = HttpRequest::get("https://x.test/x");
        req.method = "POST".into();
        req.headers.push("Content-Type", "application/xml");
        req.body = Body::from_text(r#"<a><b>text</b><c unterminated"#);
        // Must not panic; it enumerates what it could before the break.
        let inputs = discover_inputs(&req);
        assert_eq!(find(&inputs, InputKind::XmlText, "a.b").value, "text");
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

#[cfg(test)]
mod discovery_gap_tests {
    use super::*;
    use camio_core::Body;

    fn req(url: &str, body: &str, ct: &str) -> HttpRequest {
        let mut r = HttpRequest::get(url);
        if !ct.is_empty() {
            r.headers.push("Content-Type", ct);
        }
        if !body.is_empty() {
            r.body = Body::from_text(body.to_string());
        }
        r
    }

    #[test]
    fn semicolon_separated_form_pairs_are_split() {
        let inputs = discover_inputs(&req(
            "https://ex.test/",
            "a=1;b=2",
            "application/x-www-form-urlencoded",
        ));
        let names: Vec<&str> = inputs.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"a"), "got {names:?}");
        assert!(names.contains(&"b"), "got {names:?}");
    }

    #[test]
    fn json_arrays_of_objects_yield_pathed_inputs() {
        let inputs = discover_inputs(&req(
            "https://ex.test/",
            r#"[{"id":"1","tags":["a","b"]},{"id":"2"}]"#,
            "application/json",
        ));
        let names: Vec<&str> = inputs.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"0.id"), "got {names:?}");
        assert!(names.contains(&"0.tags.0"), "got {names:?}");
        assert!(names.contains(&"1.id"), "got {names:?}");
    }

    #[test]
    fn nested_objects_of_scalars_are_discovered() {
        let inputs = discover_inputs(&req(
            "https://ex.test/",
            r#"{"user":{"name":"ada","age":36}}"#,
            "application/json",
        ));
        let names: Vec<&str> = inputs.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"user.name"), "got {names:?}");
        assert!(names.contains(&"user.age"), "got {names:?}");
    }

    #[test]
    fn repeated_headers_report_every_value() {
        let mut r = HttpRequest::get("https://ex.test/");
        r.headers.push("X-Forwarded-For", "one");
        r.headers.push("X-Forwarded-For", "two");
        let inputs = discover_inputs(&r);
        let values: Vec<&str> = inputs
            .iter()
            .filter(|i| i.name == "X-Forwarded-For")
            .map(|i| i.value.as_str())
            .collect();
        assert_eq!(values, vec!["one", "two"]);
    }

    #[test]
    fn json_string_numbers_stay_strings() {
        // `"30"` in a JSON string slot is a string, not a number: the encoder
        // must not treat it as a numeric field.
        let inputs = discover_inputs(&req(
            "https://ex.test/",
            r#"{"id":"30","count":7}"#,
            "application/json",
        ));
        let id = inputs.iter().find(|i| i.name == "id").unwrap();
        assert_eq!(id.value, "30");
    }
}

#[cfg(test)]
mod multipart_tests {
    use super::*;
    use camio_core::Body;

    const BODY: &str = "--X-BOUNDARY\r\n\
        Content-Disposition: form-data; name=\"field\"\r\n\
        \r\n\
        value-1\r\n\
        --X-BOUNDARY\r\n\
        Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n\
        Content-Type: text/plain\r\n\
        \r\n\
        file-bytes\r\n\
        --X-BOUNDARY--\r\n";

    fn req() -> HttpRequest {
        let mut r = HttpRequest::get("https://ex.test/upload");
        r.headers
            .push("Content-Type", "multipart/form-data; boundary=X-BOUNDARY");
        r.body = Body::from_text(BODY);
        r
    }

    #[test]
    fn multipart_parts_are_discovered() {
        let inputs = discover_inputs(&req());
        let names: Vec<&str> = inputs.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"field"), "got {names:?}");
        // A file part's position is its filename, not its bytes.
        let upload = inputs.iter().find(|i| i.name == "upload").unwrap();
        assert_eq!(upload.value, "a.txt");
    }

    #[test]
    fn a_missing_boundary_yields_nothing_rather_than_guessing() {
        let mut r = HttpRequest::get("https://ex.test/");
        r.headers.push("Content-Type", "multipart/form-data");
        r.body = Body::from_text("garbage without a boundary");
        assert!(discover_inputs(&r).is_empty());
    }

    #[test]
    fn a_quoted_boundary_is_parsed() {
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=\"q u o t e d\"").as_deref(),
            Some("q u o t e d")
        );
    }
}
