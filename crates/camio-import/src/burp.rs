//! Burp Suite item-export (`<items>` XML) importer (plan §7.4 migration, §8
//! "schema import / Import Burp & Caido projects").
//!
//! Burp's "Save items" export is an `<items>` document of `<item>` elements, each
//! carrying `<url>`, `<host>`, `<port>`, `<protocol>`, `<method>`, `<path>`,
//! `<status>`, and `<request>`/`<response>` holding the raw HTTP messages. The
//! raw messages are usually base64 (`base64="true"`) but may be inline text, so
//! we honour the attribute and decode accordingly.
//!
//! Parsing uses `quick-xml`'s pull [`Reader`] and is tolerant of unknown
//! elements and attributes. The raw messages are handed to the shared
//! [`parse_raw_request`]/[`parse_raw_response`] helpers so header order and
//! casing are preserved exactly (plan §6.1 item 3) — Burp's whole value as a
//! source is that it recorded the bytes faithfully, and we must not undo that.

use crate::raw::{header_has_chunked, parse_raw_request, parse_raw_response};
use crate::{decode_base64, ImportError, ImportResult};
use camio_core::{Body, HeaderList, HttpExchange, HttpRequest, HttpVersion, Source};
use quick_xml::events::Event;
use quick_xml::Reader;

/// Accumulated fields of one `<item>` while streaming the document.
#[derive(Default)]
struct ItemBuf {
    url: Option<String>,
    host: Option<String>,
    port: Option<String>,
    protocol: Option<String>,
    method: Option<String>,
    path: Option<String>,
    request: Option<Vec<u8>>,
    response: Option<Vec<u8>>,
}

/// Which direct child of `<item>` is currently being read.
enum Field {
    Url,
    Host,
    Port,
    Protocol,
    Method,
    Path,
    Request,
    Response,
    /// A recognized-but-unused element (e.g. `<status>`) or anything else.
    Ignored,
}

fn classify(name: &[u8]) -> Field {
    match name.to_ascii_lowercase().as_slice() {
        b"url" => Field::Url,
        b"host" => Field::Host,
        b"port" => Field::Port,
        b"protocol" => Field::Protocol,
        b"method" => Field::Method,
        b"path" => Field::Path,
        b"request" => Field::Request,
        b"response" => Field::Response,
        _ => Field::Ignored,
    }
}

/// Import a Burp `<items>` XML export into [`HttpExchange`] records.
pub fn import_burp_xml(xml: &str) -> Result<ImportResult, ImportError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut exchanges: Vec<HttpExchange> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Depth tracking lets us scope fields to the direct children of `<item>` and
    // stay tolerant of nested/unknown structure.
    let mut depth: i32 = 0;
    let mut item_open = false;
    let mut item_depth: i32 = 0;
    let mut item = ItemBuf::default();
    let mut field: Option<Field> = None;
    let mut field_is_b64 = false;
    let mut buf = String::new();
    let mut item_index = 0usize;

    loop {
        let event = reader
            .read_event()
            .map_err(|e| ImportError::Parse(format!("XML parse error: {e}")))?;
        match event {
            Event::Start(e) => {
                depth += 1;
                let lname = e.local_name().as_ref().to_vec();
                if lname.eq_ignore_ascii_case(b"item") {
                    item_open = true;
                    item_depth = depth;
                    item = ItemBuf::default();
                    field = None;
                } else if item_open && depth == item_depth + 1 {
                    let f = classify(&lname);
                    field_is_b64 = false;
                    if matches!(f, Field::Request | Field::Response) {
                        for attr in e.attributes() {
                            let attr = attr.map_err(|err| {
                                ImportError::Parse(format!("XML attribute error: {err}"))
                            })?;
                            if attr.key.as_ref().eq_ignore_ascii_case(b"base64") {
                                let val = String::from_utf8_lossy(attr.value.as_ref());
                                field_is_b64 = val.trim().eq_ignore_ascii_case("true");
                            }
                        }
                    }
                    field = Some(f);
                    buf.clear();
                }
            }
            Event::Text(e) => {
                if item_open && field.is_some() && depth == item_depth + 1 {
                    // `BytesText::unescape` was removed in quick-xml 0.41; `xml10_content`
                    // decodes the charset and resolves XML entities, the same thing.
                    let text = e
                        .xml10_content()
                        .map_err(|err| ImportError::Parse(format!("XML text error: {err}")))?;
                    buf.push_str(&text);
                }
            }
            Event::CData(e) => {
                if item_open && field.is_some() && depth == item_depth + 1 {
                    // CDATA is raw (no entity unescaping); take its bytes directly.
                    buf.push_str(&String::from_utf8_lossy(e.into_inner().as_ref()));
                }
            }
            Event::End(e) => {
                let lname = e.local_name().as_ref().to_vec();
                if item_open && depth == item_depth + 1 && field.is_some() {
                    let value = std::mem::take(&mut buf);
                    match field.take() {
                        Some(Field::Url) => item.url = Some(value.trim().to_string()),
                        Some(Field::Host) => item.host = Some(value.trim().to_string()),
                        Some(Field::Port) => item.port = Some(value.trim().to_string()),
                        Some(Field::Protocol) => item.protocol = Some(value.trim().to_string()),
                        Some(Field::Method) => item.method = Some(value.trim().to_string()),
                        Some(Field::Path) => item.path = Some(value.trim().to_string()),
                        Some(Field::Request) => {
                            let bytes = decode_field(
                                &value,
                                field_is_b64,
                                "request",
                                item_index,
                                &mut warnings,
                            );
                            if !bytes.is_empty() {
                                item.request = Some(bytes);
                            }
                        }
                        Some(Field::Response) => {
                            let bytes = decode_field(
                                &value,
                                field_is_b64,
                                "response",
                                item_index,
                                &mut warnings,
                            );
                            if !bytes.is_empty() {
                                item.response = Some(bytes);
                            }
                        }
                        Some(Field::Ignored) | None => {}
                    }
                } else if item_open && depth == item_depth && lname.eq_ignore_ascii_case(b"item") {
                    finalize_item(&item, item_index, &mut exchanges, &mut warnings);
                    item_index += 1;
                    item_open = false;
                    item = ItemBuf::default();
                    field = None;
                }
                depth -= 1;
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Ok(ImportResult {
        format: "burp-xml",
        exchanges,
        warnings,
    })
}

/// Decode a `<request>`/`<response>` payload, honouring the `base64` attribute.
/// On a base64 failure the raw text bytes are kept and a warning is recorded so
/// no data is silently dropped.
fn decode_field(
    text: &str,
    is_b64: bool,
    which: &str,
    idx: usize,
    warnings: &mut Vec<String>,
) -> Vec<u8> {
    if is_b64 {
        match decode_base64(text) {
            Ok(bytes) => bytes,
            Err(e) => {
                warnings.push(format!(
                    "item {idx}: {which} base64 decode failed ({e}); kept raw text"
                ));
                text.as_bytes().to_vec()
            }
        }
    } else {
        text.as_bytes().to_vec()
    }
}

/// Build the exchange for one fully-read item and push it, or record a warning
/// if it cannot be imported.
fn finalize_item(
    item: &ItemBuf,
    idx: usize,
    exchanges: &mut Vec<HttpExchange>,
    warnings: &mut Vec<String>,
) {
    let url = match build_url(item) {
        Some(u) => u,
        None => {
            warnings.push(format!(
                "item {idx}: could not determine URL (no <url> and no host/protocol); skipped"
            ));
            return;
        }
    };

    let request = match &item.request {
        Some(bytes) => match parse_raw_request(bytes, &url) {
            Ok(r) => r,
            Err(e) => {
                warnings.push(format!("item {idx}: request parse failed ({e}); skipped"));
                return;
            }
        },
        None => HttpRequest {
            method: item.method.clone().unwrap_or_else(|| "GET".to_string()),
            url: url.clone(),
            version: HttpVersion::Http11,
            headers: HeaderList::new(),
            body: Body::empty(),
        },
    };
    if header_has_chunked(&request.headers) {
        warnings.push(format!(
            "item {idx}: request Transfer-Encoding: chunked kept raw (not de-chunked)"
        ));
    }

    let mut exchange = HttpExchange::new(request, Source::Import);

    if let Some(bytes) = &item.response {
        match parse_raw_response(bytes) {
            Ok(resp) => {
                if header_has_chunked(&resp.headers) {
                    warnings.push(format!(
                        "item {idx}: response Transfer-Encoding: chunked kept raw (not de-chunked)"
                    ));
                }
                exchange = exchange.with_response(resp);
            }
            Err(e) => warnings.push(format!(
                "item {idx}: response parse failed ({e}); response omitted"
            )),
        }
    }

    exchanges.push(exchange);
}

/// The default port for a scheme, so a constructed authority can omit it.
fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

/// Build the absolute URL for an item: prefer `<url>`, else assemble it from
/// `<protocol>://<host>[:<port>]<path>`.
fn build_url(item: &ItemBuf) -> Option<String> {
    if let Some(u) = &item.url {
        if !u.is_empty() {
            return Some(u.clone());
        }
    }
    let host = item.host.as_deref().filter(|h| !h.is_empty())?;
    let proto = item
        .protocol
        .as_deref()
        .filter(|p| !p.is_empty())
        .unwrap_or("https");
    let path = item
        .path
        .as_deref()
        .filter(|p| !p.is_empty())
        .unwrap_or("/");
    let authority = match item.port.as_deref().and_then(|p| p.parse::<u16>().ok()) {
        Some(p) if Some(p) != default_port(proto) => format!("{host}:{p}"),
        _ => host.to_string(),
    };
    Some(format!("{proto}://{authority}{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    #[test]
    fn imports_base64_item_preserving_order_and_casing() {
        let raw_req =
            "GET /a?x=1 HTTP/1.1\r\nHost: t.example\r\nx-custom: keep\r\nAccept: */*\r\n\r\n";
        let raw_resp =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: a=1\r\n\r\n{\"ok\":true}";
        let req_b64 = STANDARD.encode(raw_req);
        let resp_b64 = STANDARD.encode(raw_resp);

        let xml = format!(
            r#"<?xml version="1.0"?>
<items burpVersion="2023.1">
  <item>
    <url><![CDATA[https://t.example/a?x=1]]></url>
    <host ip="1.2.3.4">t.example</host>
    <port>443</port>
    <protocol>https</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/a?x=1]]></path>
    <status>200</status>
    <request base64="true">{req_b64}</request>
    <response base64="true">{resp_b64}</response>
    <comment></comment>
  </item>
</items>"#
        );

        let result = import_burp_xml(&xml).unwrap();
        assert_eq!(result.format, "burp-xml");
        assert!(
            result.warnings.is_empty(),
            "warnings: {:?}",
            result.warnings
        );
        assert_eq!(result.exchanges.len(), 1);

        let ex = &result.exchanges[0];
        assert_eq!(ex.source, Source::Import);
        assert_eq!(ex.created_at_ms, 0);
        assert_eq!(ex.fingerprint_used, None);

        // Request: method/url from the raw message + supplied URL.
        assert_eq!(ex.request.method, "GET");
        assert_eq!(ex.request.url, "https://t.example/a?x=1");
        // Header order and casing preserved exactly.
        let names: Vec<&str> = ex.request.headers.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["Host", "x-custom", "Accept"]);
        assert_eq!(ex.request.headers.get("x-custom"), Some("keep"));

        // Response parsed from the raw message.
        let resp = ex.response.as_ref().unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason.as_deref(), Some("OK"));
        assert_eq!(resp.headers.0[0].name, "Content-Type");
        assert_eq!(resp.body.as_text(), "{\"ok\":true}");
    }

    #[test]
    fn builds_url_from_parts_when_url_absent_and_handles_raw_request() {
        // No <url>; non-base64 raw request; non-default port.
        let xml = "<items>\n\
            <item>\n\
            <host>h.example</host><port>8443</port><protocol>https</protocol><path>/p</path>\n\
            <request base64=\"false\">GET /p HTTP/1.1\nHost: h.example\n\n</request>\n\
            </item>\n\
            </items>";
        let result = import_burp_xml(xml).unwrap();
        assert_eq!(result.exchanges.len(), 1);
        let ex = &result.exchanges[0];
        assert_eq!(ex.request.url, "https://h.example:8443/p");
        assert_eq!(ex.request.method, "GET");
        assert_eq!(ex.request.headers.get("Host"), Some("h.example"));
        // No response element -> no response.
        assert!(ex.response.is_none());
    }

    #[test]
    fn chunked_response_body_produces_warning() {
        let raw_req = "GET / HTTP/1.1\r\nHost: c.example\r\n\r\n";
        let raw_resp =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let xml = format!(
            r#"<items><item><url><![CDATA[https://c.example/]]></url>
            <request base64="true">{}</request>
            <response base64="true">{}</response></item></items>"#,
            STANDARD.encode(raw_req),
            STANDARD.encode(raw_resp),
        );
        let result = import_burp_xml(&xml).unwrap();
        assert_eq!(result.exchanges.len(), 1);
        assert!(result.warnings.iter().any(|w| w.contains("chunked")));
        // Chunked bytes kept verbatim.
        let resp = result.exchanges[0].response.as_ref().unwrap();
        assert_eq!(resp.body.as_text(), "5\r\nhello\r\n0\r\n\r\n");
    }

    #[test]
    fn item_without_url_or_host_is_skipped_with_warning() {
        let xml = "<items><item><method>GET</method></item></items>";
        let result = import_burp_xml(xml).unwrap();
        assert!(result.exchanges.is_empty());
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("could not determine URL"));
    }

    #[test]
    fn multiple_items_are_all_imported_in_order() {
        let xml = r#"<items>
            <item><url>https://a.example/1</url><method>GET</method></item>
            <item><url>https://b.example/2</url><method>POST</method></item>
        </items>"#;
        let result = import_burp_xml(xml).unwrap();
        assert_eq!(result.exchanges.len(), 2);
        assert_eq!(result.exchanges[0].request.url, "https://a.example/1");
        assert_eq!(result.exchanges[0].request.method, "GET");
        assert_eq!(result.exchanges[1].request.url, "https://b.example/2");
        assert_eq!(result.exchanges[1].request.method, "POST");
    }

    #[test]
    fn bad_base64_keeps_raw_and_warns() {
        let xml = r#"<items><item><url>https://x.example/</url>
            <request base64="true">!!!not base64!!!</request></item></items>"#;
        let result = import_burp_xml(xml).unwrap();
        // Decode failed -> raw text kept -> request still parses its first line.
        assert_eq!(result.exchanges.len(), 1);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("base64 decode failed")));
    }
}
