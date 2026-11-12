//! HAR (HTTP Archive) importer (plan §7.4 migration, §8 "schema import").
//!
//! HAR 1.2 is the interchange format browsers' devtools and Caido can export, so
//! it is a broad on-ramp into Camio. We parse `log.entries[]` into
//! [`HttpExchange`] records with [`serde_json::Value`] — tolerant of the many
//! optional fields real exporters omit.
//!
//! Header order is preserved exactly as it appears in the archive (plan §6.1
//! item 3 — never alphabetize/normalize). Response bodies declared
//! `encoding: "base64"` are decoded to raw bytes; otherwise the text is taken as
//! UTF-8. Entries we cannot turn into a request are skipped with a warning
//! rather than failing the whole import.

use crate::raw::{header_has_chunked, map_http_version};
use crate::{decode_base64, ImportError, ImportResult};
use camio_core::{Body, HeaderList, HttpExchange, HttpRequest, HttpResponse, Source};
use serde_json::Value;

/// Import a HAR archive (as a JSON string) into [`HttpExchange`] records.
pub fn import_har(json: &str) -> Result<ImportResult, ImportError> {
    let root: Value = serde_json::from_str(json)
        .map_err(|e| ImportError::Parse(format!("invalid HAR JSON: {e}")))?;

    let entries = root
        .get("log")
        .and_then(|log| log.get("entries"))
        .and_then(|entries| entries.as_array())
        .ok_or_else(|| ImportError::Parse("HAR missing log.entries array".to_string()))?;

    let mut exchanges: Vec<HttpExchange> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    for (idx, entry) in entries.iter().enumerate() {
        let request_value = match entry.get("request") {
            Some(r) => r,
            None => {
                warnings.push(format!("entry {idx}: missing request; skipped"));
                continue;
            }
        };

        let url = match request_value.get("url").and_then(|u| u.as_str()) {
            Some(u) if !u.is_empty() => u.to_string(),
            _ => {
                warnings.push(format!("entry {idx}: request has no url; skipped"));
                continue;
            }
        };

        let method = request_value
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("GET")
            .to_string();
        let version = request_value
            .get("httpVersion")
            .and_then(|h| h.as_str())
            .map(map_http_version)
            .unwrap_or_default();
        let headers = json_headers(request_value.get("headers"));
        let body = request_value
            .get("postData")
            .and_then(|p| p.get("text"))
            .and_then(|t| t.as_str())
            .map(Body::from_text)
            .unwrap_or_else(Body::empty);

        let request = HttpRequest {
            method,
            url,
            version,
            headers,
            body,
        };
        if header_has_chunked(&request.headers) {
            warnings.push(format!(
                "entry {idx}: request Transfer-Encoding: chunked kept raw (not de-chunked)"
            ));
        }

        let mut exchange = HttpExchange::new(request, Source::Import);
        if let Some(response_value) = entry.get("response") {
            if let Some(resp) = build_response(response_value, idx, &mut warnings) {
                exchange = exchange.with_response(resp);
            }
        }

        exchanges.push(exchange);
    }

    Ok(ImportResult {
        format: "har",
        exchanges,
        warnings,
    })
}

/// Map a HAR `headers` array (`[{name, value}, ...]`) to a [`HeaderList`],
/// preserving order and casing. Entries missing `name` or `value` are skipped.
fn json_headers(value: Option<&Value>) -> HeaderList {
    let mut headers = HeaderList::new();
    if let Some(array) = value.and_then(|v| v.as_array()) {
        for header in array {
            let name = header.get("name").and_then(|n| n.as_str());
            let val = header.get("value").and_then(|v| v.as_str());
            if let (Some(name), Some(val)) = (name, val) {
                headers.push(name, val);
            }
        }
    }
    headers
}

/// Build an [`HttpResponse`] from a HAR `response` object, or `None` when the
/// entry has no real response (status `0`/absent — HAR's marker for a failed or
/// uncaptured exchange).
fn build_response(value: &Value, idx: usize, warnings: &mut Vec<String>) -> Option<HttpResponse> {
    let status_raw = value.get("status").and_then(|s| s.as_u64());
    let status = match status_raw {
        Some(s) if (1..1000).contains(&s) => s as u16,
        _ => return None,
    };

    let version = value
        .get("httpVersion")
        .and_then(|h| h.as_str())
        .map(map_http_version)
        .unwrap_or_default();
    let reason = value
        .get("statusText")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let headers = json_headers(value.get("headers"));

    let body = match value.get("content") {
        Some(content) => {
            let text = content.get("text").and_then(|t| t.as_str()).unwrap_or("");
            let is_b64 = content
                .get("encoding")
                .and_then(|e| e.as_str())
                .map(|e| e.eq_ignore_ascii_case("base64"))
                .unwrap_or(false);
            if is_b64 {
                match decode_base64(text) {
                    Ok(bytes) => Body::from_bytes(bytes),
                    Err(e) => {
                        warnings.push(format!(
                            "entry {idx}: response content base64 decode failed ({e}); kept as text"
                        ));
                        Body::from_text(text)
                    }
                }
            } else {
                Body::from_text(text)
            }
        }
        None => Body::empty(),
    };

    if header_has_chunked(&headers) {
        warnings.push(format!(
            "entry {idx}: response Transfer-Encoding: chunked kept raw (not de-chunked)"
        ));
    }

    Some(HttpResponse {
        status,
        version,
        reason,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::HttpVersion;

    #[test]
    fn imports_entry_with_base64_content_preserving_header_order() {
        let har = r#"{
          "log": {
            "version": "1.2",
            "entries": [
              {
                "request": {
                  "method": "POST",
                  "url": "https://api.example/v1/items",
                  "httpVersion": "HTTP/2",
                  "headers": [
                    {"name": "Host", "value": "api.example"},
                    {"name": "x-custom", "value": "keepcase"},
                    {"name": "Content-Type", "value": "application/json"}
                  ],
                  "postData": {"mimeType": "application/json", "text": "{\"a\":1}"}
                },
                "response": {
                  "status": 201,
                  "statusText": "Created",
                  "httpVersion": "HTTP/2",
                  "headers": [
                    {"name": "Content-Type", "value": "text/plain"}
                  ],
                  "content": {"mimeType": "text/plain", "encoding": "base64", "text": "aGVsbG8="}
                }
              }
            ]
          }
        }"#;

        let result = import_har(har).unwrap();
        assert_eq!(result.format, "har");
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

        assert_eq!(ex.request.method, "POST");
        assert_eq!(ex.request.url, "https://api.example/v1/items");
        assert_eq!(ex.request.version, HttpVersion::H2);
        // Header order and casing preserved exactly.
        let names: Vec<&str> = ex.request.headers.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["Host", "x-custom", "Content-Type"]);
        assert_eq!(ex.request.headers.get("x-custom"), Some("keepcase"));
        assert_eq!(ex.request.body.as_text(), "{\"a\":1}");

        let resp = ex.response.as_ref().unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.reason.as_deref(), Some("Created"));
        assert_eq!(resp.version, HttpVersion::H2);
        // base64 "aGVsbG8=" decodes to "hello".
        assert_eq!(resp.body.as_bytes(), b"hello");
    }

    #[test]
    fn non_base64_content_is_utf8_text() {
        let har = r#"{"log":{"entries":[
            {"request":{"method":"GET","url":"https://x.example/"},
             "response":{"status":200,"statusText":"OK","content":{"text":"plain body","mimeType":"text/plain"}}}
        ]}}"#;
        let result = import_har(har).unwrap();
        let resp = result.exchanges[0].response.as_ref().unwrap();
        assert_eq!(resp.body.as_text(), "plain body");
    }

    #[test]
    fn entry_without_request_is_skipped_with_warning() {
        let har = r#"{"log":{"entries":[
            {"response":{"status":200}},
            {"request":{"method":"GET","url":"https://ok.example/"}}
        ]}}"#;
        let result = import_har(har).unwrap();
        assert_eq!(result.exchanges.len(), 1);
        assert_eq!(result.exchanges[0].request.url, "https://ok.example/");
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("missing request")));
    }

    #[test]
    fn zero_status_response_maps_to_none() {
        let har = r#"{"log":{"entries":[
            {"request":{"method":"GET","url":"https://x.example/"},
             "response":{"status":0,"content":{}}}
        ]}}"#;
        let result = import_har(har).unwrap();
        assert_eq!(result.exchanges.len(), 1);
        assert!(result.exchanges[0].response.is_none());
    }

    #[test]
    fn missing_log_entries_is_a_typed_error() {
        assert!(matches!(import_har("{}"), Err(ImportError::Parse(_))));
        assert!(matches!(import_har("not json"), Err(ImportError::Parse(_))));
    }

    #[test]
    fn default_version_when_http_version_absent() {
        let har = r#"{"log":{"entries":[
            {"request":{"method":"GET","url":"https://x.example/"}}
        ]}}"#;
        let result = import_har(har).unwrap();
        assert_eq!(result.exchanges[0].request.version, HttpVersion::Http11);
        assert!(result.exchanges[0].response.is_none());
    }
}
