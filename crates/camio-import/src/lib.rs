//! `camio-import` — Burp/HAR/Caido importers (plan §7.4 migration, §8 "schema
//! import").
//!
//! The biggest lever against switching cost is importing prior testing data, so
//! Camio ingests the two most portable formats security tools emit:
//!
//! * [`import_burp_xml`] — Burp Suite "Save items" `<items>` XML exports.
//! * [`import_har`] — HAR 1.2 archives (browsers' devtools, Caido, proxies).
//!
//! Both land in the one canonical [`HttpExchange`](camio_core::HttpExchange)
//! model (plan §13) with [`Source::Import`](camio_core::Source::Import), so
//! imported traffic is attributable and searchable like everything else. Because
//! Camio's thesis is fingerprint/byte transparency (plan §6.1 item 3), the
//! importers **preserve header order and casing exactly** and keep bodies as raw
//! bytes — they never sort, fold, or canonicalize. New records leave
//! `created_at_ms = 0` and `id = ExchangeId(0)`; the store stamps real ids and
//! timestamps on insert.
//!
//! [`import_bytes`] sniffs the format and dispatches. The raw-message helpers
//! [`parse_raw_request`]/[`parse_raw_response`] are public so other crates (and
//! tests) can reuse the exact same tolerant parser.

mod burp;
mod har;
mod raw;

pub use burp::import_burp_xml;
pub use har::import_har;
pub use raw::{parse_raw_request, parse_raw_response};

use camio_core::HttpExchange;
use serde::Serialize;

/// An error produced while importing. Carries a human-readable detail string and
/// implements [`std::error::Error`] so callers can propagate it uniformly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// The input was recognized but is malformed (bad XML/JSON or a broken
    /// request/status line).
    Parse(String),
    /// The input's format could not be recognized.
    Unsupported(String),
    /// A payload (e.g. base64 body) could not be decoded.
    Decode(String),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Parse(s) => write!(f, "parse error: {s}"),
            ImportError::Unsupported(s) => write!(f, "unsupported format: {s}"),
            ImportError::Decode(s) => write!(f, "decode error: {s}"),
        }
    }
}

impl std::error::Error for ImportError {}

/// The outcome of an import: the detected format, the recovered exchanges, and
/// any non-fatal warnings (skipped entries, undecodable bodies, chunked bodies
/// kept raw). Serializable so the CLI/MCP layer can report it directly.
#[derive(Debug, Clone, Serialize)]
pub struct ImportResult {
    /// A stable format tag: `"burp-xml"` or `"har"`.
    pub format: &'static str,
    /// The exchanges recovered from the input, in document order.
    pub exchanges: Vec<HttpExchange>,
    /// Non-fatal problems encountered; the import still succeeded.
    pub warnings: Vec<String>,
}

/// Whether a header name/value is safe to store and later replay.
///
/// Imported archives are replayed through the request engine, so a value
/// carrying CR/LF (or NUL) is a request-splitting primitive: the origin would
/// see headers the archive never declared. Reject control characters rather
/// than storing them.
pub fn header_is_safe(name: &str, value: &str) -> bool {
    let no_control = |s: &str| !s.chars().any(|c| c.is_control() || c == '\u{7f}');
    !name.is_empty()
        && !name.contains(':')
        && !name.contains(' ')
        && !name.contains('\t')
        && no_control(name)
        && no_control(value)
}

/// Maximum import input size (32 MiB). Callers cap further (the web API allows
/// 4 MiB), but the parser itself must never accept an unbounded file.
pub const MAX_IMPORT_BYTES: usize = 32 * 1024 * 1024;

/// Maximum exchanges one import may produce.
pub const MAX_IMPORT_EXCHANGES: usize = 50_000;

/// Import a byte buffer by sniffing its format, then dispatching.
///
/// Sniffing: a leading `{` (after optional whitespace) means HAR JSON; otherwise
/// the presence of `<items` or `<?xml` means a Burp XML export; anything else is
/// [`ImportError::Unsupported`].
pub fn import_bytes(data: &[u8]) -> Result<ImportResult, ImportError> {
    if data.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::Parse(format!(
            "input is {} bytes, over the {MAX_IMPORT_BYTES}-byte limit",
            data.len()
        )));
    }
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let first_non_ws = data.iter().position(|b| !b.is_ascii_whitespace());
    match first_non_ws {
        Some(i) if data[i] == b'{' => {
            let json = std::str::from_utf8(data)
                .map_err(|e| ImportError::Decode(format!("HAR is not valid UTF-8: {e}")))?;
            import_har(json)
        }
        _ => {
            if raw::find_subslice(data, b"<items").is_some()
                || raw::find_subslice(data, b"<?xml").is_some()
            {
                let xml = String::from_utf8_lossy(data);
                import_burp_xml(&xml)
            } else {
                Err(ImportError::Unsupported(
                    "expected HAR JSON (leading '{') or Burp items XML ('<items'/'<?xml')"
                        .to_string(),
                ))
            }
        }
    }
}

/// Decode standard base64, first stripping any ASCII whitespace (exporters wrap
/// long payloads across lines). Shared by the Burp and HAR importers.
pub(crate) fn decode_base64(s: &str) -> Result<Vec<u8>, ImportError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| ImportError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_har_with_leading_whitespace() {
        let data = b"   \n  {\"log\":{\"entries\":[]}}";
        let result = import_bytes(data).unwrap();
        assert_eq!(result.format, "har");
        assert!(result.exchanges.is_empty());
    }

    #[test]
    fn sniffs_burp_xml_by_declaration() {
        let data = b"<?xml version=\"1.0\"?>\n<items></items>";
        let result = import_bytes(data).unwrap();
        assert_eq!(result.format, "burp-xml");
    }

    #[test]
    fn sniffs_burp_xml_by_items_tag_without_declaration() {
        let data =
            b"<items>\n<item><url>https://x.example/</url><method>GET</method></item>\n</items>";
        let result = import_bytes(data).unwrap();
        assert_eq!(result.format, "burp-xml");
        assert_eq!(result.exchanges.len(), 1);
    }

    #[test]
    fn unrecognized_input_is_unsupported() {
        assert!(matches!(
            import_bytes(b"hello world, not a known format"),
            Err(ImportError::Unsupported(_))
        ));
    }

    #[test]
    fn import_result_serializes_to_json() {
        let data =
            b"<items>\n<item><url>https://x.example/a</url><method>GET</method></item>\n</items>";
        let result = import_bytes(data).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"format\":\"burp-xml\""));
        assert!(json.contains("https://x.example/a"));
    }

    #[test]
    fn error_display_is_descriptive() {
        assert_eq!(
            ImportError::Parse("bad line".to_string()).to_string(),
            "parse error: bad line"
        );
        assert_eq!(
            ImportError::Unsupported("mystery".to_string()).to_string(),
            "unsupported format: mystery"
        );
        assert_eq!(
            ImportError::Decode("bad b64".to_string()).to_string(),
            "decode error: bad b64"
        );
    }

    #[test]
    fn error_is_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&ImportError::Parse("x".to_string()));
    }

    #[test]
    fn decode_base64_strips_whitespace() {
        // "aGVsbG8=" is "hello"; split across lines as an exporter might.
        assert_eq!(decode_base64("aGVs\nbG8=").unwrap(), b"hello");
        assert!(matches!(
            decode_base64("!!!not base64!!!"),
            Err(ImportError::Decode(_))
        ));
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    #[test]
    fn oversized_input_is_refused() {
        let huge = vec![b'<'; 10];
        // A guard bigger than the cap is what matters; use the cap constant so
        // the test stays cheap.
        let mut data = Vec::new();
        data.extend_from_slice(b"<?xml version=\"1.0\"?><items>");
        data.resize(MAX_IMPORT_BYTES + 1, b' ');
        let _ = huge;
        let err = import_bytes(&data).unwrap_err();
        assert!(err.to_string().contains("limit"), "{err}");
    }

    #[test]
    fn control_characters_in_headers_are_rejected() {
        assert!(header_is_safe("X-Ok", "value"), "a normal header is safe");
        assert!(!header_is_safe("X-Ok", "a\r\nX-Evil: b"));
        assert!(!header_is_safe("X\u{0}Nul", "v"));
        assert!(!header_is_safe("Name: x", "v"));
        assert!(header_is_safe(
            "Content-Type",
            "application/json; charset=utf-8"
        ));
    }

    #[test]
    fn a_crlf_header_value_in_har_is_dropped_with_a_warning() {
        // HAR gives headers as name/value pairs, so a single value can carry
        // CRLF — that is request splitting on replay, so it is refused and
        // reported rather than silently stored.
        let har = serde_json::json!({
            "log": { "entries": [ {
                "request": {
                    "method": "GET",
                    "url": "https://ex.test/",
                    "headers": [
                        { "name": "Host", "value": "ex.test" },
                        { "name": "X-Evil", "value": "a\r\nX-Injected: b" }
                    ]
                },
                "response": { "status": 200, "headers": [] }
            } ] }
        });
        let result = import_har(&har.to_string()).unwrap();
        let ex = &result.exchanges[0];
        assert!(
            ex.request.headers.get("X-Injected").is_none(),
            "no split header"
        );
        assert!(
            result.warnings.iter().any(|w| w.contains("unsafe header")),
            "warnings: {:?}",
            result.warnings
        );
    }
}
