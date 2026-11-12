//! Sensitive-JSON-field check (plan §8 "Scan & crawl"; §16 privacy).
//!
//! A JSON API response that carries fields named like credentials or personal
//! data (`password`, `ssn`, `credit_card`, `api_key`, …) is frequently
//! over-fetching — returning data the client never needs. This parses
//! `application/json` responses with `serde_json`, walks the value tree, and
//! reports the *names* of matching fields that have a non-empty value. Values are
//! never echoed, so the finding cannot re-leak them (plan §16). The names-only
//! heuristic makes this [`Confidence::Tentative`] at [`Severity::Medium`]; a
//! parse failure yields no finding.

use crate::checks::{content_type, finding};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};
use regex::Regex;
use std::sync::OnceLock;

/// Flags sensitively-named, non-empty fields in a JSON response.
pub struct SensitiveJsonFields;

/// Field-name patterns that suggest sensitive data. A compile failure degrades
/// the check to "no finding".
fn sensitive_json_key_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(password|passwd|secret|private_key|ssn|credit_card|card_number|cvv|api[_-]?key|access_token)",
        )
        .ok()
    })
    .as_ref()
}

/// `true` when a JSON value is "non-empty": a non-empty string/array/object, or
/// any number/bool. `null` and empty containers/strings are treated as empty.
fn is_non_empty(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
        serde_json::Value::Bool(_) | serde_json::Value::Number(_) => true,
    }
}

/// Recursively collect sensitively-named keys with non-empty values, preserving
/// first-seen order and de-duplicating by name.
fn collect_keys(v: &serde_json::Value, re: &Regex, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                if re.is_match(k) && is_non_empty(val) && !out.iter().any(|e| e == k) {
                    out.push(k.clone());
                }
                collect_keys(val, re, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for val in arr {
                collect_keys(val, re, out);
            }
        }
        _ => {}
    }
}

impl PassiveCheck for SensitiveJsonFields {
    fn id(&self) -> &'static str {
        "sensitive-json-fields"
    }

    fn title(&self) -> &'static str {
        "Sensitive fields in JSON response"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        let is_json = content_type(resp)
            .map(|ct| ct.to_ascii_lowercase().contains("json"))
            .unwrap_or(false);
        if !is_json {
            return Vec::new();
        }
        let Some(re) = sensitive_json_key_re() else {
            return Vec::new();
        };
        let text = resp.body.as_text();
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text.as_ref()) else {
            return Vec::new();
        };

        let mut keys = Vec::new();
        collect_keys(&value, re, &mut keys);
        if keys.is_empty() {
            return Vec::new();
        }

        let listed = keys
            .iter()
            .map(|k| format!("`{k}`"))
            .collect::<Vec<_>>()
            .join(", ");
        vec![finding(
            "Sensitive fields in JSON response",
            Severity::Medium,
            Confidence::Tentative,
            format!(
                "The JSON response contains field(s) whose names indicate sensitive data: {listed}. (Field *names* only are reported — never the values.) Confirm these must reach this client; if not, drop or mask them server-side so the API does not over-fetch credentials or personal data."
            ),
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(ct: &str, body: &str) -> HttpExchange {
        let mut h = HeaderList::new();
        h.push("Content-Type", ct);
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(body),
        };
        HttpExchange::new(HttpRequest::get("https://api.test/me"), Source::Scanner)
            .with_response(resp)
    }

    #[test]
    fn flags_top_level_sensitive_field_by_name_not_value() {
        let ex = exchange(
            "application/json",
            r#"{"user":"bob","password":"hunter2","age":30}"#,
        );
        let f = SensitiveJsonFields.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Sensitive fields in JSON response");
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].confidence, Confidence::Tentative);
        assert!(f[0].detail.contains("password"));
        // The value must never be echoed.
        assert!(!f[0].detail.contains("hunter2"));
    }

    #[test]
    fn flags_nested_sensitive_field() {
        let ex = exchange(
            "application/json",
            r#"{"profile":{"billing":{"credit_card":"4111111111111111"}}}"#,
        );
        let f = SensitiveJsonFields.check(&ex);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("credit_card"));
        assert!(!f[0].detail.contains("4111111111111111"));
    }

    #[test]
    fn empty_or_null_values_do_not_fire() {
        assert!(SensitiveJsonFields
            .check(&exchange("application/json", r#"{"password":""}"#))
            .is_empty());
        assert!(SensitiveJsonFields
            .check(&exchange("application/json", r#"{"api_key":null}"#))
            .is_empty());
    }

    #[test]
    fn non_json_content_type_is_skipped() {
        // Same body, but served as HTML → not parsed here.
        let ex = exchange("text/html", r#"{"password":"hunter2"}"#);
        assert!(SensitiveJsonFields.check(&ex).is_empty());
    }

    #[test]
    fn invalid_json_yields_no_finding() {
        let ex = exchange("application/json", r#"{"password": "x" "#);
        assert!(SensitiveJsonFields.check(&ex).is_empty());
    }

    #[test]
    fn benign_json_does_not_fire() {
        let ex = exchange(
            "application/json",
            r#"{"user":"bob","age":30,"city":"NYC"}"#,
        );
        assert!(SensitiveJsonFields.check(&ex).is_empty());
    }

    #[test]
    fn no_response_no_findings() {
        let ex = HttpExchange::new(HttpRequest::get("https://api.test/me"), Source::Scanner);
        assert!(SensitiveJsonFields.check(&ex).is_empty());
    }
}
