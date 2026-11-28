//! Passive **input-echo** check — `input-echo`.
//!
//! When Camio has access to the on-disk payload database
//! (`payloads/DB/base/*.txt`), this check scans every captured response body
//! for distinctive payload substrings drawn from that DB. It never sends new
//! traffic; it only reports when a captured response already contains a
//! fragment that matches one of the DB's signatures.
//!
//! This lets the proxy's `--auto-scan` mode give an "any input field tested
//! against the combined payload catalog" signal without crossing the
//! active/passive line: the signatures are drawn from the full XSS / SQLi /
//! SSTI / SSRF / Smuggling / Log4Shell / etc. catalog, so reflecting any
//! probe-shaped substring in the response is surfaced as an informational
//! finding with the originating category and the matched needle.

use crate::checks::finding;
use crate::PassiveCheck;
use camio_automate::{load_payload_db, scan_for_signatures, PayloadDb};
use camio_core::{Confidence, Finding, HttpExchange, Severity};
use std::sync::OnceLock;

static DB: OnceLock<PayloadDb> = OnceLock::new();

fn shared_db() -> &'static PayloadDb {
    DB.get_or_init(load_payload_db)
}

/// Passive check that flags responses containing payload-like substrings drawn
/// from the Camio payload database.
/// Maximum response body scanned for input-echo signatures (2 MiB). The scan is
/// O(signatures × body length) and runs on the proxy's capture hot path.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

pub struct InputEcho;

impl PassiveCheck for InputEcho {
    fn id(&self) -> &'static str {
        "input-echo"
    }

    fn title(&self) -> &'static str {
        "Payload-shaped substring echoed in response"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        let db = shared_db();
        if db.signatures.is_empty() {
            return Vec::new();
        }
        // Bound the body: the scan is O(signatures × body length) and runs on
        // the proxy's capture hot path, so a multi-MiB bundle pays for a probe
        // nobody needs. The cap is generous for real HTML/JS payloads.
        if resp.body.len() > MAX_BODY_BYTES {
            return Vec::new();
        }
        let body = resp.body.as_text();
        if body.is_empty() {
            return Vec::new();
        }
        let hits = scan_for_signatures(db, &body);
        if hits.is_empty() {
            return Vec::new();
        }
        hits.into_iter()
            .map(|sig| {
                let (severity, confidence) = severity_for(&sig.category);
                let short = short_needle(&sig.needle);
                finding(
                    format!("Response contains `{}` payload pattern", sig.category),
                    severity,
                    confidence,
                    format!(
                        "The response body contains a substring that matches a payload pattern in the `{}` category of the Camio payload database (`{}`). This is a passive signal only — the substring may be benign content or a reflection of a previously sent probe. Verify in context.",
                        sig.category, short
                    ),
                    ex.id,
                )
            })
            .collect()
    }
}

fn severity_for(category: &str) -> (Severity, Confidence) {
    match category {
        "sqli" | "ssti" | "cmdi" | "log4shell" | "xxe" | "smuggling" => {
            (Severity::Medium, Confidence::Tentative)
        }
        "xss" | "ssrf" | "crlf" => (Severity::Medium, Confidence::Tentative),
        _ => (Severity::Low, Confidence::Tentative),
    }
}

fn short_needle(needle: &str) -> String {
    const MAX: usize = 60;
    if needle.len() <= MAX {
        needle.to_string()
    } else {
        // Floor to a char boundary: slicing at a raw byte offset panics on a
        // multi-byte character, and needles come from operator/target data.
        let mut end = MAX;
        while end > 0 && !needle.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", needle.get(..end).unwrap_or(needle))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn short_needle_never_panics_on_multibyte() {
        // A needle whose byte offset 60 lands mid-character must floor cleanly.
        let needle = "é".repeat(40);
        let out = super::short_needle(&needle);
        assert!(out.ends_with('…'));
        assert!(out.chars().count() <= 31);
    }

    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(body: &str) -> HttpExchange {
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text(body),
        };
        HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner).with_response(resp)
    }

    #[test]
    fn empty_response_body_is_quiet() {
        assert!(InputEcho.check(&exchange("")).is_empty());
    }

    #[test]
    fn id_and_title_stable() {
        assert_eq!(InputEcho.id(), "input-echo");
        assert!(!InputEcho.title().is_empty());
    }

    #[test]
    fn severity_mapping_promotes_critical_categories() {
        let (s1, _) = severity_for("sqli");
        let (s2, _) = severity_for("misc");
        assert!(s1 > s2);
    }

    #[test]
    fn short_needle_truncates() {
        let big = "x".repeat(200);
        let out = short_needle(&big);
        assert!(out.ends_with('…'));
        assert!(out.chars().count() <= 61);
    }
}
