//! Static DOM-XSS source→sink detection (plan §8 "Scan & crawl"; the static
//! half of the DOM-inspection capability — the browser-assisted confirmation is
//! a separate, interactive step).
//!
//! Full client-side taint tracking needs a running DOM, but a great deal of
//! DOM-based XSS is visible statically: an attacker-controlled **source**
//! (`location.hash`, `document.referrer`, `window.name`, …) reaching a dangerous
//! **sink** (`innerHTML`, `document.write`, `eval`, …). This check flags a
//! response whose script contains a source *close to* a sink — a candidate worth
//! confirming, reported conservatively (Low / Tentative) rather than as a proven
//! vulnerability.

use crate::checks::finding;
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};
use regex::Regex;
use std::sync::OnceLock;

/// Attacker-influenced DOM sources.
fn source_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        // No lookaround: Rust's `regex` has none, so sources are the explicit
        // attacker-influenced reads (navigation methods like `location.assign`
        // are deliberately NOT listed — they are sinks, not sources).
        Regex::new(
            r"(?i)(location\s*\.\s*(hash|search|href|pathname|host)|document\s*\.\s*(URL|documentURI|referrer|baseURI)|window\s*\.\s*name)",
        )
        .ok()
    })
    .as_ref()
}

/// Dangerous DOM sinks that turn a string into markup or code.
fn sink_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(\.\s*(inner|outer)HTML\s*=|\.\s*insertAdjacentHTML\s*\(|document\s*\.\s*write(ln)?\s*\(|\beval\s*\(|new\s+Function\s*\(|\.\s*srcdoc\s*=|\$\s*\(\s*[^)]*\)\s*\.\s*html\s*\()",
        )
        .ok()
    })
    .as_ref()
}

/// How many bytes before/after a sink a source may appear and still count as a
/// candidate flow. Wide enough to span a short expression, narrow enough that an
/// unrelated source and sink elsewhere on the page do not co-trigger.
const WINDOW_BEFORE: usize = 240;
const WINDOW_AFTER: usize = 80;

/// Flags response bodies whose scripts place a DOM-XSS source near a sink.
pub struct DomXssSinks;

impl PassiveCheck for DomXssSinks {
    fn id(&self) -> &'static str {
        "dom-xss-sink"
    }

    fn title(&self) -> &'static str {
        "Potential DOM-based XSS (source near sink)"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        let body = resp.body.as_text();
        let (Some(sources), Some(sinks)) = (source_re(), sink_re()) else {
            return Vec::new();
        };

        // Collect source spans once; for each sink, see if a source falls within
        // the proximity window around it.
        let source_spans: Vec<(usize, usize, &str)> = sources
            .find_iter(&body)
            .map(|m| (m.start(), m.end(), m.as_str()))
            .collect();
        if source_spans.is_empty() {
            return Vec::new();
        }

        let mut pairs: Vec<(String, String)> = Vec::new();
        for sink in sink_re_iter(sinks, &body) {
            let (sink_start, sink_end, sink_text) = sink;
            let lo = sink_start.saturating_sub(WINDOW_BEFORE);
            let hi = sink_end + WINDOW_AFTER;
            if let Some((_, _, src)) = source_spans
                .iter()
                .find(|(s, e, _)| *e > lo && *s < hi)
            {
                let pair = (normalize(src), normalize(sink_text));
                if !pairs.contains(&pair) {
                    pairs.push(pair);
                }
            }
        }
        if pairs.is_empty() {
            return Vec::new();
        }

        let listed: Vec<String> = pairs
            .iter()
            .take(6)
            .map(|(src, sink)| format!("`{src}` → `{sink}`"))
            .collect();
        let id = ex.id;
        vec![finding(
            "Potential DOM-based XSS (source near sink)",
            Severity::Low,
            Confidence::Tentative,
            format!(
                "This response's script places an attacker-influenced DOM source next to a \
                 dangerous sink: {}. If the source value reaches the sink without sanitisation, \
                 it is a DOM-based cross-site scripting flaw. Static proximity is a *candidate* \
                 only — confirm the data flow in a browser (e.g. with a DOM source-to-sink \
                 inspector) and apply contextual encoding or a safe sink (`textContent`, \
                 `setHTML`/sanitizer).",
                listed.join(", ")
            ),
            id,
        )]
    }
}

/// Collect sink match spans (start, end, text).
fn sink_re_iter<'a>(re: &Regex, body: &'a str) -> Vec<(usize, usize, &'a str)> {
    re.find_iter(body)
        .map(|m| (m.start(), m.end(), m.as_str()))
        .collect()
}

/// Collapse internal whitespace so `location .  hash` and `.innerHTML  =` render
/// tidily in the finding.
fn normalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn ex_with_body(body: &str) -> HttpExchange {
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text(body),
        };
        HttpExchange::new(HttpRequest::get("https://x.test/app.js"), Source::Scanner)
            .with_response(resp)
    }

    #[test]
    fn flags_hash_into_innerhtml() {
        let js = "var out = document.getElementById('o'); out.innerHTML = location.hash.slice(1);";
        let f = DomXssSinks.check(&ex_with_body(js));
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("location.hash"));
        assert!(f[0].detail.contains("innerHTML"));
        assert_eq!(f[0].severity, Severity::Low);
        assert_eq!(f[0].confidence, Confidence::Tentative);
    }

    #[test]
    fn flags_referrer_into_document_write() {
        let js = "document.write('<img src='+document.referrer+'>');";
        assert_eq!(DomXssSinks.check(&ex_with_body(js)).len(), 1);
    }

    #[test]
    fn flags_window_name_into_eval() {
        let js = "eval(window.name);";
        assert_eq!(DomXssSinks.check(&ex_with_body(js)).len(), 1);
    }

    #[test]
    fn does_not_flag_sink_without_a_nearby_source() {
        // innerHTML with a safe, constant string, and a source far away.
        let js = "el.innerHTML = '<b>static</b>';".to_string()
            + &" ".repeat(600)
            + "var p = location.href;";
        assert!(DomXssSinks.check(&ex_with_body(&js)).is_empty());
    }

    #[test]
    fn does_not_flag_source_without_a_sink() {
        let js = "var h = location.hash; console.log(h); el.textContent = h;";
        assert!(DomXssSinks.check(&ex_with_body(js)).is_empty());
    }

    #[test]
    fn no_response_no_finding() {
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner);
        assert!(DomXssSinks.check(&ex).is_empty());
    }

    #[test]
    fn safe_navigation_methods_are_not_sources() {
        // location.assign/replace/reload are navigations, not injectable sources;
        // paired with innerHTML they must not trigger on their own.
        let js = "location.assign('/next'); el.innerHTML = '<b>x</b>';";
        assert!(DomXssSinks.check(&ex_with_body(js)).is_empty());
    }
}
