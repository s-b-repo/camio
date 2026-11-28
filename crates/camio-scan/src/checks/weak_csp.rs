//! Weak Content-Security-Policy detection (plan §8 "Scan & crawl").
//!
//! [`MissingSecurityHeaders`](crate::MissingSecurityHeaders) reports when a CSP
//! is *absent*; this check reports a CSP that is *present but weak* — the common
//! real-world case. A policy that keeps `unsafe-inline`/`unsafe-eval`, allows a
//! wildcard or `data:` script source, or has no `object-src`/`base-uri` lockdown
//! gives back most of the XSS mitigation a CSP is meant to provide.

use crate::checks::finding;
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Flags a present-but-weak `Content-Security-Policy`.
pub struct WeakCsp;

/// The fetch directives that matter most for script execution; a weakness in any
/// of them is reported.
fn weaknesses(csp: &str) -> Vec<&'static str> {
    let lower = csp.to_ascii_lowercase();
    // Directive → value map (just the raw directive strings).
    let directives: Vec<(&str, &str)> = lower
        .split(';')
        .filter_map(|d| {
            let d = d.trim();
            let (name, value) = d.split_once(char::is_whitespace).unwrap_or((d, ""));
            if name.is_empty() {
                None
            } else {
                Some((name, value))
            }
        })
        .collect();
    let get = |name: &str| directives.iter().find(|(n, _)| *n == name).map(|(_, v)| *v);
    // The source list that governs scripts: script-src, else default-src.
    let script = get("script-src").or_else(|| get("default-src"));

    let mut out = Vec::new();
    if let Some(src) = script {
        if src.contains("'unsafe-inline'") {
            out.push("script-src allows 'unsafe-inline' (inline scripts/handlers run)");
        }
        if src.contains("'unsafe-eval'") {
            out.push("script-src allows 'unsafe-eval' (eval/new Function run)");
        }
        // A bare `*` or a scheme wildcard lets scripts load from anywhere.
        if src.split_whitespace().any(|t| t == "*" || t == "http:" || t == "https:") {
            out.push("script-src uses a wildcard/scheme source (scripts from any origin)");
        }
        if src.split_whitespace().any(|t| t.starts_with("data:")) {
            out.push("script-src allows data: URIs (a known XSS bypass)");
        }
    }
    // Missing hardening directives that a strong policy sets.
    if get("object-src").is_none() && get("default-src").is_none() {
        out.push("no object-src (plugins/embeds are not locked down)");
    }
    if get("base-uri").is_none() {
        out.push("no base-uri (a <base> injection can hijack relative URLs)");
    }
    out
}

impl PassiveCheck for WeakCsp {
    fn id(&self) -> &'static str {
        "weak-csp"
    }

    fn title(&self) -> &'static str {
        "Weak Content-Security-Policy"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        // Only HTML responses benefit from a script CSP; a JSON API's CSP is moot.
        let is_html = resp
            .headers
            .get("Content-Type")
            .map(|ct| ct.to_ascii_lowercase().contains("text/html"))
            .unwrap_or(false);
        if !is_html {
            return Vec::new();
        }
        let Some(csp) = resp.headers.get("Content-Security-Policy") else {
            // Absent CSP is MissingSecurityHeaders' job, not this check's.
            return Vec::new();
        };
        let found = weaknesses(csp);
        if found.is_empty() {
            return Vec::new();
        }
        let id = ex.id;
        vec![finding(
            "Weak Content-Security-Policy",
            Severity::Low,
            Confidence::Firm,
            format!(
                "The response sets a `Content-Security-Policy`, but it is weak: {}. These keep \
                 most of the cross-site-scripting mitigation a CSP is meant to provide. Tighten \
                 the policy: remove `'unsafe-inline'`/`'unsafe-eval'` (use nonces/hashes), drop \
                 wildcard and `data:` script sources, and set `object-src 'none'` and a `base-uri`.",
                found.join("; ")
            ),
            id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn ex_with_csp(csp: Option<&str>, content_type: &str) -> HttpExchange {
        let mut h = HeaderList::new();
        h.push("Content-Type", content_type);
        if let Some(csp) = csp {
            h.push("Content-Security-Policy", csp);
        }
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text("<html></html>"),
        };
        HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner).with_response(resp)
    }

    #[test]
    fn flags_unsafe_inline_and_eval() {
        let ex = ex_with_csp(
            Some("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'self'"),
            "text/html",
        );
        let f = WeakCsp.check(&ex);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("unsafe-inline"));
        assert!(f[0].detail.contains("unsafe-eval"));
    }

    #[test]
    fn flags_wildcard_and_data_script_source() {
        let ex = ex_with_csp(
            Some("script-src * data:; object-src 'none'; base-uri 'self'"),
            "text/html",
        );
        let f = WeakCsp.check(&ex);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("wildcard"));
        assert!(f[0].detail.contains("data:"));
    }

    #[test]
    fn flags_missing_hardening_directives() {
        // A script-src-only policy with no object-src/base-uri.
        let ex = ex_with_csp(Some("script-src 'self'"), "text/html");
        let f = WeakCsp.check(&ex);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("object-src"));
        assert!(f[0].detail.contains("base-uri"));
    }

    #[test]
    fn a_strong_policy_is_not_flagged() {
        let ex = ex_with_csp(
            Some("default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'self'"),
            "text/html",
        );
        assert!(WeakCsp.check(&ex).is_empty());
    }

    #[test]
    fn absent_csp_is_not_this_checks_job() {
        assert!(WeakCsp.check(&ex_with_csp(None, "text/html")).is_empty());
    }

    #[test]
    fn non_html_responses_are_ignored() {
        let ex = ex_with_csp(Some("script-src 'unsafe-inline'"), "application/json");
        assert!(WeakCsp.check(&ex).is_empty());
    }

    #[test]
    fn no_response_no_finding() {
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner);
        assert!(WeakCsp.check(&ex).is_empty());
    }
}
