//! JavaScript endpoint-discovery check (plan §8 "Scan & crawl"; §15 Phase 4:
//! *"crawler/discovery"*).
//!
//! Front-end bundles reference the API they talk to as quoted URL/path literals.
//! Harvesting them from an already-captured `.js` response is **passive**
//! attack-surface discovery: no requests are sent — we only read what the browser
//! already fetched. This emits one informational finding listing the referenced
//! endpoints (deduplicated and capped), reusing the same extractor as
//! [`crate::analyze_js`]. The confidence is [`Confidence::Tentative`] because a
//! quoted path literal is a hint, not proof of a live route.

use crate::checks::{extract_endpoints, finding, is_javascript};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Lists endpoints/paths referenced by a JavaScript response body.
pub struct JsEndpoints;

impl PassiveCheck for JsEndpoints {
    fn id(&self) -> &'static str {
        "js-endpoints"
    }

    fn title(&self) -> &'static str {
        "JavaScript endpoints referenced"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        // Only JavaScript resources: a JS content type, or a URL path ending `.js`.
        let is_js = is_javascript(resp) || ex.request.extension().as_deref() == Some(".js");
        if !is_js {
            return Vec::new();
        }

        let endpoints = extract_endpoints(&resp.body.as_text());
        if endpoints.is_empty() {
            return Vec::new();
        }

        let listed = endpoints
            .iter()
            .map(|e| format!("`{e}`"))
            .collect::<Vec<_>>()
            .join(", ");
        vec![finding(
            "JavaScript endpoints referenced",
            Severity::Info,
            Confidence::Tentative,
            format!(
                "This JavaScript references {} endpoint/path literal(s): {listed}. These are automated discovery hints — attack surface the bundle talks to — for further *scoped* testing. No requests were sent to produce this list; it was read from the already-captured response.",
                endpoints.len()
            ),
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(url: &str, content_type: Option<&str>, body: &str) -> HttpExchange {
        let mut h = HeaderList::new();
        if let Some(ct) = content_type {
            h.push("Content-Type", ct);
        }
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(body),
        };
        HttpExchange::new(HttpRequest::get(url), Source::Scanner).with_response(resp)
    }

    #[test]
    fn flags_endpoints_in_javascript_content_type() {
        let ex = exchange(
            "https://x.test/bundle",
            Some("application/javascript"),
            r#"const base = "/api/users"; axios.get("https://api.test/v1/orders");"#,
        );
        let f = JsEndpoints.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "JavaScript endpoints referenced");
        assert_eq!(f[0].severity, Severity::Info);
        assert_eq!(f[0].confidence, Confidence::Tentative);
        assert!(f[0].detail.contains("/api/users"));
        assert!(f[0].detail.contains("https://api.test/v1/orders"));
    }

    #[test]
    fn flags_by_js_url_extension_without_content_type() {
        // No JS content type, but the URL ends `.js` → still scanned.
        let ex = exchange(
            "https://x.test/app.min.js",
            Some("text/plain"),
            r#"fetch("/api/thing");"#,
        );
        let f = JsEndpoints.check(&ex);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("/api/thing"));
    }

    #[test]
    fn non_javascript_response_is_skipped() {
        // An HTML page with the same path literal must NOT be scanned here.
        let ex = exchange(
            "https://x.test/page",
            Some("text/html"),
            r#"<a href="/api/secret">x</a>"#,
        );
        assert!(JsEndpoints.check(&ex).is_empty());
    }

    #[test]
    fn javascript_without_endpoints_does_not_fire() {
        let ex = exchange(
            "https://x.test/app.js",
            Some("application/javascript"),
            "var total = price * qty + tax;",
        );
        assert!(JsEndpoints.check(&ex).is_empty());
    }

    #[test]
    fn no_response_no_findings() {
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/app.js"), Source::Scanner);
        assert!(JsEndpoints.check(&ex).is_empty());
    }
}
