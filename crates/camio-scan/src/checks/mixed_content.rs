//! Mixed-content check (plan §8 "Scan & crawl").
//!
//! An HTTPS page that pulls `http://` resources via `src=`/`href=` undermines
//! the page's transport security (the browser blocks or downgrades them). We
//! surface a few example references as evidence.

use crate::checks::{finding, http_resource_re, is_html, request_is_https};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Maximum example URLs to include in the finding detail.
const MAX_EXAMPLES: usize = 5;

/// Flags HTTPS HTML responses that reference `http://` resources.
pub struct MixedContent;

impl PassiveCheck for MixedContent {
    fn id(&self) -> &'static str {
        "mixed-content"
    }

    fn title(&self) -> &'static str {
        "Mixed content on HTTPS page"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        if !request_is_https(ex) {
            return Vec::new();
        }
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        if !is_html(resp) {
            return Vec::new();
        }
        let Some(re) = http_resource_re() else {
            return Vec::new();
        };

        let body = resp.body.as_text();
        let mut examples: Vec<String> = Vec::new();
        for caps in re.captures_iter(&body) {
            if let Some(m) = caps.get(1) {
                let url = m.as_str().to_string();
                if !examples.contains(&url) {
                    examples.push(url);
                }
                if examples.len() >= MAX_EXAMPLES {
                    break;
                }
            }
        }
        if examples.is_empty() {
            return Vec::new();
        }

        vec![finding(
            "Mixed content: HTTP resources on an HTTPS page",
            Severity::Low,
            Confidence::Firm,
            format!(
                "The HTTPS page references `http://` resources via `src`/`href`, which browsers block or downgrade and which weaken the page's integrity guarantees. Serve these over HTTPS. Examples:\n{}",
                examples
                    .iter()
                    .map(|u| format!("- `{u}`"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(url: &str, ct: &str, body: &str) -> HttpExchange {
        let mut h = HeaderList::new();
        h.push("Content-Type", ct);
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
    fn flags_http_script_on_https_page() {
        let ex = exchange(
            "https://x.test/",
            "text/html",
            r#"<html><head><script src="http://cdn.test/a.js"></script></head></html>"#,
        );
        let f = MixedContent.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
        assert!(f[0].detail.contains("http://cdn.test/a.js"));
    }

    #[test]
    fn flags_http_href_and_dedups_examples() {
        let ex = exchange(
            "https://x.test/",
            "text/html",
            r#"<link href="http://cdn.test/s.css"><link href="http://cdn.test/s.css">"#,
        );
        let f = MixedContent.check(&ex);
        assert_eq!(f.len(), 1);
        // The duplicate URL appears once in the detail list.
        assert_eq!(f[0].detail.matches("http://cdn.test/s.css").count(), 1);
    }

    #[test]
    fn all_https_references_do_not_fire() {
        let ex = exchange(
            "https://x.test/",
            "text/html",
            r#"<script src="https://cdn.test/a.js"></script>"#,
        );
        assert!(MixedContent.check(&ex).is_empty());
    }

    #[test]
    fn http_page_is_not_mixed_content() {
        let ex = exchange(
            "http://x.test/",
            "text/html",
            r#"<script src="http://cdn.test/a.js"></script>"#,
        );
        assert!(MixedContent.check(&ex).is_empty());
    }

    #[test]
    fn non_html_response_skipped() {
        let ex = exchange(
            "https://x.test/data",
            "application/json",
            r#"{"u":"http://cdn.test/a.js"}"#,
        );
        assert!(MixedContent.check(&ex).is_empty());
    }

    #[test]
    fn no_response_no_findings() {
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner);
        assert!(MixedContent.check(&ex).is_empty());
    }
}
