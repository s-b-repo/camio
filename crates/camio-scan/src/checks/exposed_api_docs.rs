//! Exposed-API-documentation check (plan §8 "Scan & crawl").
//!
//! A publicly reachable Swagger/OpenAPI schema (or `api-docs` endpoint) hands an
//! attacker a complete, machine-readable map of every parameter and operation —
//! a significant discovery aid. This fires either when the response body is a
//! schema document (`"swagger"`/`"openapi"` keys) or when the request URL names a
//! well-known schema/doc path. Severity is [`Severity::Low`] (exposure, not a
//! direct compromise) with [`Confidence::Firm`].

use crate::checks::finding;
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};
use regex::Regex;
use std::sync::OnceLock;

/// Flags responses or request paths that expose an API schema / documentation.
pub struct ExposedApiDocs;

/// Well-known schema/doc request paths (`/swagger.json`, `/openapi.yaml`,
/// `/swagger/…`, `/api-docs/…`). Case-insensitive because deployments vary the
/// casing. A compile failure degrades to the body check alone.
fn api_docs_path_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)/(swagger|openapi)(\.json|\.yaml|/)|/api-docs/").ok())
        .as_ref()
}

impl PassiveCheck for ExposedApiDocs {
    fn id(&self) -> &'static str {
        "exposed-api-docs"
    }

    fn title(&self) -> &'static str {
        "API schema / documentation exposed"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let path_match = api_docs_path_re()
            .map(|re| re.is_match(&ex.request.path()))
            .unwrap_or(false);
        let body_match = ex
            .response
            .as_ref()
            .map(|r| {
                let body = r.body.as_text();
                body.contains("\"swagger\"") || body.contains("\"openapi\"")
            })
            .unwrap_or(false);

        if !(path_match || body_match) {
            return Vec::new();
        }

        vec![finding(
            "API schema / documentation exposed",
            Severity::Low,
            Confidence::Firm,
            "The response or its URL exposes a machine-readable API description (Swagger/OpenAPI, or an `api-docs` endpoint). This gives an attacker a complete map of parameters, operations and models. Restrict schema and documentation endpoints to authenticated internal users, or disable them in production.",
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(url: &str, body: &str) -> HttpExchange {
        let mut h = HeaderList::new();
        h.push("Content-Type", "application/json");
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
    fn flags_openapi_document_body() {
        let ex = exchange(
            "https://x.test/v3/spec",
            r#"{"openapi":"3.0.0","paths":{"/pets":{}}}"#,
        );
        let f = ExposedApiDocs.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "API schema / documentation exposed");
        assert_eq!(f[0].severity, Severity::Low);
        assert_eq!(f[0].confidence, Confidence::Firm);
    }

    #[test]
    fn flags_swagger_body() {
        let ex = exchange("https://x.test/spec", r#"{"swagger":"2.0"}"#);
        assert_eq!(ExposedApiDocs.check(&ex).len(), 1);
    }

    #[test]
    fn flags_well_known_paths() {
        for url in [
            "https://x.test/swagger.json",
            "https://x.test/openapi.yaml",
            "https://x.test/swagger/index.html",
            "https://x.test/api-docs/",
        ] {
            // Body does not contain the markers; the path alone fires it.
            let ex = exchange(url, "<html>docs ui</html>");
            assert_eq!(ExposedApiDocs.check(&ex).len(), 1, "{url}");
        }
    }

    #[test]
    fn ordinary_page_does_not_fire() {
        // "swagger" mentioned without JSON quoting, benign path.
        let ex = exchange(
            "https://x.test/blog/post",
            "<p>We document our API with swagger internally.</p>",
        );
        assert!(ExposedApiDocs.check(&ex).is_empty());
    }

    #[test]
    fn no_response_but_matching_path_still_fires() {
        let ex = HttpExchange::new(
            HttpRequest::get("https://x.test/swagger.json"),
            Source::Scanner,
        );
        assert_eq!(ExposedApiDocs.check(&ex).len(), 1);
    }
}
