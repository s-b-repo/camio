//! Hard-coded-secret-in-response check (plan §8 "Scan & crawl"; §16 privacy).
//!
//! Front-end bundles, JSON config blobs and verbose error pages sometimes ship
//! live credentials — cloud access keys, API tokens, private-key blocks. This
//! check scans the response body (any content type; JavaScript/JSON are the most
//! relevant) with the shared [`crate::checks::find_secrets`] scanner — the same
//! machinery behind [`crate::analyze_js`] — and reports the *kinds* matched with
//! a redacted four-character preview. The secret itself is never echoed, so the
//! finding does not re-leak it (plan §16).

use crate::checks::{find_secrets, finding};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Flags response bodies that contain hard-coded secrets.
pub struct JsSecretsLeak;

impl PassiveCheck for JsSecretsLeak {
    fn id(&self) -> &'static str {
        "js-secrets-leak"
    }

    fn title(&self) -> &'static str {
        "Hard-coded secret in response"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        let body = resp.body.as_text();
        let hits = find_secrets(&body);
        if hits.is_empty() {
            return Vec::new();
        }

        let listed = hits
            .iter()
            .map(|h| format!("{} (`{}`)", h.kind, h.redacted))
            .collect::<Vec<_>>()
            .join(", ");
        vec![finding(
            "Hard-coded secret in response",
            Severity::High,
            Confidence::Firm,
            format!(
                "The response body contains what looks like hard-coded secret(s): {listed}. Previews are truncated to four characters and the full values are omitted here to avoid re-leaking them. Treat any exposed credential as compromised: rotate it and remove secrets from client-delivered code."
            ),
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(content_type: &str, body: &str) -> HttpExchange {
        let mut h = HeaderList::new();
        h.push("Content-Type", content_type);
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(body),
        };
        HttpExchange::new(HttpRequest::get("https://x.test/app.js"), Source::Scanner)
            .with_response(resp)
    }

    #[test]
    fn flags_aws_access_key() {
        let ex = exchange(
            "application/javascript",
            "const cfg = { key: \"AKIAIOSFODNN7EXAMPLE\" };",
        );
        let f = JsSecretsLeak.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Hard-coded secret in response");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].confidence, Confidence::Firm);
    }

    #[test]
    fn secret_value_is_not_echoed_verbatim() {
        // The full AWS key must never appear in the finding; only a redacted
        // 4-char preview may.
        let ex = exchange(
            "text/javascript",
            "var k = \"AKIAIOSFODNN7EXAMPLE\"; // deploy key",
        );
        let f = JsSecretsLeak.check(&ex);
        assert_eq!(f.len(), 1);
        assert!(
            !f[0].detail.contains("AKIAIOSFODNN7EXAMPLE"),
            "detail must not echo the full secret"
        );
        assert!(f[0].detail.contains("AKIA…"), "redacted preview expected");
    }

    #[test]
    fn flags_generic_credential_assignment_without_leaking_value() {
        let ex = exchange(
            "application/json",
            "{ \"api_key\": \"SuperSecretValue1234567890\" }",
        );
        let f = JsSecretsLeak.check(&ex);
        assert_eq!(f.len(), 1);
        assert!(!f[0].detail.contains("SuperSecretValue1234567890"));
    }

    #[test]
    fn clean_body_does_not_fire() {
        let ex = exchange(
            "application/javascript",
            "function add(a, b) { return a + b; }",
        );
        assert!(JsSecretsLeak.check(&ex).is_empty());
    }

    #[test]
    fn no_response_no_findings() {
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/app.js"), Source::Scanner);
        assert!(JsSecretsLeak.check(&ex).is_empty());
    }
}
