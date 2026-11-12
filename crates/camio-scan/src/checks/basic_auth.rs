//! HTTP Basic auth over cleartext check (plan §8 "Scan & crawl").
//!
//! `Authorization: Basic …` is Base64, not encryption. Sent over `http://` the
//! credentials are trivially recoverable by anyone on the network path.

use crate::checks::finding;
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Flags requests carrying HTTP Basic credentials over a plaintext `http://`
/// scheme.
pub struct BasicAuthOverHttp;

impl PassiveCheck for BasicAuthOverHttp {
    fn id(&self) -> &'static str {
        "basic-auth-over-http"
    }

    fn title(&self) -> &'static str {
        "HTTP Basic auth over cleartext"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        // Only plaintext http:// is at risk.
        if ex.request.scheme().as_deref() != Some("http") {
            return Vec::new();
        }
        let Some(auth) = ex.request.headers.get("Authorization") else {
            return Vec::new();
        };
        if !auth.trim_start().to_ascii_lowercase().starts_with("basic ") {
            return Vec::new();
        }

        vec![finding(
            "HTTP Basic credentials sent over cleartext HTTP",
            Severity::Medium,
            Confidence::Firm,
            "The request sends an `Authorization: Basic` header over plaintext `http://`. Basic auth is Base64-encoded, not encrypted, so anyone on the network path can recover the username and password. Require HTTPS for authenticated requests.",
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{HttpRequest, Source};

    fn exchange(url: &str, auth: Option<&str>) -> HttpExchange {
        let mut req = HttpRequest::get(url);
        if let Some(a) = auth {
            req.headers.push("Authorization", a);
        }
        HttpExchange::new(req, Source::Scanner)
    }

    #[test]
    fn flags_basic_auth_over_http() {
        let ex = exchange("http://x.test/", Some("Basic dXNlcjpwYXNz"));
        let f = BasicAuthOverHttp.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(
            f[0].title,
            "HTTP Basic credentials sent over cleartext HTTP"
        );
    }

    #[test]
    fn scheme_matching_is_case_insensitive_for_basic() {
        let ex = exchange("http://x.test/", Some("basic dXNlcjpwYXNz"));
        assert_eq!(BasicAuthOverHttp.check(&ex).len(), 1);
    }

    #[test]
    fn https_basic_auth_is_fine() {
        let ex = exchange("https://x.test/", Some("Basic dXNlcjpwYXNz"));
        assert!(BasicAuthOverHttp.check(&ex).is_empty());
    }

    #[test]
    fn bearer_token_over_http_not_flagged_by_this_check() {
        let ex = exchange("http://x.test/", Some("Bearer abc.def.ghi"));
        assert!(BasicAuthOverHttp.check(&ex).is_empty());
    }

    #[test]
    fn no_auth_header_no_finding() {
        let ex = exchange("http://x.test/", None);
        assert!(BasicAuthOverHttp.check(&ex).is_empty());
    }
}
