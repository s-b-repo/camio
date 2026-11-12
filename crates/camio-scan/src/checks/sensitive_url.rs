//! Sensitive-data-in-URL check (plan §8 "Scan & crawl"; §16 privacy).
//!
//! Secrets placed in a URL query leak into browser history, server/proxy access
//! logs and the `Referer` header. This check matches *key names* only and never
//! echoes the value, so the finding itself does not re-leak the secret.

use crate::checks::{finding, form_pairs, sensitive_key_re};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Flags request URL query keys that name a credential or token.
pub struct SensitiveDataInUrl;

impl PassiveCheck for SensitiveDataInUrl {
    fn id(&self) -> &'static str {
        "sensitive-data-in-url"
    }

    fn title(&self) -> &'static str {
        "Sensitive data in URL"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(query) = ex.request.query() else {
            return Vec::new();
        };
        let Some(re) = sensitive_key_re() else {
            return Vec::new();
        };

        let mut out = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for (key, _value) in form_pairs(&query) {
            if re.is_match(&key) && !seen.contains(&key) {
                seen.push(key.clone());
                out.push(finding(
                    format!("Sensitive data in URL query: `{key}`"),
                    Severity::Medium,
                    Confidence::Firm,
                    format!(
                        "The URL query carries a sensitive parameter `{key}`. Values in the URL are recorded in browser history, server and proxy logs and the `Referer` header sent to other origins. Move secrets into the request body or an `Authorization` header. (The value is omitted here to avoid re-leaking it.)"
                    ),
                    ex.id,
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{HttpRequest, Source};

    fn exchange(url: &str) -> HttpExchange {
        HttpExchange::new(HttpRequest::get(url), Source::Scanner)
    }

    #[test]
    fn flags_token_in_query() {
        let f = SensitiveDataInUrl.check(&exchange("https://x.test/cb?token=abc123&page=2"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Sensitive data in URL query: `token`");
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn detail_does_not_leak_the_value() {
        let f = SensitiveDataInUrl.check(&exchange("https://x.test/?password=hunter2"));
        assert_eq!(f.len(), 1);
        assert!(!f[0].detail.contains("hunter2"));
    }

    #[test]
    fn flags_api_key_variants() {
        for url in [
            "https://x.test/?api_key=1",
            "https://x.test/?api-key=1",
            "https://x.test/?apikey=1",
            "https://x.test/?X-Api-Key=1",
        ] {
            assert_eq!(SensitiveDataInUrl.check(&exchange(url)).len(), 1, "{url}");
        }
    }

    #[test]
    fn flags_multiple_distinct_keys() {
        let f = SensitiveDataInUrl.check(&exchange("https://x.test/?token=a&secret=b&id=3"));
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn benign_query_does_not_fire() {
        assert!(SensitiveDataInUrl
            .check(&exchange("https://x.test/?page=2&lang=en&id=7"))
            .is_empty());
    }

    #[test]
    fn no_query_no_findings() {
        assert!(SensitiveDataInUrl
            .check(&exchange("https://x.test/path"))
            .is_empty());
    }
}
