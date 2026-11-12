//! CORS misconfiguration check (plan §8 "Scan & crawl").
//!
//! The dangerous combinations are a wildcard or request-reflected
//! `Access-Control-Allow-Origin` together with
//! `Access-Control-Allow-Credentials: true` (any origin can read authenticated
//! responses). A lone wildcard without credentials is a low-severity note.

use crate::checks::finding;
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Flags permissive CORS response headers.
pub struct CorsMisconfig;

impl PassiveCheck for CorsMisconfig {
    fn id(&self) -> &'static str {
        "cors-misconfig"
    }

    fn title(&self) -> &'static str {
        "CORS misconfiguration"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        let Some(acao) = resp.headers.get("Access-Control-Allow-Origin") else {
            return Vec::new();
        };
        let acao = acao.trim();
        let credentials = resp
            .headers
            .get("Access-Control-Allow-Credentials")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if acao == "*" {
            if credentials {
                return vec![finding(
                    "CORS: wildcard origin with credentials",
                    Severity::High,
                    Confidence::Firm,
                    "The response sets `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`. Any site could read authenticated responses from this origin. Echo only explicitly allow-listed origins, and never pair a wildcard with credentials.",
                    ex.id,
                )];
            }
            return vec![finding(
                "CORS: wildcard Access-Control-Allow-Origin",
                Severity::Low,
                Confidence::Firm,
                "The response sets `Access-Control-Allow-Origin: *`, letting any origin read it. This is acceptable only for genuinely public, non-authenticated data. Restrict it if the resource is sensitive.",
                ex.id,
            )];
        }

        // Non-wildcard ACAO that exactly reflects the request Origin, with
        // credentials, is as dangerous as a wildcard-with-credentials.
        if credentials {
            if let Some(origin) = ex.request.headers.get("Origin") {
                let origin = origin.trim();
                if !origin.is_empty() && acao == origin {
                    return vec![finding(
                        "CORS: reflected Origin with credentials",
                        Severity::High,
                        Confidence::Firm,
                        format!(
                            "The response reflects the request `Origin` (`{origin}`) into `Access-Control-Allow-Origin` and allows credentials, so an attacker-controlled origin can read authenticated responses. Compare the origin against a strict allow-list instead of echoing it."
                        ),
                        ex.id,
                    )];
                }
            }
        }

        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(origin: Option<&str>, resp_headers: &[(&str, &str)]) -> HttpExchange {
        let mut req = HttpRequest::get("https://api.test/data");
        if let Some(o) = origin {
            req.headers.push("Origin", o);
        }
        let mut h = HeaderList::new();
        for (n, v) in resp_headers {
            h.push(*n, *v);
        }
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::empty(),
        };
        HttpExchange::new(req, Source::Scanner).with_response(resp)
    }

    #[test]
    fn wildcard_with_credentials_is_high() {
        let ex = exchange(
            None,
            &[
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
        );
        let f = CorsMisconfig.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].title, "CORS: wildcard origin with credentials");
    }

    #[test]
    fn wildcard_without_credentials_is_low() {
        let ex = exchange(None, &[("Access-Control-Allow-Origin", "*")]);
        let f = CorsMisconfig.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
        assert_eq!(f[0].title, "CORS: wildcard Access-Control-Allow-Origin");
    }

    #[test]
    fn reflected_origin_with_credentials_is_high() {
        let ex = exchange(
            Some("https://evil.test"),
            &[
                ("Access-Control-Allow-Origin", "https://evil.test"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
        );
        let f = CorsMisconfig.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].title, "CORS: reflected Origin with credentials");
        assert!(f[0].detail.contains("https://evil.test"));
    }

    #[test]
    fn reflected_origin_without_credentials_does_not_fire() {
        let ex = exchange(
            Some("https://evil.test"),
            &[("Access-Control-Allow-Origin", "https://evil.test")],
        );
        assert!(CorsMisconfig.check(&ex).is_empty());
    }

    #[test]
    fn fixed_allowlisted_origin_does_not_fire() {
        // ACAO is a specific origin that does NOT reflect the request Origin.
        let ex = exchange(
            Some("https://evil.test"),
            &[
                ("Access-Control-Allow-Origin", "https://trusted.test"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
        );
        assert!(CorsMisconfig.check(&ex).is_empty());
    }

    #[test]
    fn credentials_value_is_case_insensitive() {
        let ex = exchange(
            None,
            &[
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "TRUE"),
            ],
        );
        assert_eq!(CorsMisconfig.check(&ex)[0].severity, Severity::High);
    }

    #[test]
    fn no_acao_or_no_response_no_findings() {
        let ex = exchange(None, &[("Content-Type", "application/json")]);
        assert!(CorsMisconfig.check(&ex).is_empty());
        let none = HttpExchange::new(HttpRequest::get("https://api.test/"), Source::Scanner);
        assert!(CorsMisconfig.check(&none).is_empty());
    }
}
