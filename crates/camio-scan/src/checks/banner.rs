//! Server banner / version-disclosure check (plan §8 "Scan & crawl").
//!
//! Response headers that announce a software version give an attacker a head
//! start on matching the target to known CVEs. This is informational (the fix is
//! configuration), so findings are [`Severity::Info`].

use crate::checks::finding;
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Flags `Server`, `X-Powered-By`, `X-AspNet-Version` and `X-AspNetMvc-Version`
/// response headers whose value contains a digit (i.e. reveals a version).
pub struct ServerBannerDisclosure;

/// Headers that commonly leak a software version.
const BANNER_HEADERS: &[&str] = &[
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
];

impl PassiveCheck for ServerBannerDisclosure {
    fn id(&self) -> &'static str {
        "server-banner-disclosure"
    }

    fn title(&self) -> &'static str {
        "Server/version banner disclosure"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for name in BANNER_HEADERS {
            // A version is any value containing an ASCII digit. Report at most
            // one finding per header name (same title would dedup anyway).
            if let Some(value) = resp
                .headers
                .get_all(name)
                .find(|v| v.chars().any(|c| c.is_ascii_digit()))
            {
                out.push(finding(
                    format!("Version disclosure in `{name}` header"),
                    Severity::Info,
                    Confidence::Firm,
                    format!(
                        "The `{name}` response header reveals a version (`{value}`), helping an attacker fingerprint the stack and target known vulnerabilities. Suppress or genericize it."
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
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(headers: &[(&str, &str)]) -> HttpExchange {
        let mut h = HeaderList::new();
        for (n, v) in headers {
            h.push(*n, *v);
        }
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::empty(),
        };
        HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner).with_response(resp)
    }

    #[test]
    fn flags_versioned_server_header() {
        let ex = exchange(&[("Server", "nginx/1.25.3")]);
        let f = ServerBannerDisclosure.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Version disclosure in `Server` header");
        assert_eq!(f[0].severity, Severity::Info);
        assert!(f[0].detail.contains("nginx/1.25.3"));
    }

    #[test]
    fn flags_each_known_header() {
        let ex = exchange(&[
            ("Server", "Apache/2.4.58"),
            ("X-Powered-By", "PHP/8.3.1"),
            ("X-AspNet-Version", "4.0.30319"),
            ("X-AspNetMvc-Version", "5.2"),
        ]);
        let f = ServerBannerDisclosure.check(&ex);
        assert_eq!(f.len(), 4);
    }

    #[test]
    fn does_not_flag_versionless_banner() {
        // No digit -> no version revealed.
        let ex = exchange(&[("Server", "nginx"), ("X-Powered-By", "Express")]);
        assert!(ServerBannerDisclosure.check(&ex).is_empty());
    }

    #[test]
    fn ignores_unrelated_headers() {
        let ex = exchange(&[("Content-Length", "1024"), ("Date", "Mon, 01 Jan 2024")]);
        assert!(ServerBannerDisclosure.check(&ex).is_empty());
    }

    #[test]
    fn no_response_no_findings() {
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner);
        assert!(ServerBannerDisclosure.check(&ex).is_empty());
    }
}
