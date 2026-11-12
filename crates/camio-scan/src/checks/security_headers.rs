//! Missing HTTP security-header check (plan §8 "Scan & crawl": passive checks
//! that produce findings with severity/confidence and evidence).
//!
//! For rendered documents (`HTML`/`text`, `2xx`) a server should set the common
//! hardening headers. Each absent header is reported as its own finding so
//! deduplication in [`crate::scan_all`] collapses the same gap across many pages
//! of a host while keeping distinct gaps separate.

use crate::checks::{finding, is_2xx, is_html_or_text, request_is_https};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Flags absent `Content-Security-Policy`, `X-Content-Type-Options`,
/// `X-Frame-Options`, `Referrer-Policy` (and, on HTTPS,
/// `Strict-Transport-Security`) on HTML/text `2xx` responses.
pub struct MissingSecurityHeaders;

/// `(header name, severity, explanation)` for the headers checked regardless of
/// scheme. CSP carries the broadest protection, so its absence is `Medium`; the
/// rest are `Low`.
const BASE_HEADERS: &[(&str, Severity, &str)] = &[
    (
        "Content-Security-Policy",
        Severity::Medium,
        "restricts the origins scripts, styles and other resources may load from, sharply limiting the impact of injected markup (XSS)",
    ),
    (
        "X-Content-Type-Options",
        Severity::Low,
        "`nosniff` stops the browser from MIME-sniffing a response into an executable type",
    ),
    (
        "X-Frame-Options",
        Severity::Low,
        "controls whether the page may be framed, mitigating clickjacking (a CSP `frame-ancestors` directive is the modern equivalent)",
    ),
    (
        "Referrer-Policy",
        Severity::Low,
        "controls how much of the URL is sent in the `Referer` header to other origins",
    ),
];

impl PassiveCheck for MissingSecurityHeaders {
    fn id(&self) -> &'static str {
        "missing-security-headers"
    }

    fn title(&self) -> &'static str {
        "Missing security headers"
    }

    fn severity(&self) -> Severity {
        // Nominal/maximum severity emitted by this check.
        Severity::Medium
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        if !is_2xx(resp) || !is_html_or_text(resp) {
            return Vec::new();
        }

        let mut out = Vec::new();
        for (name, severity, why) in BASE_HEADERS {
            if resp.headers.get(name).is_none() {
                out.push(finding(
                    format!("Missing security header: {name}"),
                    *severity,
                    Confidence::Firm,
                    format!(
                        "The response omits the `{name}` header, which {why}. Add it with a value appropriate to the application."
                    ),
                    ex.id,
                ));
            }
        }

        // HSTS only makes sense (and is only honored) over HTTPS.
        if request_is_https(ex) && resp.headers.get("Strict-Transport-Security").is_none() {
            out.push(finding(
                "Missing security header: Strict-Transport-Security",
                Severity::Medium,
                Confidence::Firm,
                "The HTTPS response omits the `Strict-Transport-Security` header, which tells the browser to use HTTPS for future requests and defeats SSL-stripping downgrade attacks. Add it (e.g. `max-age=31536000; includeSubDomains`).",
                ex.id,
            ));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn resp(status: u16, ct: &str, headers: &[(&str, &str)]) -> HttpResponse {
        let mut h = HeaderList::new();
        h.push("Content-Type", ct);
        for (n, v) in headers {
            h.push(*n, *v);
        }
        HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text("<html></html>"),
        }
    }

    fn exchange(url: &str, resp: Option<HttpResponse>) -> HttpExchange {
        let ex = HttpExchange::new(HttpRequest::get(url), Source::Scanner);
        match resp {
            Some(r) => ex.with_response(r),
            None => ex,
        }
    }

    #[test]
    fn flags_all_missing_headers_on_https_html() {
        let ex = exchange("https://x.test/", Some(resp(200, "text/html", &[])));
        let f = MissingSecurityHeaders.check(&ex);
        let titles: Vec<&str> = f.iter().map(|x| x.title.as_str()).collect();
        assert!(titles.contains(&"Missing security header: Content-Security-Policy"));
        assert!(titles.contains(&"Missing security header: X-Content-Type-Options"));
        assert!(titles.contains(&"Missing security header: X-Frame-Options"));
        assert!(titles.contains(&"Missing security header: Referrer-Policy"));
        assert!(titles.contains(&"Missing security header: Strict-Transport-Security"));
        assert_eq!(f.len(), 5);
    }

    #[test]
    fn csp_and_hsts_are_medium_others_low() {
        let ex = exchange("https://x.test/", Some(resp(200, "text/html", &[])));
        let f = MissingSecurityHeaders.check(&ex);
        let sev = |t: &str| f.iter().find(|x| x.title == t).map(|x| x.severity);
        assert_eq!(
            sev("Missing security header: Content-Security-Policy"),
            Some(Severity::Medium)
        );
        assert_eq!(
            sev("Missing security header: Strict-Transport-Security"),
            Some(Severity::Medium)
        );
        assert_eq!(
            sev("Missing security header: X-Frame-Options"),
            Some(Severity::Low)
        );
        assert_eq!(
            sev("Missing security header: Referrer-Policy"),
            Some(Severity::Low)
        );
    }

    #[test]
    fn no_hsts_finding_over_plain_http() {
        let ex = exchange("http://x.test/", Some(resp(200, "text/html", &[])));
        let f = MissingSecurityHeaders.check(&ex);
        assert!(!f
            .iter()
            .any(|x| x.title.contains("Strict-Transport-Security")));
        // The four scheme-independent headers still fire.
        assert_eq!(f.len(), 4);
    }

    #[test]
    fn does_not_fire_when_all_headers_present() {
        let present = resp(
            200,
            "text/html",
            &[
                ("Content-Security-Policy", "default-src 'self'"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
                ("Strict-Transport-Security", "max-age=31536000"),
            ],
        );
        let ex = exchange("https://x.test/", Some(present));
        assert!(MissingSecurityHeaders.check(&ex).is_empty());
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        // Lower-cased header names must satisfy the check (HTTP names are
        // case-insensitive); we must not report them missing.
        let present = resp(
            200,
            "text/html",
            &[
                ("content-security-policy", "default-src 'self'"),
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "DENY"),
                ("referrer-policy", "no-referrer"),
                ("strict-transport-security", "max-age=1"),
            ],
        );
        let ex = exchange("https://x.test/", Some(present));
        assert!(MissingSecurityHeaders.check(&ex).is_empty());
    }

    #[test]
    fn skips_non_html_and_non_2xx_and_responseless() {
        let json = exchange("https://x.test/", Some(resp(200, "application/json", &[])));
        assert!(MissingSecurityHeaders.check(&json).is_empty());

        let err = exchange("https://x.test/", Some(resp(500, "text/html", &[])));
        assert!(MissingSecurityHeaders.check(&err).is_empty());

        let none = exchange("https://x.test/", None);
        assert!(MissingSecurityHeaders.check(&none).is_empty());
    }

    #[test]
    fn evidence_points_at_the_exchange() {
        let mut ex = exchange("https://x.test/", Some(resp(200, "text/html", &[])));
        ex.id = camio_core::ExchangeId(42);
        let f = MissingSecurityHeaders.check(&ex);
        assert!(f
            .iter()
            .all(|x| x.evidence == vec![camio_core::ExchangeId(42)]));
        assert!(f
            .iter()
            .all(|x| x.id == camio_core::FindingId(0) && x.created_at_ms == 0));
    }
}
