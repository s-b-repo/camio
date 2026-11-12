//! Insecure cookie-attribute check (plan §8 "Scan & crawl").
//!
//! Each `Set-Cookie` response header is parsed for the `Secure`, `HttpOnly` and
//! `SameSite` protections. Cookie attribute names are case-insensitive, so the
//! parser lower-cases attribute tokens — but it never rewrites the header, which
//! is only ever read through [`camio_core::HeaderList::get_all`] (plan §6.1).

use crate::checks::{finding, request_is_https};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Flags `Set-Cookie` headers missing `Secure` (on HTTPS), `HttpOnly` or
/// `SameSite`.
pub struct InsecureCookies;

impl PassiveCheck for InsecureCookies {
    fn id(&self) -> &'static str {
        "insecure-cookies"
    }

    fn title(&self) -> &'static str {
        "Insecure cookie attributes"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        let https = request_is_https(ex);
        let mut out = Vec::new();

        for raw in resp.headers.get_all("Set-Cookie") {
            // The cookie name is the key of the first `name=value` pair.
            let name_pair = raw.split(';').next().unwrap_or("");
            let name = name_pair.split('=').next().unwrap_or("").trim();
            // Remaining `;`-separated attribute tokens, lower-cased for matching.
            let attrs: Vec<String> = raw
                .split(';')
                .skip(1)
                .map(|a| a.trim().to_ascii_lowercase())
                .collect();
            let has_flag = |flag: &str| attrs.iter().any(|a| a == flag);
            let has_attr = |key: &str| {
                attrs
                    .iter()
                    .any(|a| a == key || a.starts_with(&format!("{key}=")))
            };

            if https && !has_flag("secure") {
                out.push(finding(
                    format!("Cookie `{name}` missing Secure flag"),
                    Severity::Medium,
                    Confidence::Firm,
                    format!(
                        "The cookie `{name}` is set over HTTPS without the `Secure` flag, so the browser will also send it over plaintext HTTP, exposing it to network attackers. Add `Secure`."
                    ),
                    ex.id,
                ));
            }
            if !has_flag("httponly") {
                out.push(finding(
                    format!("Cookie `{name}` missing HttpOnly flag"),
                    Severity::Low,
                    Confidence::Firm,
                    format!(
                        "The cookie `{name}` lacks the `HttpOnly` flag, so client-side JavaScript can read it; this lets an XSS flaw steal the cookie. Add `HttpOnly` unless the cookie must be script-readable."
                    ),
                    ex.id,
                ));
            }
            if !has_attr("samesite") {
                out.push(finding(
                    format!("Cookie `{name}` missing SameSite attribute"),
                    Severity::Low,
                    Confidence::Firm,
                    format!(
                        "The cookie `{name}` has no `SameSite` attribute, weakening its cross-site request forgery (CSRF) protection. Set `SameSite=Lax` or `Strict` as appropriate."
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

    fn exchange(url: &str, set_cookies: &[&str]) -> HttpExchange {
        let mut h = HeaderList::new();
        for c in set_cookies {
            h.push("Set-Cookie", *c);
        }
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::empty(),
        };
        HttpExchange::new(HttpRequest::get(url), Source::Scanner).with_response(resp)
    }

    fn titles(f: &[Finding]) -> Vec<String> {
        f.iter().map(|x| x.title.clone()).collect()
    }

    #[test]
    fn bare_cookie_on_https_flags_all_three() {
        let ex = exchange("https://x.test/", &["sid=abc"]);
        let f = InsecureCookies.check(&ex);
        assert_eq!(f.len(), 3);
        let t = titles(&f);
        assert!(t.contains(&"Cookie `sid` missing Secure flag".to_string()));
        assert!(t.contains(&"Cookie `sid` missing HttpOnly flag".to_string()));
        assert!(t.contains(&"Cookie `sid` missing SameSite attribute".to_string()));
    }

    #[test]
    fn secure_flag_only_flagged_over_https() {
        let http = exchange("http://x.test/", &["sid=abc; HttpOnly; SameSite=Lax"]);
        assert!(InsecureCookies.check(&http).is_empty());
    }

    #[test]
    fn secure_missing_is_medium_others_low() {
        let ex = exchange("https://x.test/", &["sid=abc"]);
        let f = InsecureCookies.check(&ex);
        let sev = |needle: &str| {
            f.iter()
                .find(|x| x.title.contains(needle))
                .map(|x| x.severity)
        };
        assert_eq!(sev("Secure"), Some(Severity::Medium));
        assert_eq!(sev("HttpOnly"), Some(Severity::Low));
        assert_eq!(sev("SameSite"), Some(Severity::Low));
    }

    #[test]
    fn fully_hardened_cookie_does_not_fire() {
        let ex = exchange(
            "https://x.test/",
            &["sid=abc; Secure; HttpOnly; SameSite=Strict"],
        );
        assert!(InsecureCookies.check(&ex).is_empty());
    }

    #[test]
    fn attribute_matching_is_case_insensitive() {
        let ex = exchange(
            "https://x.test/",
            &["sid=abc; secure; httponly; samesite=lax"],
        );
        assert!(InsecureCookies.check(&ex).is_empty());
    }

    #[test]
    fn each_cookie_reported_independently() {
        let ex = exchange(
            "https://x.test/",
            &["a=1; Secure; HttpOnly; SameSite=Lax", "b=2"],
        );
        let f = InsecureCookies.check(&ex);
        // Only `b` is flagged, three times.
        assert_eq!(f.len(), 3);
        assert!(f.iter().all(|x| x.title.contains("`b`")));
    }

    #[test]
    fn no_response_no_findings() {
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner);
        assert!(InsecureCookies.check(&ex).is_empty());
    }
}
