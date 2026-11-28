//! Technology fingerprinting (Wappalyzer / httpx `-tech-detect`) — passive
//! attack-surface discovery (plan §8 "Scan & crawl").
//!
//! This is a thin passive-check wrapper over the Wappalyzer-schema engine in
//! [`super::techdb`], which does the real work: regex-driven matching of
//! headers, cookies, meta tags, script sources and body markers, with version
//! extraction, confidence and `implies` resolution. Knowing the stack (and its
//! version) focuses testing on the right weak points. Passive: no requests.

use crate::checks::finding;
use crate::checks::techdb::{DetectedTech, TechDb};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, HttpResponse, Severity};

/// Fingerprint every technology (with version/implies) in a response, using the
/// default embedded database.
pub fn detect(resp: &HttpResponse) -> Vec<DetectedTech> {
    TechDb::default_db().detect(resp)
}

/// Passive technology fingerprinter.
pub struct TechFingerprint;

impl PassiveCheck for TechFingerprint {
    fn id(&self) -> &'static str {
        "tech-fingerprint"
    }

    fn title(&self) -> &'static str {
        "Technologies detected"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        let hits = detect(resp);
        if hits.is_empty() {
            return Vec::new();
        }
        let listed = hits
            .iter()
            .map(|t| {
                let ver = t.version.as_deref().map(|v| format!(" {v}")).unwrap_or_default();
                let cat = t.categories.first().cloned().unwrap_or_default();
                let implied = if t.implied { " (implied)" } else { "" };
                format!("`{}{ver}` ({cat}){implied}", t.name)
            })
            .collect::<Vec<_>>()
            .join(", ");
        vec![finding(
            "Technologies detected",
            Severity::Info,
            Confidence::Tentative,
            format!(
                "Fingerprinted {} technolog{} on this target: {listed}. This focuses testing on the stack's known weak points. Detected passively from the captured response (headers/cookies/meta/scripts/body); a signature is a hint, versions are best-effort.",
                hits.len(),
                if hits.len() == 1 { "y" } else { "ies" }
            ),
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn resp_with(headers: &[(&str, &str)], body: &str) -> HttpResponse {
        let mut h = HeaderList::new();
        h.push("Content-Type", "text/html");
        for (k, v) in headers {
            h.push(*k, *v);
        }
        HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(body),
        }
    }

    fn names(resp: &HttpResponse) -> Vec<String> {
        detect(resp).into_iter().map(|t| t.name).collect()
    }

    #[test]
    fn detects_server_and_language_from_headers() {
        let r = resp_with(&[("Server", "nginx/1.25"), ("X-Powered-By", "PHP/8.2")], "<html></html>");
        let n = names(&r);
        assert!(n.contains(&"Nginx".to_string()));
        assert!(n.contains(&"PHP".to_string()));
    }

    #[test]
    fn detects_wordpress_from_body() {
        let r = resp_with(&[], r#"<link href="/wp-content/themes/x/style.css">"#);
        assert!(names(&r).contains(&"WordPress".to_string()));
    }

    #[test]
    fn detects_react_and_jquery_from_body() {
        let r = resp_with(
            &[],
            r#"<div data-reactroot></div><script src="/jquery.min.js"></script>"#,
        );
        let n = names(&r);
        assert!(n.contains(&"React".to_string()));
        assert!(n.contains(&"jQuery".to_string()));
    }

    #[test]
    fn detects_django_from_cookie() {
        let r = resp_with(&[("Set-Cookie", "csrftoken=abc; Path=/")], "<html></html>");
        assert!(names(&r).contains(&"Django".to_string()));
    }

    #[test]
    fn clean_minimal_response_detects_nothing() {
        let r = resp_with(&[], "<html><body>hello</body></html>");
        assert!(detect(&r).is_empty());
    }

    #[test]
    fn check_emits_finding_with_version() {
        let r = resp_with(&[("Server", "Apache/2.4.57")], "<html></html>");
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner)
            .with_response(r);
        let f = TechFingerprint.check(&ex);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("Apache"));
        assert!(f[0].detail.contains("2.4.57"));
    }
}
