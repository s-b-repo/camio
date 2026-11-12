//! Reflected-input check (plan §8 "Scan & crawl"; §10 "payload reflections").
//!
//! A request parameter value echoed verbatim into the response body is a
//! candidate reflected-XSS sink. This is a passive signal only (no payloads are
//! sent), so findings are [`Confidence::Tentative`]. Query-string and
//! `application/x-www-form-urlencoded` body parameters are both considered.

use crate::checks::{finding, form_pairs};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Minimum decoded value length considered interesting (shorter values reflect
/// by coincidence too often).
const MIN_VALUE_LEN: usize = 4;

/// Flags request parameter values that appear verbatim in the response body.
pub struct ReflectedInput;

impl ReflectedInput {
    /// Collect `(name, value)` pairs from the URL query and, when the request is
    /// form-urlencoded, the body.
    fn parameters(ex: &HttpExchange) -> Vec<(String, String)> {
        let mut params = Vec::new();
        if let Some(q) = ex.request.query() {
            params.extend(form_pairs(&q));
        }
        let is_form = ex
            .request
            .headers
            .get("Content-Type")
            .map(|ct| {
                ct.to_ascii_lowercase()
                    .contains("application/x-www-form-urlencoded")
            })
            .unwrap_or(false);
        if is_form {
            params.extend(form_pairs(&ex.request.body.as_text()));
        }
        params
    }
}

impl PassiveCheck for ReflectedInput {
    fn id(&self) -> &'static str {
        "reflected-input"
    }

    fn title(&self) -> &'static str {
        "Reflected input in response"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        let body = resp.body.as_text();

        let mut out = Vec::new();
        let mut seen: Vec<(String, String)> = Vec::new();
        for (name, value) in Self::parameters(ex) {
            if value.len() < MIN_VALUE_LEN {
                continue;
            }
            if value.bytes().all(|b| b.is_ascii_digit()) {
                continue; // purely numeric: too noisy to be a useful signal
            }
            if !body.contains(value.as_str()) {
                continue;
            }
            let key = (name.clone(), value.clone());
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            out.push(finding(
                format!("Reflected input in response (`{name}`)"),
                Severity::Medium,
                Confidence::Tentative,
                format!(
                    "The value of parameter `{name}` (`{value}`) is reflected verbatim in the response body. If it reaches an HTML/script context without contextual output encoding this is a reflected cross-site scripting (XSS) vector. Verify the output context and encoding."
                ),
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

    fn exchange(url: &str, ct: Option<&str>, req_body: &str, resp_body: &str) -> HttpExchange {
        let mut req = HttpRequest::get(url);
        if let Some(ct) = ct {
            req.method = "POST".into();
            req.headers.push("Content-Type", ct);
            req.body = Body::from_text(req_body);
        }
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text(resp_body),
        };
        HttpExchange::new(req, Source::Scanner).with_response(resp)
    }

    #[test]
    fn flags_reflected_query_value() {
        let ex = exchange(
            "https://x.test/search?q=camiomarker",
            None,
            "",
            "<p>Results for camiomarker</p>",
        );
        let f = ReflectedInput.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Reflected input in response (`q`)");
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].confidence, Confidence::Tentative);
        assert!(f[0].detail.contains("camiomarker"));
    }

    #[test]
    fn decodes_before_matching() {
        // %3C etc decode to <script>, which appears in the body.
        let ex = exchange(
            "https://x.test/?name=%3Csvgonload%3E",
            None,
            "",
            "hello <svgonload> world",
        );
        assert_eq!(ReflectedInput.check(&ex).len(), 1);
    }

    #[test]
    fn flags_reflected_form_body_value() {
        let ex = exchange(
            "https://x.test/comment",
            Some("application/x-www-form-urlencoded"),
            "msg=reflectme&other=1",
            "<div>reflectme</div>",
        );
        let f = ReflectedInput.check(&ex);
        assert!(f.iter().any(|x| x.title.contains("`msg`")));
    }

    #[test]
    fn ignores_short_and_numeric_values() {
        // `q=ab` is too short; `n=12345` is purely numeric.
        let ex = exchange(
            "https://x.test/?q=ab&n=12345",
            None,
            "",
            "echo ab and 12345 here",
        );
        assert!(ReflectedInput.check(&ex).is_empty());
    }

    #[test]
    fn non_reflected_value_does_not_fire() {
        let ex = exchange(
            "https://x.test/?q=camiomarker",
            None,
            "",
            "<p>nothing echoed</p>",
        );
        assert!(ReflectedInput.check(&ex).is_empty());
    }

    #[test]
    fn body_params_ignored_without_form_content_type() {
        // Same value in a JSON body is not parsed as form params here.
        let ex = exchange(
            "https://x.test/api",
            Some("application/json"),
            "{\"msg\":\"reflectme\"}",
            "reflectme",
        );
        // No query params, and body isn't urlencoded -> no parameter extracted.
        assert!(ReflectedInput.check(&ex).is_empty());
    }

    #[test]
    fn duplicate_reflections_reported_once() {
        let ex = exchange(
            "https://x.test/?q=camiomarker&q=camiomarker",
            None,
            "",
            "camiomarker camiomarker",
        );
        assert_eq!(ReflectedInput.check(&ex).len(), 1);
    }

    #[test]
    fn no_response_no_findings() {
        let ex = HttpExchange::new(
            HttpRequest::get("https://x.test/?q=camiomarker"),
            Source::Scanner,
        );
        assert!(ReflectedInput.check(&ex).is_empty());
    }
}
