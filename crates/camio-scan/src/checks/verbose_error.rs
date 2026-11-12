//! Verbose-error / stack-trace disclosure check (plan §8 "Scan & crawl").
//!
//! Framework stack traces and database error strings leak internals (paths,
//! class names, query fragments) and often indicate an unhandled, potentially
//! injectable code path. The signatures are heuristic, so findings are
//! [`Confidence::Tentative`].

use crate::checks::finding;
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};
use regex::Regex;
use std::sync::OnceLock;

/// Flags response bodies containing stack-trace or database-error signatures.
pub struct VerboseError;

/// Lower-cased substrings that indicate a leaked stack trace or DB error.
const SIGNATURES: &[&str] = &[
    "stack trace",
    "exception in",
    "java.lang.",
    "traceback (most recent call last)",
    "sqlstate",
    "you have an error in your sql syntax",
    "warning: mysql_",
];

/// Oracle `ORA-NNNNN` codes (any length ≥ 3, zero-padded or not), word-bounded so
/// `aurora-`/`fedora-` never match. Replaces the old `ora-0` substring, which
/// missed the very common 5-digit codes (`ORA-12154`, `ORA-28000`, …).
fn oracle_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bora-\d{3,}").ok())
        .as_ref()
}

impl PassiveCheck for VerboseError {
    fn id(&self) -> &'static str {
        "verbose-error"
    }

    fn title(&self) -> &'static str {
        "Verbose error / stack trace disclosed"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        let lower = resp.body.as_text().to_ascii_lowercase();
        let mut matched: Vec<String> = SIGNATURES
            .iter()
            .copied()
            .filter(|s| lower.contains(s))
            .map(|s| s.to_string())
            .collect();
        if let Some(m) = oracle_re().and_then(|re| re.find(&lower)) {
            matched.push(m.as_str().to_string());
        }
        if matched.is_empty() {
            return Vec::new();
        }

        vec![finding(
            "Verbose error / stack trace disclosed",
            Severity::Medium,
            Confidence::Tentative,
            format!(
                "The response body contains error signatures ({}) that leak server internals such as file paths, class names or SQL fragments, and may mark an unhandled (possibly injectable) code path. Return a generic error page and log details server-side.",
                matched
                    .iter()
                    .map(|s| format!("`{s}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(status: u16, body: &str) -> HttpExchange {
        let resp = HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text(body),
        };
        HttpExchange::new(HttpRequest::get("https://x.test/app"), Source::Scanner)
            .with_response(resp)
    }

    #[test]
    fn flags_java_stack_trace() {
        let ex = exchange(500, "java.lang.NullPointerException\n\tat com.app.Foo");
        let f = VerboseError.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].confidence, Confidence::Tentative);
        assert!(f[0].detail.contains("java.lang."));
    }

    #[test]
    fn flags_sql_error() {
        let ex = exchange(200, "You have an error in your SQL syntax near '1'");
        assert_eq!(VerboseError.check(&ex).len(), 1);
    }

    #[test]
    fn flags_python_traceback_and_oracle() {
        assert_eq!(
            VerboseError
                .check(&exchange(500, "Traceback (most recent call last):"))
                .len(),
            1
        );
        assert_eq!(
            VerboseError.check(&exchange(500, "ORA-01234: oops")).len(),
            1
        );
        // 5-digit ORA codes (the common case) must also fire.
        assert_eq!(
            VerboseError
                .check(&exchange(
                    500,
                    "ORA-12154: TNS:could not resolve the connect identifier"
                ))
                .len(),
            1
        );
        // …but a word that merely contains "ora-" must not.
        assert!(VerboseError
            .check(&exchange(200, "Welcome to aurora-12345 cluster"))
            .is_empty());
    }

    #[test]
    fn single_finding_even_with_multiple_signatures() {
        let ex = exchange(
            500,
            "Exception in thread main\nStack trace:\nSQLSTATE[42000]",
        );
        let f = VerboseError.check(&ex);
        assert_eq!(f.len(), 1);
        // All three signatures are named in the one finding's detail.
        assert!(f[0].detail.contains("exception in"));
        assert!(f[0].detail.contains("stack trace"));
        assert!(f[0].detail.contains("sqlstate"));
    }

    #[test]
    fn clean_response_does_not_fire() {
        let ex = exchange(200, "<html><body>All good</body></html>");
        assert!(VerboseError.check(&ex).is_empty());
    }

    #[test]
    fn no_response_no_findings() {
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner);
        assert!(VerboseError.check(&ex).is_empty());
    }
}
