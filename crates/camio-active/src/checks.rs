//! The built-in active checks (plan §8 "opt-in scoped active checks"; plan §15
//! Phase 4 "opt-in active checks with per-check limits, evidence, dedup").
//!
//! Each check implements [`crate::ActiveCheck`]: it enumerates the base request's
//! injectable inputs, de-duplicates them, builds at most ~1 probe per input, and
//! sends each probe through the injected [`Sender`]. Detection is a comparison of
//! the probe response against either the probe marker (reflection) or an
//! unmodified baseline send (differential). All sending — and therefore all
//! scope/confirm/budget enforcement — happens in the caller's [`Sender`].

use crate::params::{dedup_params, discovered_params, with_param};
use crate::{finding, ActiveCheck, Sender};
use camio_automate::{discover_inputs, DiscoveredInput, InputKind};
use camio_core::{Confidence, Finding, HttpRequest, Severity};
use regex::Regex;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Reflected XSS
// ---------------------------------------------------------------------------

/// Distinctive marker embedded in the XSS probe. Alphanumeric so it survives URL
/// encoding unchanged and is extremely unlikely to occur by chance.
const XSS_MARKER: &str = "camioX55";

/// The reflected-XSS probe: the [`XSS_MARKER`] followed by the raw HTML/JS
/// metacharacters that matter (`"`, `'`, `<`, `>`, `/`). If this exact sequence
/// comes back in the response body, those characters were **not** encoded.
const XSS_PROBE: &str = "camioX55\"'><svg/onload=camio>";

/// Reflects an XSS marker into each input and reports the ones that come back
/// unencoded — a candidate reflected cross-site scripting sink confirmed by an
/// actual (scope-gated) send rather than passive observation.
pub struct ReflectedXss;

impl ActiveCheck for ReflectedXss {
    fn id(&self) -> &'static str {
        "reflected-xss"
    }

    fn title(&self) -> &'static str {
        "Reflected cross-site scripting"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn run(&self, base: &HttpRequest, send: &Sender) -> Vec<Finding> {
        let mut out = Vec::new();
        for (kind, name) in dedup_params(discovered_params(base)) {
            let probe = with_param(base, kind, &name, XSS_PROBE);
            let Some(ex) = send(probe) else {
                continue;
            };
            let Some(resp) = &ex.response else {
                continue;
            };
            // The whole probe (marker + raw metacharacters) surviving verbatim
            // means none of `" ' < > /` was HTML-encoded on the way out.
            if resp.body.as_text().contains(XSS_PROBE) {
                out.push(finding(
                    format!("Reflected cross-site scripting (`{name}`)"),
                    Severity::High,
                    Confidence::Tentative,
                    format!(
                        "Parameter `{name}` reflects the probe `{XSS_PROBE}` **unencoded** in the \
                         response body: the `{XSS_MARKER}` marker and its raw `\"`, `'`, `<`, `>` \
                         characters all survive, so a browser parses them as markup. This is a \
                         reflected cross-site scripting (XSS) sink. Confirm the output context and \
                         apply contextual output encoding."
                    ),
                    ex.id,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Error-based SQL injection
// ---------------------------------------------------------------------------

/// Appends a quote to each input and reports a database error that an unmodified
/// baseline send did not already show — error-based SQL injection.
pub struct ErrorBasedSqli;

/// SQL-error signatures, as specified by plan §8's active-check matrix. Combined
/// into one case-insensitive regex compiled at most once. `ora-\d+` matches an
/// Oracle error code (`ORA-00933`); the rest are literal fragments.
fn sql_error_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(you have an error in your sql syntax|sqlstate|ora-\d+|unclosed quotation|pg_query|sqlite3::|mysql_fetch|odbc|syntax error at or near)",
        )
        .ok()
    })
    .as_ref()
}

/// All SQL-error signatures present in `body`, lower-cased for comparison. Empty
/// when the regex failed to compile (degrade to "no finding") or none match.
fn sql_error_signatures(body: &str) -> Vec<String> {
    match sql_error_re() {
        Some(re) => re
            .find_iter(body)
            .map(|m| m.as_str().to_ascii_lowercase())
            .collect(),
        None => Vec::new(),
    }
}

/// De-duplicate discovered inputs by `(kind, name)`, keeping the first value, so
/// a repeated parameter is probed only once.
fn dedup_inputs(inputs: Vec<DiscoveredInput>) -> Vec<DiscoveredInput> {
    let mut seen: Vec<(InputKind, String)> = Vec::new();
    let mut out = Vec::new();
    for input in inputs {
        let key = (input.kind, input.name.clone());
        if !seen.contains(&key) {
            seen.push(key);
            out.push(input);
        }
    }
    out
}

impl ActiveCheck for ErrorBasedSqli {
    fn id(&self) -> &'static str {
        "error-based-sqli"
    }

    fn title(&self) -> &'static str {
        "Error-based SQL injection"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn run(&self, base: &HttpRequest, send: &Sender) -> Vec<Finding> {
        let inputs = dedup_inputs(
            discover_inputs(base)
                .into_iter()
                .filter(|i| matches!(i.kind, InputKind::QueryParam | InputKind::BodyParam))
                .collect(),
        );
        if inputs.is_empty() {
            return Vec::new();
        }

        // Baseline: an unmodified send, so we only flag errors the quote *added*.
        // If the baseline is refused we cannot diff, so we emit nothing.
        let Some(baseline_ex) = send(base.clone()) else {
            return Vec::new();
        };
        let baseline_sigs = match &baseline_ex.response {
            Some(resp) => sql_error_signatures(&resp.body.as_text()),
            None => Vec::new(),
        };

        let mut out = Vec::new();
        for input in inputs {
            // At most two probes: a bare quote, then `')`. Stop at the first that
            // reveals a new database error (per-input probe budget, plan §15).
            for suffix in ["'", "')"] {
                let value = format!("{}{}", input.value, suffix);
                let probe = with_param(base, input.kind, &input.name, &value);
                let Some(ex) = send(probe) else {
                    continue;
                };
                let Some(resp) = &ex.response else {
                    continue;
                };
                let probe_sigs = sql_error_signatures(&resp.body.as_text());
                if let Some(sig) = probe_sigs.iter().find(|s| !baseline_sigs.contains(s)) {
                    let name = &input.name;
                    out.push(finding(
                        format!("Error-based SQL injection (`{name}`)"),
                        Severity::High,
                        Confidence::Firm,
                        format!(
                            "Appending a quote to parameter `{name}` produced a database error \
                             signature (`{sig}`) that the unmodified baseline response did not \
                             contain. The value is concatenated into a SQL statement without \
                             parameterization — an error-based SQL injection. Confirm manually and \
                             remediate with parameterized queries."
                        ),
                        ex.id,
                    ));
                    break;
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Open redirect
// ---------------------------------------------------------------------------

/// Sentinel redirect target. Uses the reserved `.example` TLD so it can never be
/// a real in-scope host; a redirect to it proves the parameter is an unvalidated
/// redirect sink.
const REDIRECT_PROBE: &str = "https://camio-redirect-check.example/";

/// Sets redirect-shaped parameters to a sentinel URL and reports the ones the
/// application actually redirects to — an open redirect.
pub struct OpenRedirect;

/// Parameter names that commonly carry a redirect target. Anchored so only an
/// exact (case-insensitive) name matches — `url` matches, `returnurl` matches,
/// but `author` (merely containing `r`) does not. Compiled at most once.
fn redirect_name_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^(url|next|redirect|redir|return|returnurl|dest|destination|continue|goto|to|u|r|out|link|target)$",
        )
        .ok()
    })
    .as_ref()
}

/// `true` when a `Location` header points at the redirect sentinel, whether as an
/// absolute `http(s)://` URL or a scheme-relative `//host` one.
fn redirects_to_sentinel(location: &str) -> bool {
    let lower = location.trim().to_ascii_lowercase();
    lower.starts_with("https://camio-redirect-check.example")
        || lower.starts_with("http://camio-redirect-check.example")
        || lower.starts_with("//camio-redirect-check.example")
}

impl ActiveCheck for OpenRedirect {
    fn id(&self) -> &'static str {
        "open-redirect"
    }

    fn title(&self) -> &'static str {
        "Open redirect"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn run(&self, base: &HttpRequest, send: &Sender) -> Vec<Finding> {
        let Some(name_re) = redirect_name_re() else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for (kind, name) in dedup_params(discovered_params(base)) {
            if !name_re.is_match(&name) {
                continue;
            }
            let probe = with_param(base, kind, &name, REDIRECT_PROBE);
            let Some(ex) = send(probe) else {
                continue;
            };
            let Some(resp) = &ex.response else {
                continue;
            };
            if !(300..=399).contains(&resp.status) {
                continue;
            }
            let Some(location) = resp.headers.get("Location") else {
                continue;
            };
            if redirects_to_sentinel(location) {
                let status = resp.status;
                out.push(finding(
                    format!("Open redirect (`{name}`)"),
                    Severity::Medium,
                    Confidence::Firm,
                    format!(
                        "Parameter `{name}` was set to the sentinel `{REDIRECT_PROBE}` and the \
                         response redirected to it (HTTP {status}, `Location: {location}`). The \
                         application uses this parameter as an unvalidated redirect target — an \
                         open redirect usable for phishing or token leakage. Restrict redirects to \
                         an allowlist of in-scope destinations."
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
    use camio_core::{
        Body, ExchangeId, HeaderList, HttpExchange, HttpResponse, HttpVersion, Source,
    };
    use std::cell::Cell;

    /// Wrap a response body (200 OK, no headers) into a stored exchange with the
    /// given id, echoing back the request.
    fn ok_exchange(req: HttpRequest, id: i64, body: &str) -> HttpExchange {
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text(body),
        };
        let mut ex = HttpExchange::new(req, Source::Scanner).with_response(resp);
        ex.id = ExchangeId(id);
        ex
    }

    // --- ReflectedXss -----------------------------------------------------

    #[test]
    fn reflected_xss_fires_when_probe_echoed_raw() {
        let base = HttpRequest::get("https://x.test/s?q=hello");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            // Echo the raw probe back (server did not encode it).
            let body = format!("<p>results for {XSS_PROBE}</p>");
            Some(ok_exchange(req, 11, &body))
        };
        let send: &Sender = &sender;
        let findings = ReflectedXss.run(&base, send);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Reflected cross-site scripting (`q`)");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::Tentative);
        assert_eq!(findings[0].evidence, vec![ExchangeId(11)]);
        assert_eq!(calls.get(), 1, "exactly one probe for one input");
    }

    #[test]
    fn reflected_xss_does_not_fire_when_probe_html_encoded() {
        let base = HttpRequest::get("https://x.test/s?q=hello");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            // Server HTML-encodes the metacharacters: marker survives, raw < > " do not.
            let body = "<p>results for camioX55&quot;&#39;&gt;&lt;svg/onload=camio&gt;</p>";
            Some(ok_exchange(req, 12, body))
        };
        let send: &Sender = &sender;
        assert!(ReflectedXss.run(&base, send).is_empty());
        assert_eq!(calls.get(), 1, "still probes once, just no finding");
    }

    #[test]
    fn reflected_xss_one_finding_per_reflecting_param() {
        let base = HttpRequest::get("https://x.test/s?q=hello&p=world");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            let body = format!("<p>{XSS_PROBE}</p>");
            Some(ok_exchange(req, 1, &body))
        };
        let send: &Sender = &sender;
        let findings = ReflectedXss.run(&base, send);
        assert_eq!(findings.len(), 2, "one per reflecting parameter");
        assert_eq!(calls.get(), 2, "one probe per input, no more");
        assert!(findings.iter().any(|f| f.title.contains("`q`")));
        assert!(findings.iter().any(|f| f.title.contains("`p`")));
    }

    #[test]
    fn reflected_xss_probes_each_input_once_only() {
        // Duplicate `q` must be probed a single time.
        let base = HttpRequest::get("https://x.test/s?q=1&q=2");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            Some(ok_exchange(req, 1, "no reflection here"))
        };
        let send: &Sender = &sender;
        assert!(ReflectedXss.run(&base, send).is_empty());
        assert_eq!(calls.get(), 1, "a repeated parameter is one input");
    }

    // --- ErrorBasedSqli ---------------------------------------------------

    #[test]
    fn sqli_fires_when_quote_reveals_new_error() {
        let base = HttpRequest::get("https://x.test/item?id=5");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            // A request carrying an encoded quote (%27) errors; the baseline does not.
            let body = if req.raw().contains("%27") {
                "Warning: You have an error in your SQL syntax near '''"
            } else {
                "<html>item 5</html>"
            };
            Some(ok_exchange(req, 21, body))
        };
        let send: &Sender = &sender;
        let findings = ErrorBasedSqli.run(&base, send);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Error-based SQL injection (`id`)");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::Firm);
        assert_eq!(findings[0].evidence, vec![ExchangeId(21)]);
        // One baseline + one quote probe (short-circuits before the `')` probe).
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn sqli_does_not_fire_when_baseline_already_errors() {
        // The page always shows a SQL error, so the quote adds nothing new.
        let base = HttpRequest::get("https://x.test/item?id=5");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            Some(ok_exchange(
                req,
                1,
                "ORA-00933: SQL command not properly ended",
            ))
        };
        let send: &Sender = &sender;
        assert!(ErrorBasedSqli.run(&base, send).is_empty());
        // Baseline + both probes, since nothing ever fires.
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn sqli_does_not_fire_without_any_error() {
        let base = HttpRequest::get("https://x.test/item?id=5");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            Some(ok_exchange(req, 1, "<html>all good</html>"))
        };
        let send: &Sender = &sender;
        assert!(ErrorBasedSqli.run(&base, send).is_empty());
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn sqli_sends_nothing_without_inputs() {
        let base = HttpRequest::get("https://x.test/static");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            Some(ok_exchange(req, 1, "x"))
        };
        let send: &Sender = &sender;
        assert!(ErrorBasedSqli.run(&base, send).is_empty());
        assert_eq!(calls.get(), 0, "no baseline send when there are no inputs");
    }

    #[test]
    fn sqli_emits_nothing_when_baseline_refused() {
        let base = HttpRequest::get("https://x.test/item?id=5");
        let calls = Cell::new(0usize);
        let sender = |_req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            None // every send refused
        };
        let send: &Sender = &sender;
        assert!(ErrorBasedSqli.run(&base, send).is_empty());
        assert_eq!(calls.get(), 1, "stops after the baseline is refused");
    }

    // --- OpenRedirect -----------------------------------------------------

    fn redirect_exchange(
        req: HttpRequest,
        id: i64,
        status: u16,
        location: Option<&str>,
    ) -> HttpExchange {
        let mut headers = HeaderList::new();
        if let Some(loc) = location {
            headers.push("Location", loc);
        }
        let resp = HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers,
            body: Body::empty(),
        };
        let mut ex = HttpExchange::new(req, Source::Scanner).with_response(resp);
        ex.id = ExchangeId(id);
        ex
    }

    #[test]
    fn open_redirect_fires_on_302_to_sentinel() {
        let base = HttpRequest::get("https://x.test/login?next=/home");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            Some(redirect_exchange(
                req,
                31,
                302,
                Some("https://camio-redirect-check.example/"),
            ))
        };
        let send: &Sender = &sender;
        let findings = OpenRedirect.run(&base, send);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Open redirect (`next`)");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].confidence, Confidence::Firm);
        assert_eq!(findings[0].evidence, vec![ExchangeId(31)]);
        assert_eq!(calls.get(), 1, "only the redirect-shaped param is probed");
    }

    #[test]
    fn open_redirect_ignores_non_redirect_param_names() {
        // `q` is not a redirect-shaped name, so nothing is sent at all.
        let base = HttpRequest::get("https://x.test/s?q=hello");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            Some(redirect_exchange(req, 1, 302, Some(REDIRECT_PROBE)))
        };
        let send: &Sender = &sender;
        assert!(OpenRedirect.run(&base, send).is_empty());
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn open_redirect_does_not_fire_without_3xx() {
        let base = HttpRequest::get("https://x.test/login?url=/home");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            // 200, not a redirect.
            Some(redirect_exchange(req, 1, 200, Some(REDIRECT_PROBE)))
        };
        let send: &Sender = &sender;
        assert!(OpenRedirect.run(&base, send).is_empty());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn open_redirect_does_not_fire_when_location_is_elsewhere() {
        let base = HttpRequest::get("https://x.test/login?redirect=/home");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            Some(redirect_exchange(req, 1, 302, Some("https://x.test/home")))
        };
        let send: &Sender = &sender;
        assert!(OpenRedirect.run(&base, send).is_empty());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn open_redirect_matches_scheme_relative_location() {
        let base = HttpRequest::get("https://x.test/go?goto=/home");
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            Some(redirect_exchange(
                req,
                41,
                301,
                Some("//camio-redirect-check.example/evil"),
            ))
        };
        let send: &Sender = &sender;
        let findings = OpenRedirect.run(&base, send);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("`goto`"));
    }

    // --- regex / signature helpers ---------------------------------------

    #[test]
    fn sql_error_signatures_detect_known_databases() {
        for body in [
            "You have an error in your SQL syntax; check the manual",
            "ORA-00933: SQL command not properly ended",
            "Warning: pg_query(): Query failed",
            "SQLSTATE[42000]: Syntax error",
            "Unclosed quotation mark after the character string",
            "near \"SELECT\": syntax error at or near",
        ] {
            assert!(
                !sql_error_signatures(body).is_empty(),
                "expected a signature in: {body}"
            );
        }
        // Benign bodies yield nothing.
        assert!(sql_error_signatures("<html>welcome</html>").is_empty());
        // `ora-` without a number must not match (avoids matching words like `fedora`).
        assert!(sql_error_signatures("the fedora release notes").is_empty());
    }

    #[test]
    fn redirect_name_regex_is_anchored() {
        let re = redirect_name_re().expect("regex compiles");
        for name in [
            "url",
            "next",
            "redirect",
            "returnurl",
            "goto",
            "dest",
            "u",
            "r",
        ] {
            assert!(re.is_match(name), "expected `{name}` to match");
        }
        for name in ["author", "username", "query", "format", "turl", "redirects"] {
            assert!(!re.is_match(name), "expected `{name}` not to match");
        }
    }
}
