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
use camio_core::{Body, Confidence, Finding, HttpRequest, Severity};
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
            // `odbc` must appear in an error context — the bare token shows up
            // in ordinary prose and would flag any page mentioning it.
            r"(?i)(you have an error in your sql syntax|sqlstate|ora-\d+|unclosed quotation|pg_query|sqlite3::|mysql_fetch|odbc[^a-z]{0,8}(error|fail)|syntax error at or near)",
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

// ---------------------------------------------------------------------------
// HTTP method audit
// ---------------------------------------------------------------------------

/// Distinctive sub-path for write-method capability probes. A PUT/DELETE/PATCH is
/// sent to `{resource}/{segment}` — a path that does not exist — so the probe
/// measures whether the *method itself* is accepted without ever touching the
/// real resource (plan §16: active testing must stay bounded and must not be
/// gratuitously destructive).
const METHOD_PROBE_SEGMENT: &str = "camio-method-probe-7f3a9e2b";

/// Marker carried in a TRACE probe header. A server that echoes the whole request
/// back (Cross-Site Tracing) reflects it in the response body, which is how the
/// check distinguishes a real echo from a generic 200.
const TRACE_MARKER: &str = "camio-xst-7f3a9e2b";

/// HTTP methods that an application server should not normally expose and that,
/// once enabled, materially widen the attack surface (arbitrary write, delete,
/// request reflection, or proxying).
const DANGEROUS_METHODS: &[&str] = &["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"];

/// Audits which HTTP methods a resource accepts and reports the dangerous ones.
///
/// Four signals, each confirmed by a real (scope-gated) send and keyed off the
/// response **status** (plan §10 "Results and filters"):
///
///  * **Dangerous methods advertised** — the `Allow`/`Access-Control-Allow-Methods`
///    response to an `OPTIONS` lists PUT/DELETE/PATCH/TRACE/CONNECT (Low/Firm).
///  * **Cross-Site Tracing** — a `TRACE` returns `2xx` and echoes the request
///    (Low/Firm).
///  * **Method-based access-control bypass** — the base method is blocked
///    (`401`/`403`/`405`) but a different method returns the resource (`2xx`).
///    The classic "403 on GET, 200 on HEAD" flaw (High/Tentative).
///  * **Write method enabled** — a `PUT`/`DELETE`/`PATCH` to a non-existent
///    sub-path is *accepted* (`2xx`), proving the verb is processed (High/Firm).
///    Opt-in only: these are state-changing verbs, so they stay behind
///    [`with_write_methods`](HttpMethodAudit::with_write_methods) **and** the
///    caller's destructive policy gate, and they target a randomized path so no
///    real resource is modified.
///
/// Unlike the injection checks this one audits the *resource*, not its
/// parameters, so it probes even a request with no inputs (e.g. an `/admin` page
/// that is `403` on GET but `200` on HEAD). Every probe still flows through the
/// injected [`Sender`], so scope, confirmation and budget are enforced there.
pub struct HttpMethodAudit {
    /// When set, also probe the state-changing verbs PUT/DELETE/PATCH against a
    /// randomized non-existent sub-path. Off by default: these verbs mutate, so
    /// they require an explicit opt-in here *and* destructive authorization at
    /// the [`Sender`]/policy layer.
    pub probe_write_methods: bool,
}

impl HttpMethodAudit {
    /// The safe default: read-only probes only (OPTIONS/TRACE/HEAD). This is the
    /// variant registered in [`crate::default_active_checks`].
    pub const fn safe() -> Self {
        Self {
            probe_write_methods: false,
        }
    }

    /// Also probe the write verbs PUT/DELETE/PATCH. The probes target a
    /// non-existent sub-path so no real resource is written or deleted, but they
    /// are still mutating sends: only enable this with destructive authorization
    /// at the policy layer.
    pub const fn with_write_methods() -> Self {
        Self {
            probe_write_methods: true,
        }
    }

    /// Run **only** the write-method capability probes (PUT/DELETE/PATCH against a
    /// non-existent sub-path), independent of the `probe_write_methods` flag.
    ///
    /// This is the add-on an orchestrator uses when the read-only method audit has
    /// already run via [`crate::default_active_checks`] and it wants the opt-in
    /// write probes without repeating the OPTIONS/TRACE/HEAD findings. The probes
    /// are mutating sends: only call this with destructive authorization at the
    /// [`Sender`]/policy layer. No real resource is written or deleted — each verb
    /// lands on `{resource}/{segment}`, a path that does not exist.
    pub fn run_write_probes(&self, base: &HttpRequest, send: &Sender) -> Vec<Finding> {
        let mut out: Vec<Finding> = Vec::new();
        let probe_url = probe_path_url(&base.url);
        for method in ["PUT", "DELETE", "PATCH"] {
            let mut req = base.clone();
            req.method = method.to_string();
            req.url = probe_url.clone();
            // A clearly-marked sentinel body for the verbs that carry one.
            req.body = if method == "DELETE" {
                Body::empty()
            } else {
                Body::from_text(format!(
                    "camio method-audit capability probe ({METHOD_PROBE_SEGMENT}); inert, safe to delete\n"
                ))
            };
            let Some(ex) = send(req) else {
                continue;
            };
            let Some(resp) = &ex.response else {
                continue;
            };
            if is_success(resp.status) {
                out.push(finding(
                    format!("HTTP {method} method enabled"),
                    Severity::High,
                    Confidence::Firm,
                    format!(
                        "A `{method}` request to `{probe_url}` (a non-existent sub-path) was \
                         accepted (HTTP {}). The server processes `{method}`, which allows {}. If \
                         this reflects the real configuration rather than a catch-all handler, it \
                         is a serious exposure. Verify manually and, for PUT, remove any file the \
                         probe may have created; then restrict the server to the methods the \
                         application actually needs.",
                        resp.status,
                        match method {
                            "PUT" => "writing arbitrary files (web-shell upload)",
                            "DELETE" => "deleting arbitrary resources",
                            _ => "modifying resources in place",
                        }
                    ),
                    ex.id,
                ));
            }
        }
        // These probes run directly (outside `run_active`), so tag them here.
        for f in &mut out {
            f.rule = Some(self.id().to_string());
        }
        out
    }
}

/// Split an `Allow`-style header value into its method tokens, trimmed and
/// non-empty. `GET, POST, HEAD` → `["GET", "POST", "HEAD"]`.
fn parse_allow(header: &str) -> Vec<String> {
    header
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Build the sub-path URL a write-method capability probe targets: the request's
/// path with query and fragment dropped, trailing slash removed, and the
/// distinctive [`METHOD_PROBE_SEGMENT`] appended. The result is a path that does
/// not exist, so a PUT/DELETE/PATCH there cannot overwrite or delete a real
/// resource — it only reveals whether the verb is processed.
fn probe_path_url(url: &str) -> String {
    let no_fragment = url.split('#').next().unwrap_or(url);
    let path_part = no_fragment.split('?').next().unwrap_or(no_fragment);
    let trimmed = path_part.trim_end_matches('/');
    format!("{trimmed}/{METHOD_PROBE_SEGMENT}")
}

/// Whether a status is a 2xx success (the resource/verb was accepted).
fn is_success(status: u16) -> bool {
    (200..=299).contains(&status)
}

impl ActiveCheck for HttpMethodAudit {
    fn id(&self) -> &'static str {
        "http-method-audit"
    }

    fn title(&self) -> &'static str {
        "HTTP method audit"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn run(&self, base: &HttpRequest, send: &Sender) -> Vec<Finding> {
        let mut out = Vec::new();

        // Baseline: the resource's normal method. If it is refused (out of scope,
        // over budget, blocked by the SSRF guard) the resource is unreachable and
        // there is nothing to audit.
        let Some(base_ex) = send(base.clone()) else {
            return out;
        };
        let base_status = match &base_ex.response {
            Some(r) => r.status,
            None => return out,
        };
        let base_method = base.method.clone();

        // 1. OPTIONS — the server's own statement of which methods it allows.
        let mut options_req = base.clone();
        options_req.method = "OPTIONS".into();
        options_req.body = Body::empty();
        if let Some(ex) = send(options_req) {
            if let Some(resp) = &ex.response {
                let allow = resp
                    .headers
                    .get("Allow")
                    .or_else(|| resp.headers.get("Access-Control-Allow-Methods"));
                if let Some(allow) = allow {
                    let listed = parse_allow(allow);
                    let dangerous: Vec<&str> = DANGEROUS_METHODS
                        .iter()
                        .copied()
                        .filter(|m| listed.iter().any(|l| l.eq_ignore_ascii_case(m)))
                        .collect();
                    if !dangerous.is_empty() {
                        out.push(finding(
                            "Dangerous HTTP methods advertised",
                            Severity::Low,
                            Confidence::Firm,
                            format!(
                                "The response to an `OPTIONS` request advertises dangerous \
                                 method(s) in its `Allow` header: **{}** (full header: `{allow}`). \
                                 PUT/DELETE/PATCH permit writing or deleting resources, TRACE \
                                 enables Cross-Site Tracing, and CONNECT can proxy arbitrary \
                                 connections. Confirm which are actually honoured and disable the \
                                 ones the application does not require.",
                                dangerous.join(", ")
                            ),
                            ex.id,
                        ));
                    }
                }
            }
        }

        // 2. TRACE — a 2xx that echoes the request is Cross-Site Tracing (XST).
        let mut trace_req = base.clone();
        trace_req.method = "TRACE".into();
        trace_req.body = Body::empty();
        trace_req.headers.push("X-Camio-Trace", TRACE_MARKER);
        if let Some(ex) = send(trace_req) {
            if let Some(resp) = &ex.response {
                if is_success(resp.status) && resp.body.as_text().contains(TRACE_MARKER) {
                    out.push(finding(
                        "Cross-Site Tracing (TRACE enabled)",
                        Severity::Low,
                        Confidence::Firm,
                        format!(
                            "A `TRACE` request returned HTTP {} and echoed the request back \
                             (the `X-Camio-Trace` marker was reflected in the body). TRACE lets an \
                             attacker read request headers — including ones added by intermediaries \
                             (session cookies, auth tokens) — via Cross-Site Tracing. Disable TRACE \
                             on the web server and any upstream proxy.",
                            resp.status
                        ),
                        ex.id,
                    ));
                }
            }
        }

        // 3. Access-control differential — the base method is blocked but a
        //    different method returns the resource (method-based ACL bypass).
        if matches!(base_status, 401 | 403 | 405) {
            let mut head_req = base.clone();
            head_req.method = "HEAD".into();
            head_req.body = Body::empty();
            if let Some(ex) = send(head_req) {
                if let Some(resp) = &ex.response {
                    if is_success(resp.status) {
                        out.push(finding(
                            "Access control bypass via HTTP method",
                            Severity::High,
                            Confidence::Tentative,
                            format!(
                                "A `{base_method}` request to this resource was blocked (HTTP \
                                 {base_status}), but a `HEAD` request returned HTTP {}. The \
                                 access-control decision is tied to the HTTP method rather than the \
                                 resource, so changing the verb bypasses it — a method-based access \
                                 control flaw. Confirm the response content, then enforce \
                                 authorization independently of the request method.",
                                resp.status
                            ),
                            ex.id,
                        ));
                    }
                }
            }
        }

        // 4. Write-method capability (opt-in; mutating verbs on a path that does
        //    not exist, so a real resource is never written or deleted).
        if self.probe_write_methods {
            out.extend(self.run_write_probes(base, send));
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

    // --- HttpMethodAudit --------------------------------------------------

    /// Build a stored exchange with a chosen status, optional headers, and body.
    fn resp_exchange(
        req: HttpRequest,
        id: i64,
        status: u16,
        headers: &[(&str, &str)],
        body: &str,
    ) -> HttpExchange {
        let mut h = HeaderList::new();
        for (k, v) in headers {
            h.push(*k, *v);
        }
        let resp = HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(body),
        };
        let mut ex = HttpExchange::new(req, Source::Scanner).with_response(resp);
        ex.id = ExchangeId(id);
        ex
    }

    #[test]
    fn method_audit_flags_dangerous_options_allow() {
        let base = HttpRequest::get("https://x.test/api/thing");
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            match req.method.as_str() {
                "OPTIONS" => Some(resp_exchange(
                    req,
                    51,
                    204,
                    &[("Allow", "GET, POST, PUT, DELETE, OPTIONS")],
                    "",
                )),
                // Base GET succeeds; TRACE blocked.
                "GET" => Some(resp_exchange(req, 50, 200, &[], "ok")),
                _ => Some(resp_exchange(req, 59, 405, &[], "")),
            }
        };
        let send: &Sender = &sender;
        let findings = HttpMethodAudit::safe().run(&base, send);
        let f = findings
            .iter()
            .find(|f| f.title == "Dangerous HTTP methods advertised")
            .expect("expected an advertised-methods finding");
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.evidence, vec![ExchangeId(51)]);
        assert!(f.detail.contains("PUT"));
        assert!(f.detail.contains("DELETE"));
    }

    #[test]
    fn method_audit_flags_trace_xst() {
        let base = HttpRequest::get("https://x.test/");
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            match req.method.as_str() {
                // Echo the request body/headers back, reflecting the marker.
                "TRACE" => {
                    let echoed = format!("TRACE / HTTP/1.1\nX-Camio-Trace: {TRACE_MARKER}\n");
                    Some(resp_exchange(req, 61, 200, &[], &echoed))
                }
                "GET" => Some(resp_exchange(req, 60, 200, &[], "home")),
                _ => Some(resp_exchange(req, 69, 405, &[], "")),
            }
        };
        let send: &Sender = &sender;
        let findings = HttpMethodAudit::safe().run(&base, send);
        let f = findings
            .iter()
            .find(|f| f.title.contains("Cross-Site Tracing"))
            .expect("expected an XST finding");
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.evidence, vec![ExchangeId(61)]);
    }

    #[test]
    fn method_audit_flags_method_based_acl_bypass() {
        // GET is forbidden, but HEAD returns the resource: ACL keyed off method.
        let base = HttpRequest::get("https://x.test/admin");
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            match req.method.as_str() {
                "GET" => Some(resp_exchange(req, 70, 403, &[], "Forbidden")),
                "HEAD" => Some(resp_exchange(req, 71, 200, &[], "")),
                "OPTIONS" => Some(resp_exchange(req, 72, 204, &[("Allow", "GET, HEAD")], "")),
                _ => Some(resp_exchange(req, 79, 405, &[], "")),
            }
        };
        let send: &Sender = &sender;
        let findings = HttpMethodAudit::safe().run(&base, send);
        let f = findings
            .iter()
            .find(|f| f.title == "Access control bypass via HTTP method")
            .expect("expected an ACL-bypass finding");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Tentative);
        assert_eq!(f.evidence, vec![ExchangeId(71)]);
    }

    #[test]
    fn method_audit_clean_resource_has_no_findings() {
        let base = HttpRequest::get("https://x.test/page");
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            match req.method.as_str() {
                "GET" => Some(resp_exchange(req, 80, 200, &[], "page")),
                "OPTIONS" => Some(resp_exchange(
                    req,
                    81,
                    204,
                    &[("Allow", "GET, HEAD, OPTIONS")],
                    "",
                )),
                // TRACE disabled, everything else blocked.
                _ => Some(resp_exchange(req, 89, 405, &[], "")),
            }
        };
        let send: &Sender = &sender;
        assert!(HttpMethodAudit::safe().run(&base, send).is_empty());
    }

    #[test]
    fn method_audit_safe_variant_never_sends_write_methods() {
        let base = HttpRequest::get("https://x.test/upload");
        let saw_write = Cell::new(false);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            if matches!(req.method.as_str(), "PUT" | "DELETE" | "PATCH") {
                saw_write.set(true);
            }
            Some(resp_exchange(req, 1, 200, &[], "ok"))
        };
        let send: &Sender = &sender;
        let _ = HttpMethodAudit::safe().run(&base, send);
        assert!(!saw_write.get(), "safe() must not send PUT/DELETE/PATCH");
    }

    #[test]
    fn method_audit_write_methods_detects_enabled_put() {
        let base = HttpRequest::get("https://x.test/files/report.pdf");
        let put_url = Cell::new(String::new());
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            match req.method.as_str() {
                "GET" => Some(resp_exchange(req, 90, 200, &[], "pdf")),
                "PUT" => {
                    put_url.set(req.url.clone());
                    Some(resp_exchange(req, 91, 201, &[], ""))
                }
                // DELETE/PATCH rejected.
                _ => Some(resp_exchange(req, 99, 405, &[], "")),
            }
        };
        let send: &Sender = &sender;
        let findings = HttpMethodAudit::with_write_methods().run(&base, send);
        let f = findings
            .iter()
            .find(|f| f.title == "HTTP PUT method enabled")
            .expect("expected a PUT-enabled finding");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Firm);
        assert_eq!(f.evidence, vec![ExchangeId(91)]);
        // The PUT landed on a non-existent sub-path, never the real resource.
        assert_eq!(
            put_url.take(),
            format!("https://x.test/files/report.pdf/{METHOD_PROBE_SEGMENT}")
        );
    }

    #[test]
    fn method_audit_refused_baseline_yields_nothing() {
        let base = HttpRequest::get("https://x.test/");
        let calls = Cell::new(0usize);
        let sender = |_req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            None // out of scope / refused
        };
        let send: &Sender = &sender;
        assert!(HttpMethodAudit::with_write_methods().run(&base, send).is_empty());
        assert_eq!(calls.get(), 1, "stops after the baseline is refused");
    }

    #[test]
    fn probe_path_url_appends_segment_and_drops_query() {
        assert_eq!(
            probe_path_url("https://x.test/a/b?x=1#frag"),
            format!("https://x.test/a/b/{METHOD_PROBE_SEGMENT}")
        );
        assert_eq!(
            probe_path_url("https://x.test/a/"),
            format!("https://x.test/a/{METHOD_PROBE_SEGMENT}")
        );
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
