//! `camio-active` — opt-in, scoped **active** security checks (plan §8 "Scan &
//! crawl" row: *"Passive checks first; opt-in scoped active checks …"*; plan §15
//! Phase 4: *"Passive checks first, then opt-in active checks with per-check
//! limits, evidence, dedup, severity/confidence …"*).
//!
//! Unlike [`camio-scan`](../camio_scan/index.html), which only *reads* captured
//! exchanges, an active check must *send* probe requests to confirm a
//! vulnerability. This crate is still **pure**: it builds probe
//! [`HttpRequest`](camio_core::HttpRequest)s and interprets the responses, but it
//! never touches the network itself. The caller injects a [`Sender`] — a closure
//! that routes each probe through the fingerprint-matched, scope- and
//! policy-gated engine (`camio-request`). That is the one place scope,
//! confirmation and request budget are enforced (plan §16: *"Require
//! confirmation for active scans … Enforce scope and rate limits below the UI so
//! plugins cannot bypass them — including the fingerprint engine"*), so active
//! testing stays in-scope, confirmed and bounded no matter which check runs.
//!
//! The built-in checks, each sending at most ~1 probe per discovered input:
//!
//! * [`ReflectedXss`] — reflects a distinctive XSS marker and reports when it
//!   comes back **unencoded** (High / [`Tentative`](camio_core::Confidence)).
//! * [`ErrorBasedSqli`] — appends a quote and looks for a database error that a
//!   baseline send did not already show (High / [`Firm`](camio_core::Confidence)).
//! * [`OpenRedirect`] — sets redirect-shaped parameters to a sentinel URL and
//!   reports when the response redirects to it (Medium / `Firm`).
//!
//! ## Invariants (shared with the rest of Camio)
//!
//! * **Findings carry evidence.** Each [`Finding::evidence`] links back to the
//!   probe [`ExchangeId`](camio_core::ExchangeId) the [`Sender`] returned
//!   (plan §8). New findings use `id = FindingId(0)` and `created_at_ms = 0`; the
//!   store assigns the real values on persistence (plan §13).
//! * **Bounded work.** Each check enumerates inputs once, de-duplicates them, and
//!   sends at most ~1 probe per input (plan §15 "per-check limits"). The caller's
//!   [`Sender`] is the final budget gate.
//! * **Headers are never reordered or canonicalized** (plan §6.1 item 3) — probe
//!   requests clone the base and only rewrite the targeted parameter.
//! * **No panics.** This crate contains no `unwrap`/`expect`/`panic!` outside
//!   tests; a (practically impossible) regex-compile failure degrades a check to
//!   "no finding" rather than aborting.

use camio_core::{Confidence, ExchangeId, Finding, FindingId, HttpExchange, HttpRequest, Severity};

mod advanced;
mod autofuzz;
mod checks;
mod crawl;
mod oast_ssrf;
mod params;

pub use autofuzz::{run_auto_fuzz, AutoFuzzResult, AutoFuzzSummary, FuzzCategory};
pub use crawl::{crawl, extract_links, CrawlOptions, CrawlResult};
pub use oast_ssrf::run_oast_ssrf;

pub use advanced::{CorsMisconfig, CrlfInjection, HostHeaderInjection, PathTraversal, Ssti};
pub use checks::{ErrorBasedSqli, HttpMethodAudit, OpenRedirect, ReflectedXss};
pub use params::{discovered_params, set_query_param};

/// Sends one probe request and returns the completed exchange.
///
/// The closure is injected by the caller and is the **only** component that
/// touches the network: it routes the request through the fingerprint-matched,
/// scope- and policy-gated engine (`camio-request`). It returns `Some(exchange)`
/// on a completed send, or `None` when the send was refused — out of scope, over
/// budget, blocked by the SSRF guard, or a transport error (plan §16). A check
/// treats `None` as "no information" and simply emits no finding for that probe.
///
/// The returned [`HttpExchange`] carries whatever [`ExchangeId`] the engine/store
/// assigned; checks use it as the finding's evidence.
pub type Sender<'a> = dyn Fn(HttpRequest) -> Option<HttpExchange> + 'a;

/// A single opt-in active security check.
///
/// Implementors build probe requests from a base request, send them through the
/// injected [`Sender`], interpret the responses, and return zero or more
/// [`Finding`]s. Each returned finding sets `evidence` to the probe exchange's
/// id, `id = FindingId(0)` and `created_at_ms = 0` (the store assigns real
/// values), a specific `title` naming the affected parameter, a confidence
/// appropriate to how conclusively the probe confirmed the issue, and a Markdown
/// `detail`.
pub trait ActiveCheck {
    /// Stable, kebab-case identifier (used for per-check configuration and dedup
    /// of the check itself). Never changes once published.
    fn id(&self) -> &'static str;

    /// Short human-readable name of the check.
    fn title(&self) -> &'static str;

    /// The nominal (maximum) severity this check emits.
    fn severity(&self) -> Severity;

    /// Run the check against `base`, sending probes through `send`.
    fn run(&self, base: &HttpRequest, send: &Sender) -> Vec<Finding>;
}

/// The built-in active checks, in a stable order.
///
/// The checks are stateless unit structs, so a caller may build the set once and
/// reuse it. This mirrors [`camio_scan::default_checks`] so the two scanners
/// share a shape.
pub fn default_active_checks() -> Vec<Box<dyn ActiveCheck>> {
    vec![
        Box::new(ReflectedXss),
        Box::new(ErrorBasedSqli),
        Box::new(OpenRedirect),
        // The resource-level method audit uses only read-only probes by default
        // (OPTIONS/TRACE/HEAD); its write-method probes stay opt-in (plan §16).
        Box::new(HttpMethodAudit::safe()),
        // Expanded active-check matrix (plan §8): template injection, traversal,
        // response splitting, CORS, and host-header injection.
        Box::new(Ssti),
        Box::new(PathTraversal),
        Box::new(CrlfInjection),
        Box::new(CorsMisconfig),
        Box::new(HostHeaderInjection),
    ]
}

/// Run every [`default_active_checks`] check against one base request and return
/// all findings, in check order. No deduplication is applied here; the findings
/// store collapses duplicates across runs just as it does for passive findings.
pub fn run_active(base: &HttpRequest, send: &Sender) -> Vec<Finding> {
    run_active_filtered(base, send, &[], &[])
}

/// Like [`run_active`] but restricted to a subset of the active checks by id
/// (plan §F13 scanner profiles/exclusions). When `only` is non-empty, only
/// checks whose id is listed run; any id in `exclude` is skipped. Both match on
/// the stable check id (`reflected-xss`, `error-based-sqli`, `open-redirect`,
/// `http-method-audit`). Findings are still tagged with their producing check.
pub fn run_active_filtered(
    base: &HttpRequest,
    send: &Sender,
    only: &[String],
    exclude: &[String],
) -> Vec<Finding> {
    let mut out = Vec::new();
    for check in default_active_checks() {
        let id = check.id();
        if !only.is_empty() && !only.iter().any(|o| o == id) {
            continue;
        }
        if exclude.iter().any(|e| e == id) {
            continue;
        }
        for mut finding in check.run(base, send) {
            if finding.rule.is_none() {
                finding.rule = Some(id.to_string());
            }
            out.push(finding);
        }
    }
    out
}

/// Titles of the HTTP-method-audit findings that describe the **host**, not a
/// specific resource (the advertised method set and TRACE support are the same
/// for every page). During a crawl sweep these should be reported once from the
/// seed, not repeated per page — see [`is_host_level_finding`].
const HOST_LEVEL_METHOD_TITLES: &[&str] = &[
    "Dangerous HTTP methods advertised",
    "Cross-Site Tracing (TRACE enabled)",
];

/// Whether a finding is a host-level (resource-independent) method-audit result,
/// so a site sweep can report it once instead of once per crawled page. The
/// resource-level method findings (access-control bypass, write-method capability)
/// are *not* host-level and stay per page.
pub fn is_host_level_finding(finding: &Finding) -> bool {
    finding.rule.as_deref() == Some("http-method-audit")
        && HOST_LEVEL_METHOD_TITLES.contains(&finding.title.as_str())
}

/// Build an active [`Finding`] for one probe exchange.
///
/// `id` is always [`FindingId`]`(0)` and `created_at_ms` is `0`: the store
/// assigns real values when the finding is persisted (plan §13). `evidence` is
/// the single probe exchange that confirmed the issue.
pub(crate) fn finding(
    title: impl Into<String>,
    severity: Severity,
    confidence: Confidence,
    detail: impl Into<String>,
    evidence: ExchangeId,
) -> Finding {
    Finding {
        id: FindingId(0),
        title: title.into(),
        severity,
        confidence,
        detail: detail.into(),
        evidence: vec![evidence],
        created_at_ms: 0,
        // The runner (`run_active`) tags each finding with its check id.
        rule: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpResponse, HttpVersion, Source};
    use std::cell::Cell;

    /// A reflecting echo server: any request whose raw form carries the XSS
    /// marker comes back with the raw probe in the body. Everything else gets a
    /// 302 to the open-redirect sentinel when the request targets it. Used to
    /// confirm [`run_active`] concatenates findings from several checks.
    fn echo_response(req: &HttpRequest) -> HttpResponse {
        let raw = req.raw();
        if raw.contains("camio-redirect-check.example") {
            let mut headers = HeaderList::new();
            headers.push("Location", "https://camio-redirect-check.example/");
            return HttpResponse {
                status: 302,
                version: HttpVersion::Http11,
                reason: Some("Found".into()),
                headers,
                body: Body::empty(),
            };
        }
        let body = if raw.contains("camioX55") {
            "<p>camioX55\"'><svg/onload=camio></p>".to_string()
        } else {
            "<p>ok</p>".to_string()
        };
        HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text(body),
        }
    }

    #[test]
    fn default_active_checks_have_unique_ids() {
        let checks = default_active_checks();
        assert_eq!(checks.len(), 9);
        let mut ids: Vec<&str> = checks.iter().map(|c| c.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 9, "check ids must be unique");
    }

    #[test]
    fn every_check_reports_a_known_severity() {
        for c in default_active_checks() {
            let _ = c.title();
            assert!(matches!(
                c.severity(),
                Severity::Info
                    | Severity::Low
                    | Severity::Medium
                    | Severity::High
                    | Severity::Critical
            ));
        }
    }

    #[test]
    fn run_active_concatenates_findings_from_several_checks() {
        // A request with a reflecting `q` and a redirect-shaped `next`: the XSS
        // check and the open-redirect check should each contribute a finding.
        let base = HttpRequest::get("https://app.test/go?q=hello&next=/home");
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            let resp = echo_response(&req);
            Some(HttpExchange::new(req, Source::Scanner).with_response(resp))
        };
        let send: &Sender = &sender;
        let findings = run_active(&base, send);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("cross-site scripting") && f.title.contains("`q`")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Open redirect") && f.title.contains("`next`")));
        // Unpersisted ids and timestamps, per the shared invariant.
        assert!(findings.iter().all(|f| f.created_at_ms == 0));
    }

    #[test]
    fn injection_checks_send_nothing_when_there_are_no_inputs() {
        // The parameter-injection checks target inputs: with no query or body
        // parameters at all, they must send no probes. (The resource-level
        // HttpMethodAudit is intentionally excluded here — it audits the
        // resource, not its parameters, so it probes even a param-less request.)
        let base = HttpRequest::get("https://app.test/");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            Some(HttpExchange::new(req, Source::Scanner))
        };
        let send: &Sender = &sender;
        for check in [
            Box::new(ReflectedXss) as Box<dyn ActiveCheck>,
            Box::new(ErrorBasedSqli),
            Box::new(OpenRedirect),
        ] {
            assert!(check.run(&base, send).is_empty());
        }
        assert_eq!(calls.get(), 0, "no inputs must mean no probes");
    }

    #[test]
    fn refusing_sender_yields_no_findings() {
        // A sender that refuses every send (None) must never produce a finding.
        let base = HttpRequest::get("https://app.test/go?q=hello&next=/home");
        let sender = |_req: HttpRequest| -> Option<HttpExchange> { None };
        let send: &Sender = &sender;
        assert!(run_active(&base, send).is_empty());
    }

    #[test]
    fn run_active_filtered_selects_and_excludes_by_id() {
        // Reflects XSS and redirects to the sentinel: both checks would fire.
        let base = HttpRequest::get("https://app.test/go?q=hello&next=/home");
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            let resp = echo_response(&req);
            Some(HttpExchange::new(req, Source::Scanner).with_response(resp))
        };
        let send: &Sender = &sender;

        // only = reflected-xss → just the XSS finding, no open-redirect.
        let only = run_active_filtered(&base, send, &["reflected-xss".into()], &[]);
        assert!(only.iter().all(|f| f.rule.as_deref() == Some("reflected-xss")));
        assert!(only.iter().any(|f| f.title.contains("cross-site scripting")));

        // exclude = reflected-xss → the XSS finding is gone, open-redirect stays.
        let excl = run_active_filtered(&base, send, &[], &["reflected-xss".into()]);
        assert!(excl.iter().all(|f| f.rule.as_deref() != Some("reflected-xss")));
        assert!(excl.iter().any(|f| f.rule.as_deref() == Some("open-redirect")));
    }

    #[test]
    fn run_active_tags_each_finding_with_its_check_id() {
        // A reflecting endpoint yields an XSS finding; run_active must tag it
        // with the producing check's id (its report/SARIF ruleId).
        let base = HttpRequest::get("https://app.test/go?q=hello");
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            let resp = echo_response(&req);
            Some(HttpExchange::new(req, Source::Scanner).with_response(resp))
        };
        let send: &Sender = &sender;
        let findings = run_active(&base, send);
        let xss = findings
            .iter()
            .find(|f| f.title.contains("cross-site scripting"))
            .expect("expected an XSS finding");
        assert_eq!(xss.rule.as_deref(), Some("reflected-xss"));
    }

    #[test]
    fn finding_helper_stamps_unpersisted_ids() {
        let f = finding("T", Severity::High, Confidence::Firm, "d", ExchangeId(42));
        assert_eq!(f.id, FindingId(0));
        assert_eq!(f.created_at_ms, 0);
        assert_eq!(f.evidence, vec![ExchangeId(42)]);
    }
}
