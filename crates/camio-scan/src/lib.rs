//! `camio-scan` — passive security checks over captured exchanges (plan §8
//! "Scan & crawl" row: *"Passive checks first; opt-in scoped active checks; scan
//! configs, evidence, severity/confidence, dedup, exclusions …"*; plan §15
//! Phase 4: *"Passive checks first, then opt-in active checks …"*).
//!
//! This crate is **passive only**: every check reads an already-captured
//! [`HttpExchange`] and emits [`Finding`]s. Nothing here sends traffic — active
//! checks are deliberately out of scope for now, but the [`PassiveCheck`] trait
//! and the registry are the extension point a future active scanner slots into.
//!
//! ```
//! use camio_core::{HttpExchange, HttpRequest, HttpResponse, HeaderList, Body, HttpVersion, Source};
//! use camio_scan::scan_exchange;
//!
//! let mut headers = HeaderList::new();
//! headers.push("Content-Type", "text/html");
//! let resp = HttpResponse { status: 200, version: HttpVersion::Http11, reason: None, headers, body: Body::from_text("<html></html>") };
//! let ex = HttpExchange::new(HttpRequest::get("https://example.test/"), Source::Scanner).with_response(resp);
//!
//! // An HTML page with no security headers yields passive findings.
//! assert!(!scan_exchange(&ex).is_empty());
//! ```
//!
//! ## Invariants (shared with the rest of Camio)
//!
//! * **Findings carry evidence.** Each [`Finding::evidence`] links back to the
//!   [`ExchangeId`](camio_core::ExchangeId)(s) that justify it (plan §8).
//! * **New findings use `id = FindingId(0)` and `created_at_ms = 0`;** the store
//!   assigns the real id and timestamp on persistence (plan §13).
//! * **Headers are never reordered or canonicalized** (plan §6.1 item 3) — checks
//!   only read via case-insensitive lookups.
//! * **No panics.** This crate contains no `unwrap`/`expect`/`panic!` outside
//!   tests; everything degrades to "no finding".

use camio_core::{Finding, HttpExchange, Severity};
use serde::{Deserialize, Serialize};

mod checks;

pub use checks::{
    BasicAuthOverHttp, CorsMisconfig, DirectoryListing, InsecureCookies, MissingSecurityHeaders,
    MixedContent, ReflectedInput, SensitiveDataInUrl, ServerBannerDisclosure, VerboseError,
};

/// A single passive security check.
///
/// Implementors inspect one captured [`HttpExchange`] and return zero or more
/// [`Finding`]s. Each returned finding sets `evidence = vec![ex.id]`,
/// `id = FindingId(0)` and `created_at_ms = 0` (the store assigns real values),
/// a specific `title`, a confidence appropriate to how certain the detection is,
/// and a Markdown `detail` explaining the issue.
pub trait PassiveCheck {
    /// Stable, kebab-case identifier (used for configuration and dedup of the
    /// check itself). Never changes once published.
    fn id(&self) -> &'static str;

    /// Short human-readable name of the check.
    fn title(&self) -> &'static str;

    /// The nominal (maximum) severity this check emits. Individual findings may
    /// be lower — e.g. a headers check emits both `Low` and `Medium`.
    fn severity(&self) -> Severity;

    /// Run the check against one exchange.
    fn check(&self, ex: &HttpExchange) -> Vec<Finding>;
}

/// The built-in passive checks, in a stable order.
///
/// This is the extension point for the scanner: a future active-check registry
/// mirrors it. The returned checks are stateless, so callers may build the set
/// once and reuse it across many exchanges.
pub fn default_checks() -> Vec<Box<dyn PassiveCheck>> {
    vec![
        Box::new(MissingSecurityHeaders),
        Box::new(InsecureCookies),
        Box::new(ServerBannerDisclosure),
        Box::new(DirectoryListing),
        Box::new(VerboseError),
        Box::new(ReflectedInput),
        Box::new(CorsMisconfig),
        Box::new(SensitiveDataInUrl),
        Box::new(BasicAuthOverHttp),
        Box::new(MixedContent),
    ]
}

/// Run every [`default_checks`] check against a single exchange and return all
/// findings, in check order. No deduplication is applied (there is only one
/// exchange); use [`scan_all`] to scan and deduplicate across many.
pub fn scan_exchange(ex: &HttpExchange) -> Vec<Finding> {
    let checks = default_checks();
    let mut out = Vec::new();
    for check in &checks {
        out.extend(check.check(ex));
    }
    out
}

/// The result of scanning a batch of exchanges (plan §8: evidence,
/// severity/confidence, dedup). Serializable so it can be exported as a report
/// (plan §8: "exportable reports").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassiveReport {
    /// Deduplicated findings, most-severe first.
    pub findings: Vec<Finding>,
    /// Number of distinct passive checks executed per exchange.
    pub checks_run: usize,
    /// Number of exchanges scanned.
    pub exchanges_scanned: usize,
}

/// Run the passive checks across many exchanges and produce a deduplicated,
/// severity-sorted report.
///
/// Findings that share the same `(title, host)` are collapsed into one: their
/// evidence [`ExchangeId`](camio_core::ExchangeId)s are unioned (preserving
/// first-seen order) and the highest severity is kept. `host` is the request
/// host of the originating exchange (empty when the URL has no host). The final
/// list is sorted most-severe first; findings of equal severity keep their
/// first-seen order.
pub fn scan_all(exchanges: &[HttpExchange]) -> PassiveReport {
    let checks = default_checks();
    let mut agg: Vec<Aggregated> = Vec::new();

    for ex in exchanges {
        let host = ex.request.host().unwrap_or_default();
        for check in &checks {
            for finding in check.check(ex) {
                upsert(&mut agg, &host, finding);
            }
        }
    }

    let mut findings: Vec<Finding> = agg.into_iter().map(|a| a.finding).collect();
    // Stable sort, most-severe first (Severity: Info < Low < … < Critical).
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

    PassiveReport {
        findings,
        checks_run: checks.len(),
        exchanges_scanned: exchanges.len(),
    }
}

/// One deduplication bucket keyed by `(host, finding.title)`.
struct Aggregated {
    host: String,
    title: String,
    finding: Finding,
}

/// Merge `finding` into `agg` under its `(host, title)` key: union evidence and
/// keep the highest severity, or insert a new bucket.
fn upsert(agg: &mut Vec<Aggregated>, host: &str, mut finding: Finding) {
    if let Some(entry) = agg
        .iter_mut()
        .find(|a| a.host == host && a.title == finding.title)
    {
        for id in finding.evidence.drain(..) {
            if !entry.finding.evidence.contains(&id) {
                entry.finding.evidence.push(id);
            }
        }
        if finding.severity > entry.finding.severity {
            entry.finding.severity = finding.severity;
        }
    } else {
        agg.push(Aggregated {
            host: host.to_string(),
            title: finding.title.clone(),
            finding,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{
        Body, Confidence, ExchangeId, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source,
    };

    fn html_exchange(id: i64, url: &str, extra_headers: &[(&str, &str)]) -> HttpExchange {
        let mut h = HeaderList::new();
        h.push("Content-Type", "text/html");
        for (n, v) in extra_headers {
            h.push(*n, *v);
        }
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text("<html></html>"),
        };
        let mut ex = HttpExchange::new(HttpRequest::get(url), Source::Scanner).with_response(resp);
        ex.id = ExchangeId(id);
        ex
    }

    #[test]
    fn default_checks_are_ten_with_unique_ids() {
        let checks = default_checks();
        assert_eq!(checks.len(), 10);
        let mut ids: Vec<&str> = checks.iter().map(|c| c.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 10, "check ids must be unique");
    }

    #[test]
    fn every_check_reports_a_sane_nominal_severity() {
        // Each check's nominal severity is one of the known variants and the
        // trait object is usable through the registry.
        for c in default_checks() {
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
    fn scan_exchange_runs_all_checks() {
        // Bare HTML page over HTTPS with a versioned banner: missing-header and
        // banner findings should both appear.
        let ex = html_exchange(1, "https://x.test/", &[("Server", "nginx/1.25.3")]);
        let findings = scan_exchange(&ex);
        assert!(findings
            .iter()
            .any(|f| f.title.starts_with("Missing security header")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Version disclosure")));
        // Every finding is unpersisted and points back at this exchange.
        assert!(findings
            .iter()
            .all(|f| f.evidence == vec![ExchangeId(1)] && f.created_at_ms == 0));
    }

    #[test]
    fn scan_all_dedups_same_title_and_host_and_unions_evidence() {
        // Two pages on the SAME host, both missing CSP.
        let a = html_exchange(1, "https://shop.test/a", &[]);
        let b = html_exchange(2, "https://shop.test/b", &[]);
        let report = scan_all(&[a, b]);

        let csp: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.title == "Missing security header: Content-Security-Policy")
            .collect();
        assert_eq!(
            csp.len(),
            1,
            "same (title, host) must collapse to one finding"
        );
        assert_eq!(csp[0].evidence, vec![ExchangeId(1), ExchangeId(2)]);
        assert_eq!(report.exchanges_scanned, 2);
        assert_eq!(report.checks_run, 10);
    }

    #[test]
    fn scan_all_keeps_findings_separate_across_hosts() {
        let a = html_exchange(1, "https://one.test/", &[]);
        let b = html_exchange(2, "https://two.test/", &[]);
        let report = scan_all(&[a, b]);
        let csp = report
            .findings
            .iter()
            .filter(|f| f.title == "Missing security header: Content-Security-Policy")
            .count();
        assert_eq!(csp, 2, "different hosts remain distinct findings");
    }

    #[test]
    fn scan_all_sorts_most_severe_first() {
        // A page that triggers a High (CORS wildcard+creds), Mediums and Lows.
        let mut req = HttpRequest::get("https://api.test/data?token=secret");
        req.headers.push("Origin", "https://evil.test");
        let mut rh = HeaderList::new();
        rh.push("Content-Type", "text/html");
        rh.push("Access-Control-Allow-Origin", "*");
        rh.push("Access-Control-Allow-Credentials", "true");
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: rh,
            body: Body::from_text("<html></html>"),
        };
        let mut ex = HttpExchange::new(req, Source::Scanner).with_response(resp);
        ex.id = ExchangeId(7);

        let report = scan_all(&[ex]);
        assert!(report.findings.len() >= 3);
        // Severity is non-increasing down the list.
        for pair in report.findings.windows(2) {
            assert!(pair[0].severity >= pair[1].severity);
        }
        assert_eq!(report.findings[0].severity, Severity::High);
    }

    #[test]
    fn scan_all_handles_empty_input() {
        let report = scan_all(&[]);
        assert!(report.findings.is_empty());
        assert_eq!(report.exchanges_scanned, 0);
        assert_eq!(report.checks_run, 10);
    }

    #[test]
    fn upsert_takes_the_highest_severity() {
        let mut agg: Vec<Aggregated> = Vec::new();
        let low = checks::finding("T", Severity::Low, Confidence::Firm, "d", ExchangeId(1));
        let high = checks::finding("T", Severity::High, Confidence::Firm, "d", ExchangeId(2));
        upsert(&mut agg, "h", low);
        upsert(&mut agg, "h", high);
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].finding.severity, Severity::High);
        assert_eq!(agg[0].finding.evidence, vec![ExchangeId(1), ExchangeId(2)]);
    }

    #[test]
    fn report_serde_roundtrips() {
        let ex = html_exchange(1, "https://x.test/", &[]);
        let report = scan_all(&[ex]);
        let json = serde_json::to_string(&report).expect("serialize");
        let back: PassiveReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, back);
        // Severity serializes snake_case per camio-core.
        assert!(json.contains("\"severity\""));
    }

    #[test]
    fn exchange_without_response_yields_no_findings() {
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner);
        // Request-only checks (sensitive URL, basic auth) still don't fire on a
        // clean https GET with no query or auth.
        assert!(scan_exchange(&ex).is_empty());
    }
}
