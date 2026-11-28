//! Categorized, bounded auto-fuzz over discovered inputs (plan §8 "Automate";
//! plan §10 "Automatic input discovery and test matrix").
//!
//! This is the execution end of the recon→plan→act loop: [`camio_scan`]'s
//! attack-surface synthesis recommends payload-DB categories for a target, and
//! this driver injects those categories' payloads into the target's discovered
//! query/body inputs, classifying each response. It is the same path the manual
//! `camio fuzz` command takes, pointed automatically at the suggested categories.
//!
//! Like the rest of [`crate`], it is **pure orchestration**: every probe is sent
//! through the injected [`Sender`], so scope, confirmation and budget are
//! enforced there (plan §16). The driver only decides *which* bounded set of
//! `(input, payload)` combinations to try — it cannot widen what is reachable.

use crate::params::{with_json_field, with_param, with_xml_input};
use crate::Sender;
use camio_automate::{classify, discover_inputs, Baseline, ClassifiedResult, InputKind, PayloadSet};
use camio_core::{HttpRequest, Query};
use serde::{Deserialize, Serialize};

/// One payload-DB category to fuzz: its name and the payload set to draw from.
pub struct FuzzCategory<'a> {
    pub name: String,
    pub set: &'a PayloadSet,
}

/// One flagged auto-fuzz result: the category/input/payload that produced it and
/// the classification (status, length delta, flags such as `server-error` or
/// `reflected`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoFuzzResult {
    pub category: String,
    pub input_kind: InputKind,
    pub input_name: String,
    pub payload: String,
    pub result: ClassifiedResult,
}

/// The outcome of a [`run_auto_fuzz`] pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutoFuzzSummary {
    /// Probe attempts made (sent or refused) — bounded by the budget.
    pub attempts: usize,
    /// Probes that completed with a response.
    pub sent: usize,
    /// Only the *flagged* results (a change from baseline, a server error, a
    /// reflection, or an `interesting`-query match). An unflagged probe is
    /// dropped, so a clean target yields an empty list (plan §10: a `200` is not
    /// automatically a hit).
    pub results: Vec<AutoFuzzResult>,
}

/// Inject each category's payloads into each discovered query/body input through
/// the gated `send`, classify the responses, and return the flagged results.
///
/// The work is bounded two ways so an AI-driven call cannot balloon into a
/// stress test (plan §10): `budget` caps the total probe attempts, and that
/// budget is split evenly across the non-empty categories so several categories
/// are exercised rather than the first one exhausting the whole budget. Payloads
/// are tried payload-major (each payload across every input before the next
/// payload), so a small budget still spreads over all of a request's inputs.
///
/// `baseline` (typically the unmodified base response) drives the
/// status/length-change flags; `interesting` is an optional CamioQL query whose
/// matches are flagged. Both may be `None`.
pub fn run_auto_fuzz(
    base: &HttpRequest,
    categories: &[FuzzCategory],
    budget: usize,
    baseline: Option<&Baseline>,
    interesting: Option<&Query>,
    send: &Sender,
) -> AutoFuzzSummary {
    let mut summary = AutoFuzzSummary::default();
    // Inject into query params, urlencoded body params, and JSON body fields
    // (addressed by dotted path), deduplicated and in discovery order.
    let mut inputs: Vec<(InputKind, String)> = Vec::new();
    for input in discover_inputs(base) {
        if matches!(
            input.kind,
            InputKind::QueryParam
                | InputKind::BodyParam
                | InputKind::JsonField
                | InputKind::XmlText
                | InputKind::XmlAttr
        ) {
            let key = (input.kind, input.name);
            if !inputs.contains(&key) {
                inputs.push(key);
            }
        }
    }
    if inputs.is_empty() || budget == 0 {
        return summary;
    }

    let used_cats = categories
        .iter()
        .filter(|c| !c.set.payloads.is_empty())
        .count()
        .max(1);
    // Per-category attempt cap, so the budget is shared across categories.
    let per_cat = (budget / used_cats).max(1);

    for cat in categories {
        if cat.set.payloads.is_empty() {
            continue;
        }
        let mut cat_attempts = 0usize;
        'payloads: for payload in &cat.set.payloads {
            if cat_attempts >= per_cat || summary.attempts >= budget {
                break;
            }
            for (kind, name) in &inputs {
                if cat_attempts >= per_cat || summary.attempts >= budget {
                    break 'payloads;
                }
                summary.attempts += 1;
                cat_attempts += 1;
                let probe = match kind {
                    InputKind::JsonField => with_json_field(base, name, payload),
                    InputKind::XmlText | InputKind::XmlAttr => with_xml_input(base, name, payload),
                    _ => with_param(base, *kind, name, payload),
                };
                let Some(ex) = send(probe) else {
                    continue;
                };
                summary.sent += 1;
                let classified = classify(&[(vec![payload.clone()], ex)], baseline, interesting);
                if let Some(cr) = classified.into_iter().next() {
                    if !cr.flags.is_empty() {
                        summary.results.push(AutoFuzzResult {
                            category: cat.name.clone(),
                            input_kind: *kind,
                            input_name: name.clone(),
                            payload: payload.clone(),
                            result: cr,
                        });
                    }
                }
            }
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, ExchangeId, HeaderList, HttpExchange, HttpResponse, HttpVersion, Source};
    use std::cell::Cell;

    fn ok(req: HttpRequest, status: u16, body: &str) -> HttpExchange {
        let resp = HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text(body),
        };
        let mut ex = HttpExchange::new(req, Source::Scanner).with_response(resp);
        ex.id = ExchangeId(1);
        ex
    }

    fn cats<'a>(sets: &'a [(String, PayloadSet)]) -> Vec<FuzzCategory<'a>> {
        sets.iter()
            .map(|(n, s)| FuzzCategory {
                name: n.clone(),
                set: s,
            })
            .collect()
    }

    #[test]
    fn flags_a_server_error_from_a_payload() {
        let base = HttpRequest::get("https://x.test/item?id=5");
        // A payload containing a quote triggers a 500; everything else is 200.
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            if req.url.contains("%27") {
                Some(ok(req, 500, "db error"))
            } else {
                Some(ok(req, 200, "fine"))
            }
        };
        let send: &Sender = &sender;
        let sets = vec![("sqli".to_string(), PayloadSet::from_lines("sqli", "'\n1"))];
        let out = run_auto_fuzz(&base, &cats(&sets), 50, None, None, send);
        assert!(out.sent >= 1);
        let hit = out
            .results
            .iter()
            .find(|r| r.result.flags.iter().any(|f| f == "server-error"))
            .expect("expected a server-error hit");
        assert_eq!(hit.category, "sqli");
        assert_eq!(hit.input_name, "id");
    }

    #[test]
    fn fuzzes_json_body_fields_by_path() {
        // A JSON POST whose nested `user.name` field, when it carries a quote,
        // triggers a 500. The fuzzer must discover and inject that field.
        let mut base = HttpRequest::get("https://api.test/login");
        base.method = "POST".into();
        base.headers.push("Content-Type", "application/json");
        base.body = Body::from_text(r#"{"user":{"name":"bob","id":7}}"#);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            if req.body.as_text().contains('\'') {
                Some(ok(req, 500, "db error"))
            } else {
                Some(ok(req, 200, "ok"))
            }
        };
        let send: &Sender = &sender;
        let sets = vec![("sqli".to_string(), PayloadSet::from_lines("sqli", "'"))];
        let out = run_auto_fuzz(&base, &cats(&sets), 50, None, None, send);
        let hit = out
            .results
            .iter()
            .find(|r| r.result.flags.iter().any(|f| f == "server-error"))
            .expect("expected a server-error hit from a JSON field");
        assert_eq!(hit.input_kind, InputKind::JsonField);
        // Addressed by its dotted path into the nested object.
        assert!(
            hit.input_name == "user.name" || hit.input_name == "user.id",
            "unexpected JSON path: {}",
            hit.input_name
        );
    }

    #[test]
    fn respects_the_budget() {
        let base = HttpRequest::get("https://x.test/s?a=1&b=2");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            Some(ok(req, 200, "x"))
        };
        let send: &Sender = &sender;
        // 100 payloads × 2 inputs = 200 possible, but the budget caps attempts.
        let big = PayloadSet::new(
            "big",
            (0..100).map(|i| format!("p{i}")).collect::<Vec<_>>(),
        );
        let sets = vec![("big".to_string(), big)];
        let out = run_auto_fuzz(&base, &cats(&sets), 10, None, None, send);
        assert_eq!(out.attempts, 10, "attempts must not exceed the budget");
        assert!(calls.get() <= 10);
    }

    #[test]
    fn budget_is_split_across_categories() {
        let base = HttpRequest::get("https://x.test/s?a=1");
        let sender = |req: HttpRequest| -> Option<HttpExchange> { Some(ok(req, 200, "x")) };
        let send: &Sender = &sender;
        let set_a = PayloadSet::new("a", (0..50).map(|i| format!("a{i}")).collect::<Vec<_>>());
        let set_b = PayloadSet::new("b", (0..50).map(|i| format!("b{i}")).collect::<Vec<_>>());
        let sets = vec![("a".to_string(), set_a), ("b".to_string(), set_b)];
        // Budget 10 over two categories → ~5 each; both categories must be tried.
        let out = run_auto_fuzz(&base, &cats(&sets), 10, None, None, send);
        assert!(out.attempts <= 10);
    }

    #[test]
    fn no_inputs_means_no_fuzzing() {
        let base = HttpRequest::get("https://x.test/static");
        let calls = Cell::new(0usize);
        let sender = |req: HttpRequest| -> Option<HttpExchange> {
            calls.set(calls.get() + 1);
            Some(ok(req, 200, "x"))
        };
        let send: &Sender = &sender;
        let sets = vec![("sqli".to_string(), PayloadSet::from_lines("sqli", "'"))];
        let out = run_auto_fuzz(&base, &cats(&sets), 50, None, None, send);
        assert_eq!(out.attempts, 0);
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn unflagged_probes_are_dropped() {
        // Every response is a benign 200 identical to baseline → no flags.
        let base = HttpRequest::get("https://x.test/s?q=1");
        let sender = |req: HttpRequest| -> Option<HttpExchange> { Some(ok(req, 200, "same")) };
        let send: &Sender = &sender;
        let baseline = Baseline {
            status: 200,
            body_len: "same".len(),
        };
        let sets = vec![("x".to_string(), PayloadSet::from_lines("x", "aaaaaa\nbbbbbb"))];
        let out = run_auto_fuzz(&base, &cats(&sets), 50, Some(&baseline), None, send);
        assert!(out.sent >= 1);
        assert!(out.results.is_empty(), "benign probes must not be reported");
    }

    #[test]
    fn empty_categories_are_skipped() {
        let base = HttpRequest::get("https://x.test/s?q=1");
        let sender = |req: HttpRequest| -> Option<HttpExchange> { Some(ok(req, 200, "x")) };
        let send: &Sender = &sender;
        let empty = PayloadSet::new("empty", Vec::new());
        let sets = vec![("empty".to_string(), empty)];
        let out = run_auto_fuzz(&base, &cats(&sets), 50, None, None, send);
        assert_eq!(out.attempts, 0);
    }
}
