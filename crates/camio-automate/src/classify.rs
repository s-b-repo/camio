//! Result classification (plan §8 "Automate" row: "results table/filters";
//! plan §10 "Results and filters").
//!
//! After a campaign's requests are sent, each response is compared against a
//! baseline and against an optional "interesting" CamioQL query, and tagged with
//! human-readable flags ("status-changed", "server-error", "reflected", …) that
//! the UI/MCP surface can filter on. Defaults are deliberately conservative — a
//! `200` is not automatically a hit (plan §10) — so classification only reports
//! observable differences and lets the operator decide.

use camio_core::{HttpExchange, Query};
use serde::{Deserialize, Serialize};

/// The reference response a campaign is compared against (typically the
/// unmodified base request's response).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    pub status: u16,
    pub body_len: usize,
}

/// One classified campaign result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedResult {
    /// The payload(s) that produced this exchange.
    pub payloads: Vec<String>,
    /// Response status, if there was a response.
    pub status: Option<u16>,
    /// Response body length in bytes, if there was a response.
    pub body_len: Option<usize>,
    /// Whether the status differs from the baseline (`false` with no baseline or
    /// no response).
    pub status_changed: bool,
    /// Body length minus the baseline body length (`0` with no baseline or no
    /// response).
    pub length_delta: i64,
    /// Human-readable tags, in a stable order (see [`classify`]).
    pub flags: Vec<String>,
}

/// Classify a batch of `(payloads, exchange)` results.
///
/// Flags, in the order they are emitted:
///  * `status-changed` — status differs from `baseline`.
///  * `length-changed` — body length differs from `baseline`.
///  * `server-error`   — status is in the 5xx range.
///  * `match`          — the `interesting` query matches the exchange.
///  * `reflected`      — a non-empty payload appears verbatim in the response body.
///
/// `baseline`-dependent flags are never set when `baseline` is `None`; body
/// flags are never set when there is no response.
pub fn classify(
    results: &[(Vec<String>, HttpExchange)],
    baseline: Option<&Baseline>,
    interesting: Option<&Query>,
) -> Vec<ClassifiedResult> {
    results
        .iter()
        .map(|(payloads, exchange)| classify_one(payloads, exchange, baseline, interesting))
        .collect()
}

fn classify_one(
    payloads: &[String],
    exchange: &HttpExchange,
    baseline: Option<&Baseline>,
    interesting: Option<&Query>,
) -> ClassifiedResult {
    let response = exchange.response.as_ref();
    let status = response.map(|r| r.status);
    let body_len = response.map(|r| r.body.len());

    let status_changed = match (baseline, status) {
        (Some(base), Some(code)) => code != base.status,
        _ => false,
    };

    let length_delta = match (baseline, body_len) {
        (Some(base), Some(len)) => len as i64 - base.body_len as i64,
        _ => 0,
    };
    let length_changed = matches!((baseline, body_len), (Some(_), Some(_))) && length_delta != 0;

    let server_error = matches!(status, Some(code) if (500..=599).contains(&code));

    let query_match = interesting.map(|q| q.matches(exchange)).unwrap_or(false);

    let reflected = response
        .map(|r| {
            let body = r.body.as_text();
            payloads
                .iter()
                .any(|p| !p.is_empty() && body.contains(p.as_str()))
        })
        .unwrap_or(false);

    let mut flags = Vec::new();
    if status_changed {
        flags.push("status-changed".to_string());
    }
    if length_changed {
        flags.push("length-changed".to_string());
    }
    if server_error {
        flags.push("server-error".to_string());
    }
    if query_match {
        flags.push("match".to_string());
    }
    if reflected {
        flags.push("reflected".to_string());
    }

    ClassifiedResult {
        payloads: payloads.to_vec(),
        status,
        body_len,
        status_changed,
        length_delta,
        flags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn response(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text(body),
        }
    }

    fn exchange(status: u16, body: &str) -> HttpExchange {
        HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Automate)
            .with_response(response(status, body))
    }

    #[test]
    fn reflected_payload_is_flagged() {
        let payload = "<script>alert(1)</script>";
        let results = vec![(
            vec![payload.to_string()],
            exchange(200, &format!("echo: {payload} done")),
        )];
        let out = classify(&results, None, None);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.contains(&"reflected".to_string()));
    }

    #[test]
    fn empty_payload_never_counts_as_reflected() {
        let results = vec![(vec![String::new()], exchange(200, "anything"))];
        let out = classify(&results, None, None);
        assert!(!out[0].flags.contains(&"reflected".to_string()));
    }

    #[test]
    fn server_error_is_flagged() {
        let results = vec![(vec!["x".to_string()], exchange(500, "boom"))];
        let out = classify(&results, None, None);
        assert_eq!(out[0].status, Some(500));
        assert!(out[0].flags.contains(&"server-error".to_string()));
    }

    #[test]
    fn status_and_length_change_against_baseline() {
        let base = Baseline {
            status: 200,
            body_len: 10,
        };
        let results = vec![(vec!["p".to_string()], exchange(404, "different body here"))];
        let out = classify(&results, Some(&base), None);
        assert!(out[0].status_changed);
        assert!(out[0].flags.contains(&"status-changed".to_string()));
        assert!(out[0].flags.contains(&"length-changed".to_string()));
        assert_eq!(out[0].length_delta, "different body here".len() as i64 - 10);
    }

    #[test]
    fn no_baseline_means_no_status_or_length_flags() {
        let results = vec![(vec!["p".to_string()], exchange(404, "body"))];
        let out = classify(&results, None, None);
        assert!(!out[0].status_changed);
        assert_eq!(out[0].length_delta, 0);
        assert!(!out[0]
            .flags
            .iter()
            .any(|f| f == "status-changed" || f == "length-changed"));
    }

    #[test]
    fn identical_to_baseline_has_no_change_flags() {
        let base = Baseline {
            status: 200,
            body_len: 4,
        };
        let results = vec![(vec!["p".to_string()], exchange(200, "body"))];
        let out = classify(&results, Some(&base), None);
        assert!(!out[0].status_changed);
        assert_eq!(out[0].length_delta, 0);
        assert!(out[0].flags.is_empty());
    }

    #[test]
    fn interesting_query_match_is_flagged() {
        let query = Query::compile("resp.code.eq:500").unwrap();
        let results = vec![(vec!["p".to_string()], exchange(500, "x"))];
        let out = classify(&results, None, Some(&query));
        assert!(out[0].flags.contains(&"match".to_string()));
        // A non-matching query does not flag.
        let query = Query::compile("resp.code.eq:200").unwrap();
        let out = classify(&results, None, Some(&query));
        assert!(!out[0].flags.contains(&"match".to_string()));
    }

    #[test]
    fn missing_response_yields_empty_metrics() {
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Automate);
        let results = vec![(vec!["p".to_string()], ex)];
        let out = classify(
            &results,
            Some(&Baseline {
                status: 200,
                body_len: 5,
            }),
            None,
        );
        assert_eq!(out[0].status, None);
        assert_eq!(out[0].body_len, None);
        assert!(!out[0].status_changed);
        assert_eq!(out[0].length_delta, 0);
        assert!(out[0].flags.is_empty());
    }

    #[test]
    fn flag_order_is_stable() {
        let base = Baseline {
            status: 200,
            body_len: 0,
        };
        let query = Query::compile("resp.code.gte:500").unwrap();
        // 500 + length change + query match + reflection all at once.
        let results = vec![(vec!["boom".to_string()], exchange(500, "boom"))];
        let out = classify(&results, Some(&base), Some(&query));
        assert_eq!(
            out[0].flags,
            vec![
                "status-changed",
                "length-changed",
                "server-error",
                "match",
                "reflected"
            ]
        );
    }

    #[test]
    fn classified_result_serde_roundtrips() {
        let base = Baseline {
            status: 200,
            body_len: 1,
        };
        let results = vec![(vec!["p".to_string()], exchange(500, "x"))];
        let out = classify(&results, Some(&base), None);
        let json = serde_json::to_string(&out[0]).unwrap();
        let back: ClassifiedResult = serde_json::from_str(&json).unwrap();
        assert_eq!(out[0], back);
    }
}
