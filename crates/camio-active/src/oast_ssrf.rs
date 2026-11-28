//! OAST-driven blind SSRF detection (plan §10 active testing, §F15).
//!
//! Reflection- and error-based checks can only see what comes back *in the
//! response*. A blind server-side request forgery leaves no trace there — the
//! only evidence is the server reaching out. This check closes that gap the way
//! Burp's Collaborator does: it injects a unique, correlated callback URL
//! (served by Camio's own [`camio_oast`] collector) into each discovered input,
//! sends the probe through the scope/policy-gated [`Sender`], and then asks the
//! collector whether that token was hit. A hit is proof the target fetched an
//! attacker-controlled URL.
//!
//! Like the other checks it never touches the network itself: the caller injects
//! the `send` closure (the matched engine) and supplies a running collector.

use crate::params::{dedup_params, discovered_params, with_param};
use crate::{finding, Sender};
use camio_core::{Confidence, Finding, HttpRequest, Severity};
use camio_oast::Collector;
use std::time::Duration;

/// Probe every discovered query/body parameter with a correlated OAST callback
/// URL and report a blind-SSRF finding for any that trigger an interaction.
///
/// `settle` is how long to wait after each send for the out-of-band callback to
/// arrive before checking the collector (a callback may lag the HTTP response).
/// The collector must be reachable at the address its [`Collector::base`] names,
/// or no callback can land — the check then simply reports nothing.
pub fn run_oast_ssrf(
    base: &HttpRequest,
    send: &Sender,
    collector: &Collector,
    settle: Duration,
) -> Vec<Finding> {
    let mut out = Vec::new();
    // One settle window for the whole run, set on the first successful send.
    let mut deadline: Option<std::time::Instant> = None;
    for (kind, name) in dedup_params(discovered_params(base)) {
        // Without a token there is nothing to correlate, so stop the run rather
        // than probing with a guessable one.
        let Ok(token) = collector.new_token() else {
            // One line, not a panic: every later probe needs the same token
            // machinery, so continuing would only repeat the failure.
            eprintln!("camio: OAST probes stopped — no random bytes for a correlation token");
            break;
        };
        let url = collector.callback_url(&token);
        let before = collector.for_token(&token).len();

        let probe = with_param(base, kind, &name, &url);
        let Some(exchange) = send(probe) else {
            continue; // refused / out of budget / transport error
        };

        if !settle.is_zero() {
            // One global deadline instead of a per-probe sleep: waiting
            // `settle` after *each* send is N× settle of uninterruptible
            // blocking, so the whole run waits at most once.
            let until = *deadline.get_or_insert_with(|| std::time::Instant::now() + settle);
            let now = std::time::Instant::now();
            if now < until {
                std::thread::sleep(until - now);
            }
        }
        let hits = collector.for_token(&token).len();
        if hits > before {
            out.push(finding(
                format!("Blind SSRF via `{name}` (OAST callback)"),
                Severity::High,
                Confidence::Firm,
                format!(
                    "Injecting an out-of-band URL into `{name}` caused the target to make an \
                     HTTP callback to the Camio OAST collector (token `{token}`, {} \
                     interaction(s)). The server fetched an attacker-supplied URL — a blind \
                     server-side request forgery. Re-plant the token to reproduce.",
                    hits - before
                ),
                exchange.id,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{
        Body, ExchangeId, HeaderList, HttpExchange, HttpResponse, HttpVersion, Source,
    };
    use camio_oast::{Collector, OastServer};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    fn ok_exchange(req: HttpRequest) -> HttpExchange {
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text("ok"),
        };
        let mut ex = HttpExchange::new(req, Source::Replay).with_response(resp);
        ex.id = ExchangeId(1);
        ex
    }

    /// Minimal percent-decoder so the fake target can recover the callback URL
    /// that `with_param` percent-encoded into the query.
    fn pct_decode(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = String::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v as char);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i] as char);
            i += 1;
        }
        out
    }

    /// Start a collector + server on a loopback port; return both.
    fn collector_server() -> (std::sync::Arc<Collector>, camio_oast::OastHandle) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let collector = Collector::new(addr.to_string());
        let handle = OastServer::new(collector.clone()).spawn(listener).unwrap();
        (collector, handle)
    }

    #[test]
    fn vulnerable_target_triggers_ssrf_finding() {
        let (collector, handle) = collector_server();

        // A "vulnerable" sender: it fetches the collector-addressed URL it finds
        // in the probe (classic SSRF), then returns a benign 200.
        let needle = format!("http://{}", collector.base());
        let vulnerable = move |req: HttpRequest| -> Option<HttpExchange> {
            let decoded = pct_decode(&format!("{} {}", req.url, req.body.as_text()));
            if let Some(start) = decoded.find(&needle) {
                let tail = &decoded[start..];
                let url = tail.split([' ', '&', '"']).next().unwrap_or(tail);
                if let Some(rest) = url.strip_prefix("http://") {
                    let (authority, path) = match rest.find('/') {
                        Some(i) => (&rest[..i], &rest[i..]),
                        None => (rest, "/"),
                    };
                    if let Ok(mut s) = TcpStream::connect(authority) {
                        let _ = s.write_all(
                            format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                                .as_bytes(),
                        );
                        let mut buf = Vec::new();
                        let _ = s.read_to_end(&mut buf);
                    }
                }
            }
            Some(ok_exchange(req))
        };

        let base = HttpRequest::get("http://target.test/fetch?url=original&page=1");
        let findings = run_oast_ssrf(&base, &vulnerable, &collector, Duration::from_millis(200));
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Blind SSRF via `url`")),
            "expected an SSRF finding for `url`, got {findings:?}"
        );
        assert!(findings.iter().all(|f| f.severity == Severity::High));
        handle.stop_and_join();
    }

    #[test]
    fn safe_target_produces_no_finding() {
        let (collector, handle) = collector_server();
        // A sender that never fetches the injected URL (not vulnerable).
        let safe = |req: HttpRequest| -> Option<HttpExchange> { Some(ok_exchange(req)) };
        let base = HttpRequest::get("http://target.test/fetch?url=original");
        let findings = run_oast_ssrf(&base, &safe, &collector, Duration::from_millis(50));
        assert!(findings.is_empty(), "no callback should mean no finding");
        handle.stop_and_join();
    }
}
