//! WebDriver BiDi network-capture codec (plan §5 "Browser traffic capture",
//! F05 — the browser-native capture path for the *managed* browser).
//!
//! The managed Camoufox browser speaks WebDriver BiDi. Capturing its traffic
//! means subscribing to `network.*` events and turning each into Camio's
//! [`HttpExchange`] model. This module is the **pure** half of that: it builds
//! the subscribe command and decodes BiDi event JSON into exchanges, so it is
//! fully unit-testable without a live browser. The WebSocket transport and the
//! browser launch (enabling the remote agent) are the separate, browser-
//! dependent glue that drives this codec.
//!
//! BiDi's `network.responseCompleted` event carries request and response
//! metadata (method, URL, status, headers) but **not** the response body, so a
//! captured exchange has an empty body — missing data stays explicitly absent
//! (plan §4.1) rather than being fabricated. A later interception or a BiDi
//! `network.getData` call can fill it in.

use camio_core::{Body, HeaderList, HttpExchange, HttpRequest, HttpResponse, HttpVersion, Source};
use serde_json::{json, Value};

/// The network events Camio subscribes to for capture.
pub const CAPTURE_EVENTS: &[&str] = &[
    "network.beforeRequestSent",
    "network.responseCompleted",
    "network.fetchError",
];

/// Build the BiDi `session.new` command that establishes a session before
/// subscribing (the first message a client sends after the WebSocket opens).
pub fn session_new_command(id: u64) -> Value {
    json!({
        "id": id,
        "method": "session.new",
        "params": { "capabilities": {} },
    })
}

/// Build the BiDi `session.subscribe` command that turns on network capture.
pub fn subscribe_network_command(id: u64) -> Value {
    json!({
        "id": id,
        "method": "session.subscribe",
        "params": { "events": CAPTURE_EVENTS },
    })
}

/// Decode BiDi headers (`[{name, value:{type:"string", value}}]`, or the simpler
/// `[{name, value}]` some builds emit) into a [`HeaderList`], preserving order.
fn parse_headers(value: &Value) -> HeaderList {
    let mut headers = HeaderList::new();
    if let Some(arr) = value.as_array() {
        for item in arr {
            let Some(name) = item.get("name").and_then(Value::as_str) else {
                continue;
            };
            // `value` is either `{ "type": "string", "value": "…" }` or a bare
            // string, depending on the BiDi build.
            let val = item
                .get("value")
                .and_then(|v| v.get("value").and_then(Value::as_str).or_else(|| v.as_str()));
            if let Some(val) = val {
                headers.push(name, val);
            }
        }
    }
    headers
}

/// Decode a BiDi `network.responseCompleted` event into a captured
/// [`HttpExchange`] ([`Source::Browser`]). Returns `None` if the event is not a
/// completed response or lacks a request URL.
pub fn parse_response_completed(event: &Value) -> Option<HttpExchange> {
    if let Some(method) = event.get("method").and_then(Value::as_str) {
        if method != "network.responseCompleted" {
            return None;
        }
    }
    let params = event.get("params")?;

    let req = params.get("request")?;
    let url = req.get("url").and_then(Value::as_str)?;
    let mut request = HttpRequest::get(url);
    request.method = req
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .to_string();
    request.headers = parse_headers(req.get("headers").unwrap_or(&Value::Null));

    let resp = params.get("response")?;
    let status = resp.get("status").and_then(Value::as_u64).unwrap_or(0) as u16;
    let reason = resp
        .get("statusText")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let response = HttpResponse {
        status,
        version: HttpVersion::Http11,
        reason,
        headers: parse_headers(resp.get("headers").unwrap_or(&Value::Null)),
        // BiDi does not deliver the body in this event; keep it explicitly empty.
        body: Body::empty(),
    };

    Some(HttpExchange::new(request, Source::Browser).with_response(response))
}

/// Decode a `network.fetchError` event into the failed request's URL and error
/// text, for logging a capture that never produced a response.
pub fn parse_fetch_error(event: &Value) -> Option<(String, String)> {
    if event.get("method").and_then(Value::as_str) != Some("network.fetchError") {
        return None;
    }
    let params = event.get("params")?;
    let url = params
        .get("request")
        .and_then(|r| r.get("url"))
        .and_then(Value::as_str)?
        .to_string();
    let error = params
        .get("errorText")
        .and_then(Value::as_str)
        .unwrap_or("fetch error")
        .to_string();
    Some((url, error))
}

// ---------------------------------------------------------------------------
// Interception: pause / edit / continue / drop (plan §5, F05)
// ---------------------------------------------------------------------------

/// A request paused by an interception at the `beforeRequestSent` phase: the
/// operator may continue it (optionally edited) or drop it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PausedRequest {
    pub request_id: String,
    pub url: String,
    pub method: String,
}

/// Decode a `network.beforeRequestSent` event into the paused request, if the
/// event is an interception pause (it carries `isBlocked: true`).
pub fn parse_before_request_sent(event: &Value) -> Option<PausedRequest> {
    if event.get("method").and_then(Value::as_str) != Some("network.beforeRequestSent") {
        return None;
    }
    let params = event.get("params")?;
    // `network.beforeRequestSent` fires for EVERY request once the operator has
    // subscribed to network events; only requests actually held by an intercept
    // carry `isBlocked: true`. Returning a PausedRequest for an unblocked event
    // would make a caller try to continue/fail a request the browser never
    // paused, so gate on the flag (BiDi spec: BaseParameters.isBlocked).
    if params.get("isBlocked").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let req = params.get("request")?;
    Some(PausedRequest {
        request_id: req.get("request").and_then(Value::as_str)?.to_string(),
        url: req
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        method: req
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET")
            .to_string(),
    })
}

/// Enable request interception at the `beforeRequestSent` phase (so matching
/// requests pause for the operator).
pub fn add_intercept_command(id: u64) -> Value {
    json!({
        "id": id,
        "method": "network.addIntercept",
        "params": { "phases": ["beforeRequestSent"] },
    })
}

/// Continue a paused request unchanged.
pub fn continue_request_command(id: u64, request_id: &str) -> Value {
    json!({
        "id": id,
        "method": "network.continueRequest",
        "params": { "request": request_id },
    })
}

/// Continue a paused request with edits: any of method, headers, or body may be
/// overridden (headers/body use BiDi's `{type:"string", value}` shape).
pub fn continue_request_edited_command(
    id: u64,
    request_id: &str,
    method: Option<&str>,
    headers: Option<&[(String, String)]>,
    body: Option<&str>,
) -> Value {
    let mut params = serde_json::Map::new();
    params.insert("request".into(), json!(request_id));
    if let Some(m) = method {
        params.insert("method".into(), json!(m));
    }
    if let Some(hs) = headers {
        params.insert(
            "headers".into(),
            Value::Array(
                hs.iter()
                    .map(|(n, v)| json!({ "name": n, "value": { "type": "string", "value": v } }))
                    .collect(),
            ),
        );
    }
    if let Some(b) = body {
        params.insert("body".into(), json!({ "type": "string", "value": b }));
    }
    json!({ "id": id, "method": "network.continueRequest", "params": Value::Object(params) })
}

/// Drop a paused request (fail it so it never reaches the origin).
pub fn fail_request_command(id: u64, request_id: &str) -> Value {
    json!({
        "id": id,
        "method": "network.failRequest",
        "params": { "request": request_id },
    })
}

/// Accumulates captured exchanges from a stream of BiDi messages. Transport-
/// agnostic: feed it each raw message (command result or event) and it keeps the
/// completed responses and records fetch errors. This is the capture state
/// machine — fully testable without a live browser.
#[derive(Default)]
pub struct BiDiCapture {
    exchanges: Vec<HttpExchange>,
    errors: Vec<(String, String)>,
}

impl BiDiCapture {
    pub fn new() -> Self {
        BiDiCapture::default()
    }

    /// Process one raw BiDi message: a `network.responseCompleted` event becomes
    /// a captured exchange, a `network.fetchError` is recorded, anything else is
    /// ignored.
    pub fn ingest(&mut self, message: &Value) {
        if let Some(ex) = parse_response_completed(message) {
            self.exchanges.push(ex);
        } else if let Some(err) = parse_fetch_error(message) {
            self.errors.push(err);
        }
    }

    pub fn exchanges(&self) -> &[HttpExchange] {
        &self.exchanges
    }

    pub fn errors(&self) -> &[(String, String)] {
        &self.errors
    }

    pub fn into_exchanges(self) -> Vec<HttpExchange> {
        self.exchanges
    }
}

/// A BiDi message transport (a WebSocket to the browser's remote agent, in
/// production). Abstracted so the capture loop is testable with a mock; the real
/// WebSocket implementation is the browser-dependent glue that plugs in here.
pub trait BiDiTransport {
    /// Send one BiDi command/JSON message.
    fn send(&mut self, message: &Value) -> std::io::Result<()>;
    /// Receive the next message, or `None` when the connection is closed.
    fn recv(&mut self) -> std::io::Result<Option<Value>>;
}

/// Subscribe to network events over `transport` and capture completed exchanges
/// until it closes or `stop` returns true. Pure over the transport, so the whole
/// capture session is unit-tested with a mock transport.
pub fn capture_session(
    transport: &mut impl BiDiTransport,
    mut stop: impl FnMut() -> bool,
) -> std::io::Result<BiDiCapture> {
    transport.send(&subscribe_network_command(1))?;
    let mut capture = BiDiCapture::new();
    while !stop() {
        match transport.recv()? {
            Some(message) => capture.ingest(&message),
            None => break,
        }
    }
    Ok(capture)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_new_command_is_well_formed() {
        let cmd = session_new_command(1);
        assert_eq!(cmd["method"], "session.new");
        assert!(cmd["params"]["capabilities"].is_object());
    }

    #[test]
    fn subscribe_command_targets_network_events() {
        let cmd = subscribe_network_command(7);
        assert_eq!(cmd["id"], 7);
        assert_eq!(cmd["method"], "session.subscribe");
        let events = cmd["params"]["events"].as_array().unwrap();
        assert!(events.iter().any(|e| e == "network.responseCompleted"));
    }

    #[test]
    fn decodes_a_response_completed_event() {
        let event = json!({
            "method": "network.responseCompleted",
            "params": {
                "request": {
                    "request": "req-1",
                    "url": "https://app.test/api?id=5",
                    "method": "POST",
                    "headers": [
                        { "name": "Content-Type", "value": { "type": "string", "value": "application/json" } },
                        { "name": "X-Bare", "value": "bareform" }
                    ]
                },
                "response": {
                    "url": "https://app.test/api?id=5",
                    "status": 201,
                    "statusText": "Created",
                    "headers": [
                        { "name": "Server", "value": { "type": "string", "value": "nginx" } }
                    ]
                }
            }
        });
        let ex = parse_response_completed(&event).expect("should decode");
        assert_eq!(ex.request.method, "POST");
        assert_eq!(ex.request.url, "https://app.test/api?id=5");
        assert_eq!(ex.request.headers.get("Content-Type"), Some("application/json"));
        // Bare-string header value form is handled too.
        assert_eq!(ex.request.headers.get("X-Bare"), Some("bareform"));
        let resp = ex.response.as_ref().unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.reason.as_deref(), Some("Created"));
        assert_eq!(resp.headers.get("Server"), Some("nginx"));
        // No body is delivered in this event.
        assert!(resp.body.is_empty());
        assert_eq!(ex.source, Source::Browser);
    }

    #[test]
    fn ignores_a_non_response_event() {
        let event = json!({ "method": "network.beforeRequestSent", "params": {} });
        assert!(parse_response_completed(&event).is_none());
    }

    #[test]
    fn missing_request_url_is_none() {
        let event = json!({
            "method": "network.responseCompleted",
            "params": { "request": { "method": "GET" }, "response": { "status": 200 } }
        });
        assert!(parse_response_completed(&event).is_none());
    }

    /// A mock transport that replays a queued sequence of messages, then closes.
    struct MockTransport {
        sent: Vec<Value>,
        inbox: std::collections::VecDeque<Value>,
    }
    impl BiDiTransport for MockTransport {
        fn send(&mut self, message: &Value) -> std::io::Result<()> {
            self.sent.push(message.clone());
            Ok(())
        }
        fn recv(&mut self) -> std::io::Result<Option<Value>> {
            Ok(self.inbox.pop_front())
        }
    }

    fn response_event(url: &str, status: u64) -> Value {
        json!({
            "method": "network.responseCompleted",
            "params": {
                "request": { "url": url, "method": "GET", "headers": [] },
                "response": { "status": status, "headers": [] }
            }
        })
    }

    #[test]
    fn capture_session_subscribes_then_accumulates_exchanges() {
        let mut t = MockTransport {
            sent: Vec::new(),
            inbox: [
                response_event("https://a.test/1", 200),
                json!({ "method": "network.beforeRequestSent", "params": {} }), // ignored
                response_event("https://a.test/2", 404),
            ]
            .into_iter()
            .collect(),
        };
        let capture = capture_session(&mut t, || false).unwrap();
        // It subscribed to network events first.
        assert_eq!(t.sent.len(), 1);
        assert_eq!(t.sent[0]["method"], "session.subscribe");
        // Two completed responses captured, the non-response event ignored.
        assert_eq!(capture.exchanges().len(), 2);
        assert_eq!(capture.exchanges()[0].request.url, "https://a.test/1");
        assert_eq!(capture.exchanges()[1].response.as_ref().unwrap().status, 404);
    }

    #[test]
    fn capture_session_stops_when_asked() {
        let mut t = MockTransport {
            sent: Vec::new(),
            inbox: [response_event("https://a.test/1", 200)].into_iter().collect(),
        };
        // stop() true immediately → no messages consumed after subscribe.
        let capture = capture_session(&mut t, || true).unwrap();
        assert!(capture.exchanges().is_empty());
    }

    #[test]
    fn capture_records_fetch_errors_separately() {
        let mut capture = BiDiCapture::new();
        capture.ingest(&json!({
            "method": "network.fetchError",
            "params": { "request": { "url": "https://x.test/down" }, "errorText": "boom" }
        }));
        assert!(capture.exchanges().is_empty());
        assert_eq!(capture.errors().len(), 1);
        assert_eq!(capture.errors()[0].0, "https://x.test/down");
    }

    #[test]
    fn parses_a_paused_request() {
        let event = json!({
            "method": "network.beforeRequestSent",
            "params": { "isBlocked": true, "request": {
                "request": "req-9", "url": "https://x.test/login", "method": "POST"
            } }
        });
        let paused = parse_before_request_sent(&event).unwrap();
        assert_eq!(paused.request_id, "req-9");
        assert_eq!(paused.url, "https://x.test/login");
        assert_eq!(paused.method, "POST");
    }

    #[test]
    fn an_unblocked_before_request_sent_is_not_a_pause() {
        // The event fires for every request; without `isBlocked: true` it is an
        // ordinary (non-intercepted) request and must NOT be reported as paused,
        // or a caller would try to continue/fail a request the browser never held.
        let unblocked = json!({
            "method": "network.beforeRequestSent",
            "params": { "isBlocked": false, "request": {
                "request": "req-1", "url": "https://x.test/", "method": "GET"
            } }
        });
        assert!(parse_before_request_sent(&unblocked).is_none());
        // Absent flag is treated the same as false.
        let no_flag = json!({
            "method": "network.beforeRequestSent",
            "params": { "request": { "request": "req-2", "url": "https://x.test/", "method": "GET" } }
        });
        assert!(parse_before_request_sent(&no_flag).is_none());
    }

    #[test]
    fn interception_commands_are_well_formed() {
        assert_eq!(add_intercept_command(1)["method"], "network.addIntercept");
        assert_eq!(
            continue_request_command(2, "req-9")["params"]["request"],
            "req-9"
        );
        assert_eq!(fail_request_command(3, "req-9")["method"], "network.failRequest");

        // Edited continue carries method + headers + body in BiDi shape.
        let headers = vec![("X-Edited".to_string(), "yes".to_string())];
        let cmd = continue_request_edited_command(4, "req-9", Some("PUT"), Some(&headers), Some("{}"));
        assert_eq!(cmd["method"], "network.continueRequest");
        assert_eq!(cmd["params"]["method"], "PUT");
        assert_eq!(cmd["params"]["headers"][0]["name"], "X-Edited");
        assert_eq!(cmd["params"]["headers"][0]["value"]["value"], "yes");
        assert_eq!(cmd["params"]["body"]["value"], "{}");
    }

    #[test]
    fn decodes_a_fetch_error() {
        let event = json!({
            "method": "network.fetchError",
            "params": { "request": { "url": "https://x.test/down" }, "errorText": "NS_ERROR_CONNECTION_REFUSED" }
        });
        let (url, err) = parse_fetch_error(&event).unwrap();
        assert_eq!(url, "https://x.test/down");
        assert!(err.contains("CONNECTION_REFUSED"));
    }
}
