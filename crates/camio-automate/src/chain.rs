//! Payload chaining — multi-step campaigns with variable passthrough.
//!
//! A chain is an ordered sequence of [`ChainStep`]s where each step:
//! 1. Expands template variables (`${name}`) in its request from a shared
//!    [`ChainState`] map.
//! 2. Is sent by the operator (through the matched engine, out-of-band — this
//!    crate is pure).
//! 3. Extracts named variables from the returned exchange via its
//!    [`Extractor`]s, which land in [`ChainState`] for the next step.
//!
//! Example use-cases:
//! * Fetch a CSRF token, then POST the stored-XSS payload with that token.
//! * Log in, then exercise an authenticated endpoint using the session cookie.
//! * Trigger a stored payload (step 1), then view the sink (step 2) to prove
//!   the payload reflected.
//!
//! The chain compiler produces a flat list of requests that the campaign
//! runner can push through the matched engine. Variable substitution is
//! performed deterministically; unresolved placeholders produce an error so a
//! chain with missing dependencies never silently sends garbled requests.

use crate::payloads::PayloadSet;
use camio_core::{HeaderList, HttpExchange, HttpRequest};
use std::collections::HashMap;
use std::fmt;

/// Named variables produced and consumed by chain steps.
pub type ChainState = HashMap<String, String>;

/// One step in a payload chain.
#[derive(Debug, Clone)]
pub struct ChainStep {
    /// Short human-readable label (e.g. "login", "csrf-fetch", "trigger").
    pub label: String,
    /// The request template. `${name}` tokens are substituted from
    /// [`ChainState`] when the step is materialised.
    pub request: HttpRequest,
    /// Optional payload set for this step — one request is emitted per payload
    /// (one-at-a-time; the payload is substituted into `${payload}` in the
    /// request template). If `None`, the step runs once per chain invocation.
    pub payloads: Option<PayloadSet>,
    /// Variables to extract from this step's *response* into [`ChainState`]
    /// after the step runs.
    pub extract: Vec<Extractor>,
    /// Pre-flight condition. The step is skipped if the predicate is false.
    pub when: Option<Condition>,
}

/// A simple boolean predicate over [`ChainState`]. Enough to express "skip
/// this step unless the previous one gave us a session cookie" — more complex
/// conditions should live in the runner that calls into this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// The variable is present in the state and non-empty.
    VarDefined(String),
    /// The variable is absent from the state.
    VarMissing(String),
    /// The variable equals the literal.
    VarEquals(String, String),
    /// The variable does not equal the literal.
    VarNotEquals(String, String),
    /// Boolean negation.
    Not(Box<Condition>),
    /// All sub-conditions hold.
    All(Vec<Condition>),
    /// At least one sub-condition holds.
    Any(Vec<Condition>),
}

impl Condition {
    pub fn eval(&self, state: &ChainState) -> bool {
        match self {
            Condition::VarDefined(name) => state.get(name).map(|v| !v.is_empty()).unwrap_or(false),
            Condition::VarMissing(name) => !state.contains_key(name),
            Condition::VarEquals(name, want) => state.get(name).map(|v| v == want).unwrap_or(false),
            Condition::VarNotEquals(name, want) => {
                state.get(name).map(|v| v != want).unwrap_or(true)
            }
            Condition::Not(c) => !c.eval(state),
            Condition::All(cs) => cs.iter().all(|c| c.eval(state)),
            Condition::Any(cs) => cs.iter().any(|c| c.eval(state)),
        }
    }
}

impl ChainStep {
    pub fn new(label: impl Into<String>, request: HttpRequest) -> Self {
        ChainStep {
            label: label.into(),
            request,
            payloads: None,
            extract: Vec::new(),
            when: None,
        }
    }

    pub fn with_payloads(mut self, set: PayloadSet) -> Self {
        self.payloads = Some(set);
        self
    }

    pub fn with_extractor(mut self, ex: Extractor) -> Self {
        self.extract.push(ex);
        self
    }

    pub fn when(mut self, cond: Condition) -> Self {
        self.when = Some(cond);
        self
    }
}

/// An ordered payload chain.
#[derive(Debug, Clone, Default)]
pub struct Chain {
    pub steps: Vec<ChainStep>,
}

impl Chain {
    pub fn new() -> Self {
        Chain { steps: Vec::new() }
    }

    pub fn push(mut self, step: ChainStep) -> Self {
        self.steps.push(step);
        self
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// How to pull a variable out of a captured [`HttpExchange`] response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extractor {
    /// Save the first `Set-Cookie` cookie value for the given cookie name.
    Cookie { name: String, var: String },
    /// Save a response header value.
    Header { name: String, var: String },
    /// Save text between the first `before` and the next `after` in the body.
    Between {
        before: String,
        after: String,
        var: String,
    },
    /// Save a regex capture group 1 against the body.
    Regex { pattern: String, var: String },
    /// Follow the `Location:` header after a 3xx redirect (whole URL).
    LastLocation { var: String },
    /// Save the HTTP status code (as a string).
    StatusCode { var: String },
    /// Save the full response body (bounded — large bodies truncate at 1 MiB).
    Body { var: String },
    /// Pull a field from a JSON body via a dotted path (`a.b.c`). Supports
    /// numeric array indices (`items.0.id`). Only scalar leaves are returned.
    JsonPath { path: String, var: String },
    /// Save a request-counter / "attempt number" — the number of previous
    /// responses in this chain, 1-indexed. Mainly useful for chained probes.
    AttemptIndex { var: String },
}

impl Extractor {
    pub fn var_name(&self) -> &str {
        match self {
            Extractor::Cookie { var, .. }
            | Extractor::Header { var, .. }
            | Extractor::Between { var, .. }
            | Extractor::Regex { var, .. }
            | Extractor::LastLocation { var }
            | Extractor::StatusCode { var }
            | Extractor::Body { var }
            | Extractor::JsonPath { var, .. }
            | Extractor::AttemptIndex { var } => var,
        }
    }

    /// Run this extractor on a response — for testing / UI; the real runner
    /// may do its own extraction. `attempt_index` is the 1-indexed position of
    /// this response in the chain, used only by `AttemptIndex`.
    pub fn apply(&self, ex: &HttpExchange) -> Option<String> {
        self.apply_at(ex, 1)
    }

    /// Variant of [`apply`] that lets the caller provide the chain's current
    /// attempt-index for `AttemptIndex`.
    pub fn apply_at(&self, ex: &HttpExchange, attempt_index: u64) -> Option<String> {
        let resp = ex.response.as_ref()?;
        match self {
            Extractor::Header { name, .. } => resp.headers.get(name).map(|v| v.to_string()),
            Extractor::Cookie { name, .. } => {
                for v in resp.headers.get_all("Set-Cookie") {
                    if let Some(value) = parse_cookie_value(v, name) {
                        return Some(value);
                    }
                }
                None
            }
            Extractor::Between { before, after, .. } => {
                let body = resp.body.as_text();
                let start = body.find(before)?;
                let from = start + before.len();
                let end = body[from..].find(after)?;
                Some(body[from..from + end].to_string())
            }
            Extractor::Regex { pattern, .. } => regex_capture_1(pattern, &resp.body.as_text()),
            Extractor::LastLocation { .. } => resp.headers.get("Location").map(|v| v.to_string()),
            Extractor::StatusCode { .. } => Some(resp.status.to_string()),
            Extractor::Body { .. } => {
                let text = resp.body.as_text();
                Some(truncate_chars(&text, 1024 * 1024))
            }
            Extractor::JsonPath { path, .. } => {
                let text = resp.body.as_text();
                let value: serde_json::Value = serde_json::from_str(&text).ok()?;
                let leaf = traverse_json_path(&value, path)?;
                scalar_to_string(leaf)
            }
            Extractor::AttemptIndex { .. } => Some(attempt_index.to_string()),
        }
    }
}

fn traverse_json_path<'a>(v: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = v;
    for segment in path.split('.') {
        let seg = segment.trim();
        if seg.is_empty() {
            continue;
        }
        cur = match cur {
            serde_json::Value::Object(map) => map.get(seg)?,
            serde_json::Value::Array(arr) => {
                let idx: usize = seg.parse().ok()?;
                arr.get(idx)?
            }
            _ => return None,
        };
    }
    Some(cur)
}

fn scalar_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => Some("null".to_string()),
        _ => None,
    }
}

/// Truncate to at most `max` bytes, ending on a char boundary. Slicing a
/// `String` at a raw byte offset panics when the boundary lands mid-character,
/// and response bodies are attacker-controlled — so this always floors to a
/// valid boundary.
fn truncate_chars(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn regex_capture_1(pattern: &str, body: &str) -> Option<String> {
    // regex is not a direct dep of camio-automate (yet). Do a simple-minded
    // literal fallback: find the pattern verbatim and return the following
    // non-whitespace run. This is intentionally weak; callers that need real
    // regex should use `Between` or `JsonPath`.
    let start = body.find(pattern)?;
    let after = &body[start + pattern.len()..];
    let end = after
        .find(|c: char| c.is_whitespace() || c == '<' || c == '"' || c == '\'')
        .unwrap_or(after.len());
    if end == 0 {
        None
    } else {
        Some(after[..end].to_string())
    }
}

fn parse_cookie_value(set_cookie: &str, name: &str) -> Option<String> {
    let first = set_cookie.split(';').next()?.trim();
    let (n, v) = first.split_once('=')?;
    if n.trim() == name {
        Some(v.trim().to_string())
    } else {
        None
    }
}

/// Error returned by chain compilation / substitution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A `${name}` token in the request template was not in [`ChainState`].
    UnresolvedVariable(String),
    /// A step is marked as requiring payloads but none were provided.
    MissingPayloads(String),
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::UnresolvedVariable(name) => {
                write!(
                    f,
                    "unresolved chain variable `{name}` — define it before this step runs"
                )
            }
            ChainError::MissingPayloads(label) => {
                write!(f, "step `{label}` declared payloads but the set is empty")
            }
        }
    }
}

impl std::error::Error for ChainError {}

/// One concrete request produced by chain expansion, ready to send.
#[derive(Debug, Clone)]
pub struct MaterializedStep {
    pub step_label: String,
    pub payload: Option<String>,
    pub request: HttpRequest,
}

/// Expand a chain into concrete requests under a (possibly empty) initial
/// state. One step without payloads yields one request; one step with N
/// payloads yields N requests at that step; the chain is flattened in step
/// order (step 1's N variants, then step 2's M variants, …) because the
/// runner doesn't carry state across different payload branches — a true
/// branching runner lives above this crate.
///
/// A step whose [`ChainStep::when`] predicate is false is **skipped** —
/// no requests are emitted for it.
pub fn materialize(chain: &Chain, state: &ChainState) -> Result<Vec<MaterializedStep>, ChainError> {
    let mut out: Vec<MaterializedStep> = Vec::new();
    for step in &chain.steps {
        if let Some(cond) = &step.when {
            if !cond.eval(state) {
                continue;
            }
        }
        match &step.payloads {
            None => {
                let req = substitute(&step.request, state, None)?;
                out.push(MaterializedStep {
                    step_label: step.label.clone(),
                    payload: None,
                    request: req,
                });
            }
            Some(set) if set.is_empty() => {
                return Err(ChainError::MissingPayloads(step.label.clone()));
            }
            Some(set) => {
                for p in &set.payloads {
                    let req = substitute(&step.request, state, Some(p))?;
                    out.push(MaterializedStep {
                        step_label: step.label.clone(),
                        payload: Some(p.clone()),
                        request: req,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// Static validation of a chain. Catches obvious problems without running it:
/// * references to variables that nothing extracts earlier in the chain
///   (except the reserved `payload`, which comes from the step's own set)
/// * steps whose template uses `${payload}` but declare no payload set
/// * empty labels and duplicate labels
pub fn validate(chain: &Chain) -> Result<(), Vec<ChainError>> {
    let mut errs: Vec<ChainError> = Vec::new();
    let mut known: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut labels: std::collections::HashSet<String> = std::collections::HashSet::new();
    for step in &chain.steps {
        if step.label.is_empty() {
            errs.push(ChainError::UnresolvedVariable("<empty step label>".into()));
        } else if !labels.insert(step.label.clone()) {
            errs.push(ChainError::UnresolvedVariable(format!(
                "duplicate step label `{}`",
                step.label
            )));
        }
        let tmpl_refs = collect_refs(step);
        for r in &tmpl_refs {
            if r == "payload" {
                if step.payloads.is_none() {
                    errs.push(ChainError::MissingPayloads(step.label.clone()));
                }
                continue;
            }
            if !known.contains(r) {
                errs.push(ChainError::UnresolvedVariable(format!(
                    "step `{}` references `{r}` before it is extracted",
                    step.label
                )));
            }
        }
        for ex in &step.extract {
            known.insert(ex.var_name().to_string());
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

fn collect_refs(step: &ChainStep) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in template_sources(step) {
        let mut rest = s.as_str();
        while let Some(idx) = rest.find("${") {
            let after = &rest[idx + 2..];
            if let Some(end) = after.find('}') {
                let name = after[..end].to_string();
                if !out.contains(&name) {
                    out.push(name);
                }
                rest = &after[end + 1..];
            } else {
                break;
            }
        }
    }
    out
}

fn template_sources(step: &ChainStep) -> Vec<String> {
    let mut v = vec![
        step.request.url.clone(),
        step.request.method.clone(),
        step.request.body.as_text().to_string(),
    ];
    for h in step.request.headers.iter() {
        v.push(h.name.clone());
        v.push(h.value.clone());
    }
    v
}

/// Substitute `${name}` placeholders in every field of `req` from `state`.
/// `${payload}` is substituted from `payload_value` when given.
fn substitute(
    req: &HttpRequest,
    state: &ChainState,
    payload_value: Option<&str>,
) -> Result<HttpRequest, ChainError> {
    let mut out = req.clone();
    out.url = subst(&req.url, state, payload_value)?;
    out.method = subst(&req.method, state, payload_value)?;
    let mut hdrs = HeaderList::new();
    for h in req.headers.iter() {
        hdrs.push(
            subst(&h.name, state, payload_value)?,
            subst(&h.value, state, payload_value)?,
        );
    }
    out.headers = hdrs;
    // A body is only rebuilt through text when it actually is text *and* the
    // substitution changed something: `Body::as_text()` is lossy, so round-
    // tripping a binary body (multipart, gzip, protobuf) through it would
    // replace every invalid byte with U+FFFD even with no `${…}` present.
    let body_text = req.body.as_text();
    let body = subst(&body_text, state, payload_value)?;
    out.body = if body == body_text {
        req.body.clone()
    } else if std::str::from_utf8(req.body.as_bytes()).is_ok() {
        camio_core::Body::from_text(body)
    } else {
        // The template substituted into a binary body: the result is text, so
        // it is stored as text — the caller asked for a textual substitution.
        camio_core::Body::from_text(body)
    };
    Ok(out)
}

fn subst(
    input: &str,
    state: &ChainState,
    payload_value: Option<&str>,
) -> Result<String, ChainError> {
    if !input.contains("${") {
        return Ok(input.to_string());
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        // `start` is from `find`, and `start + 2` is the length of the marker,
        // so both slices are within `rest`; `get` keeps that local.
        out.push_str(rest.get(..start).unwrap_or(""));
        let after = rest.get(start + 2..).unwrap_or("");
        let end = after.find('}').ok_or_else(|| {
            ChainError::UnresolvedVariable(format!(
                "unterminated ${{…}} at position {start} in {input:?}"
            ))
        })?;
        let name = after.get(..end).unwrap_or("");
        let value = if name == "payload" {
            payload_value
                .map(|s| s.to_string())
                .ok_or_else(|| ChainError::UnresolvedVariable("payload".to_string()))?
        } else {
            state
                .get(name)
                .cloned()
                .ok_or_else(|| ChainError::UnresolvedVariable(name.to_string()))?
        };
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HttpResponse, HttpVersion, Source};

    fn req(url: &str) -> HttpRequest {
        HttpRequest::get(url)
    }

    fn resp_with_body(body: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text(body),
        }
    }

    #[test]
    fn substitute_replaces_known_variables() {
        let mut state = ChainState::new();
        state.insert("csrf".into(), "token-123".into());
        let r = req("https://x.test/?t=${csrf}");
        let s = substitute(&r, &state, None).unwrap();
        assert_eq!(s.url, "https://x.test/?t=token-123");
    }

    #[test]
    fn substitute_fails_on_missing_variable() {
        let r = req("https://x.test/?t=${missing}");
        let err = substitute(&r, &ChainState::new(), None).unwrap_err();
        assert!(matches!(err, ChainError::UnresolvedVariable(ref n) if n == "missing"));
    }

    #[test]
    fn payload_variable_substitutes_from_arg() {
        let r = req("https://x.test/?q=${payload}");
        let s = substitute(&r, &ChainState::new(), Some("<xss>")).unwrap();
        assert_eq!(s.url, "https://x.test/?q=<xss>");
    }

    #[test]
    fn materialize_one_step_no_payloads() {
        let chain = Chain::new().push(ChainStep::new("fetch", req("https://x.test/")));
        let out = materialize(&chain, &ChainState::new()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].step_label, "fetch");
        assert!(out[0].payload.is_none());
    }

    #[test]
    fn materialize_fans_out_per_payload() {
        let set = PayloadSet::new("x", vec!["a".into(), "b".into(), "c".into()]);
        let chain = Chain::new()
            .push(ChainStep::new("fuzz", req("https://x.test/?q=${payload}")).with_payloads(set));
        let out = materialize(&chain, &ChainState::new()).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].request.url, "https://x.test/?q=a");
        assert_eq!(out[2].request.url, "https://x.test/?q=c");
    }

    #[test]
    fn materialize_fails_on_empty_payload_set() {
        let chain = Chain::new().push(
            ChainStep::new("fuzz", req("https://x.test/?q=${payload}"))
                .with_payloads(PayloadSet::new("empty", vec![])),
        );
        let err = materialize(&chain, &ChainState::new()).unwrap_err();
        assert!(matches!(err, ChainError::MissingPayloads(ref l) if l == "fuzz"));
    }

    #[test]
    fn extractor_cookie_pulls_named_cookie() {
        let mut resp = resp_with_body("");
        resp.headers
            .push("Set-Cookie", "sess=abc123; Path=/; HttpOnly");
        let ex = HttpExchange::new(req("https://x.test/"), Source::Scanner).with_response(resp);
        let got = Extractor::Cookie {
            name: "sess".into(),
            var: "session".into(),
        }
        .apply(&ex);
        assert_eq!(got.as_deref(), Some("abc123"));
    }

    #[test]
    fn extractor_header_pulls_header_value() {
        let mut resp = resp_with_body("");
        resp.headers.push("X-Csrf", "token-xyz");
        let ex = HttpExchange::new(req("https://x.test/"), Source::Scanner).with_response(resp);
        let got = Extractor::Header {
            name: "X-Csrf".into(),
            var: "csrf".into(),
        }
        .apply(&ex);
        assert_eq!(got.as_deref(), Some("token-xyz"));
    }

    #[test]
    fn extractor_between_pulls_body_fragment() {
        let resp = resp_with_body("<meta name=csrf content=\"abc-xyz\">");
        let ex = HttpExchange::new(req("https://x.test/"), Source::Scanner).with_response(resp);
        let got = Extractor::Between {
            before: "content=\"".into(),
            after: "\"".into(),
            var: "csrf".into(),
        }
        .apply(&ex);
        assert_eq!(got.as_deref(), Some("abc-xyz"));
    }

    #[test]
    fn chain_with_dependency_resolves_in_order() {
        let step1 = ChainStep::new("login", req("https://x.test/login"));
        let step2 = ChainStep::new("hit", req("https://x.test/?s=${session}"));
        let chain = Chain::new().push(step1).push(step2);
        let mut state = ChainState::new();
        state.insert("session".into(), "s-1".into());
        let out = materialize(&chain, &state).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out[1].request.url.contains("s=s-1"));
    }

    #[test]
    fn var_names_from_extractors() {
        let x = Extractor::Cookie {
            name: "sess".into(),
            var: "session".into(),
        };
        assert_eq!(x.var_name(), "session");
        let y = Extractor::Header {
            name: "X".into(),
            var: "h".into(),
        };
        assert_eq!(y.var_name(), "h");
    }

    #[test]
    fn extractor_status_code() {
        let resp = resp_with_body("ok");
        let ex = HttpExchange::new(req("https://x.test/"), Source::Scanner).with_response(resp);
        let got = Extractor::StatusCode { var: "code".into() }.apply(&ex);
        assert_eq!(got.as_deref(), Some("200"));
    }

    #[test]
    fn extractor_last_location_follows_redirect() {
        let mut resp = resp_with_body("");
        resp.status = 302;
        resp.headers.push("Location", "https://next.test/x");
        let ex = HttpExchange::new(req("https://x.test/"), Source::Scanner).with_response(resp);
        let got = Extractor::LastLocation { var: "next".into() }.apply(&ex);
        assert_eq!(got.as_deref(), Some("https://next.test/x"));
    }

    #[test]
    fn extractor_body_captures_text() {
        let resp = resp_with_body("hello world");
        let ex = HttpExchange::new(req("https://x.test/"), Source::Scanner).with_response(resp);
        let got = Extractor::Body { var: "b".into() }.apply(&ex);
        assert_eq!(got.as_deref(), Some("hello world"));
    }

    #[test]
    fn extractor_jsonpath_navigates_dotted_path() {
        let resp = resp_with_body(r#"{"user":{"id":42,"name":"a"},"items":[{"id":1},{"id":2}]}"#);
        let ex = HttpExchange::new(req("https://x.test/"), Source::Scanner).with_response(resp);
        assert_eq!(
            Extractor::JsonPath {
                path: "user.id".into(),
                var: "v".into()
            }
            .apply(&ex)
            .as_deref(),
            Some("42")
        );
        assert_eq!(
            Extractor::JsonPath {
                path: "user.name".into(),
                var: "v".into()
            }
            .apply(&ex)
            .as_deref(),
            Some("a")
        );
        assert_eq!(
            Extractor::JsonPath {
                path: "items.1.id".into(),
                var: "v".into()
            }
            .apply(&ex)
            .as_deref(),
            Some("2")
        );
        assert!(Extractor::JsonPath {
            path: "nope.nothing".into(),
            var: "v".into()
        }
        .apply(&ex)
        .is_none());
    }

    #[test]
    fn extractor_attempt_index_returns_the_argument() {
        let ex = HttpExchange::new(req("https://x.test/"), Source::Scanner)
            .with_response(resp_with_body(""));
        let got = Extractor::AttemptIndex { var: "n".into() }.apply_at(&ex, 7);
        assert_eq!(got.as_deref(), Some("7"));
    }

    #[test]
    fn condition_var_defined_tracks_state() {
        let mut state = ChainState::new();
        let c = Condition::VarDefined("session".into());
        assert!(!c.eval(&state));
        state.insert("session".into(), String::new());
        assert!(!c.eval(&state));
        state.insert("session".into(), "abc".into());
        assert!(c.eval(&state));
    }

    #[test]
    fn condition_var_equals_literal() {
        let mut state = ChainState::new();
        state.insert("role".into(), "admin".into());
        assert!(Condition::VarEquals("role".into(), "admin".into()).eval(&state));
        assert!(!Condition::VarEquals("role".into(), "user".into()).eval(&state));
        assert!(Condition::VarNotEquals("role".into(), "user".into()).eval(&state));
    }

    #[test]
    fn condition_combinators() {
        let mut s = ChainState::new();
        s.insert("a".into(), "1".into());
        s.insert("b".into(), "2".into());
        let c = Condition::All(vec![
            Condition::VarDefined("a".into()),
            Condition::VarDefined("b".into()),
        ]);
        assert!(c.eval(&s));
        let c = Condition::Any(vec![
            Condition::VarDefined("missing".into()),
            Condition::VarDefined("a".into()),
        ]);
        assert!(c.eval(&s));
        assert!(Condition::Not(Box::new(Condition::VarDefined("missing".into()))).eval(&s));
    }

    #[test]
    fn materialize_skips_when_condition_false() {
        let chain = Chain::new()
            .push(
                ChainStep::new("skipped", req("https://x.test/a"))
                    .when(Condition::VarDefined("session".into())),
            )
            .push(ChainStep::new("run", req("https://x.test/b")));
        let out = materialize(&chain, &ChainState::new()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].step_label, "run");
    }

    #[test]
    fn validate_catches_unknown_reference() {
        let chain = Chain::new().push(ChainStep::new("one", req("https://x.test/?t=${missing}")));
        let errs = validate(&chain).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ChainError::UnresolvedVariable(s) if s.contains("missing"))));
    }

    #[test]
    fn validate_accepts_extracted_variable() {
        let step1 = ChainStep::new("login", req("https://x.test/login")).with_extractor(
            Extractor::Cookie {
                name: "sess".into(),
                var: "session".into(),
            },
        );
        let step2 = ChainStep::new("hit", req("https://x.test/?s=${session}"));
        let chain = Chain::new().push(step1).push(step2);
        validate(&chain).unwrap();
    }

    #[test]
    fn validate_flags_payload_ref_without_set() {
        let chain = Chain::new().push(ChainStep::new("fuzz", req("https://x.test/?q=${payload}")));
        let errs = validate(&chain).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ChainError::MissingPayloads(_))));
    }

    #[test]
    fn validate_flags_duplicate_labels() {
        let chain = Chain::new()
            .push(ChainStep::new("x", req("https://x.test/a")))
            .push(ChainStep::new("x", req("https://x.test/b")));
        let errs = validate(&chain).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ChainError::UnresolvedVariable(s) if s.contains("duplicate"))));
    }
}

#[cfg(test)]
mod truncate_tests {
    use super::truncate_chars;

    #[test]
    fn truncates_on_char_boundaries() {
        // "é" is 2 bytes: a naive byte slice at max would panic.
        let text = "é".repeat(10);
        let out = truncate_chars(&text, 5);
        assert!(out.len() <= 5, "len was {}", out.len());
        assert_eq!(out, "é".repeat(2));
        assert_eq!(truncate_chars("hello", 60), "hello");
        // A 4-byte emoji straddling the boundary must also floor cleanly.
        let emoji = "😀".repeat(5);
        let out = truncate_chars(&emoji, 10);
        assert!(out.len() <= 10);
        assert!(out.chars().count() == 2);
    }
}

#[cfg(test)]
mod body_tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpVersion};

    fn req(url: &str) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            url: url.into(),
            version: HttpVersion::Http11,
            headers: HeaderList::new(),
            body: Body::empty(),
        }
    }

    #[test]
    fn a_binary_body_survives_an_unrelated_substitution() {
        // A multipart body with binary parts and no `${…}` must round-trip
        // byte-for-byte: `Body::as_text()` is lossy, so rebuilding it from the
        // text view would replace invalid bytes with U+FFFD.
        let binary: Vec<u8> = vec![0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe, 0x00, 0x80];
        let mut r = req("https://ex.test/upload?ref=${ref}");
        r.body = Body::from_bytes(binary.clone());
        let mut state = ChainState::new();
        state.insert("ref".into(), "b".into());
        let out = substitute(&r, &state, None).unwrap();
        assert_eq!(out.url, "https://ex.test/upload?ref=b");
        assert_eq!(
            out.body.as_bytes(),
            binary.as_slice(),
            "body must be untouched"
        );
    }

    #[test]
    fn a_template_substitution_changes_the_body() {
        let mut r = req("https://ex.test/?t=1");
        r.body = Body::from_text("A=${t}");
        let mut state = ChainState::new();
        state.insert("t".into(), "2".into());
        let out = substitute(&r, &state, None).unwrap();
        assert_eq!(out.body.as_text(), "A=2");
    }
}
