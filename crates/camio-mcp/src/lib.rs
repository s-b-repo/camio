//! `camio-mcp` — Camio's local MCP server (plan §11).
//!
//! Exposes Camio's **capabilities and data** (not a 1:1 mirror of every UI
//! toggle) over the Model Context Protocol on stdio JSON-RPC, so a local agent
//! can drive the workbench under exactly the same policy the UI obeys:
//!
//! * **Resources** (read-only): fingerprint status, recent history, findings.
//! * **Tools**: run a CamioQL query, inspect scope, send a request through the
//!   matched engine.
//! * **Policy parity** (plan §11): mutating/active tools go through the shared
//!   [`Policy`] — they report a preview, the scope decision, and the fingerprint
//!   that would be used, and require confirmation before executing.
//! * **Local by default**: stdio needs no accounts, keys, or network.
//!
//! The protocol handling is split from the IO loop ([`McpServer::handle_line`])
//! so it is unit-testable without a live transport.

// The tools-list `json!` literal is large; each array element adds macro
// expansion depth, so the default recursion limit of 128 is not enough.
#![recursion_limit = "512"]

use camio_automate::{AttackType, Campaign, PayloadSet};
use camio_convert::Transform;
use camio_core::{
    ActionClass, Approval, Body, ExchangeId, FindingId, FingerprintProfile, HeaderList,
    HttpExchange, HttpRequest, HttpResponse, HttpVersion, PlanSummary, Policy, PolicyOutcome,
    Scope, SiteMap, Source, TaskId,
};
use camio_request::{DryRunEngine, FingerprintSpec, RequestEngine};
use camio_store::{bounded_limit, FindingStatus, ReviewTask, Store};
use serde_json::{json, Value};
use std::io::Write;

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "camio";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The MCP server state.
/// Hard cap on one stdio JSON-RPC message (4 MiB), matching the web API's
/// body bound so a hostile client cannot exhaust memory through either door.
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

pub struct McpServer {
    profile: FingerprintProfile,
    scope: Scope,
    policy: Policy,
    store: Option<Store>,
    engine: Box<dyn RequestEngine>,
    /// A loopback OAST collector, started lazily on the first `oast_*` tool call.
    oast: Option<OastState>,
}

struct OastState {
    collector: std::sync::Arc<camio_oast::Collector>,
    base: String,
    _handle: camio_oast::OastHandle,
}

/// Read a required string argument, rejecting wrong types instead of silently
/// coercing (a numeric `method` must not become `GET`).
fn string_arg(args: &Value, key: &str) -> Result<String, String> {
    match args.get(key) {
        None => Err(format!("missing `{key}`")),
        Some(value) => value
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("`{key}` must be a string")),
    }
}

/// Read an optional string list from an argument: a JSON array of strings, or a
/// single comma-separated string. Missing/other → empty.
fn string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// Pretty-print a tool's JSON value.
///
/// Serialization of our own types is not expected to fail, but an empty string
/// on failure is indistinguishable from "the tool produced nothing" — and an
/// MCP client receiving empty text shows the user nothing at all. Emit a
/// readable error object instead.
fn render_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value)
        .unwrap_or_else(|e| format!("{{\"error\":\"could not render result: {e}\"}}"))
}

/// Read an optional boolean argument; presence with a non-boolean value is an
/// error so `"confirm": "true"` cannot silently mean "not confirmed".
fn bool_arg(args: &Value, key: &str) -> Result<bool, String> {
    match args.get(key) {
        None => Ok(false),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("`{key}` must be a boolean")),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl McpServer {
    /// Build a server for a profile. By default it uses a [`DryRunEngine`]
    /// (no network); call [`McpServer::with_engine`] to inject the real
    /// fingerprint-matched engine.
    pub fn new(profile: FingerprintProfile) -> Self {
        let spec = FingerprintSpec::from_profile(&profile);
        McpServer {
            profile,
            scope: Scope::new(),
            policy: Policy::safe(),
            store: None,
            engine: Box::new(DryRunEngine::new(spec)),
            oast: None,
        }
    }

    pub fn with_engine(mut self, engine: Box<dyn RequestEngine>) -> Self {
        self.engine = engine;
        self
    }

    pub fn with_store(mut self, store: Store) -> Self {
        self.store = Some(store);
        self
    }

    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Run the stdio JSON-RPC loop until EOF.
    pub fn serve_stdio(&mut self) -> std::io::Result<()> {
        use std::io::BufRead as _;
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        let mut reader = stdin.lock();
        let mut line = String::new();
        loop {
            line.clear();
            // Bounded read: one JSON-RPC message per line, but a peer must not
            // be able to exhaust memory with an unterminated line.
            let read = std::io::Read::take(&mut reader, MAX_MESSAGE_BYTES as u64 + 1)
                .read_line(&mut line)?;
            if read == 0 {
                return Ok(());
            }
            if line.len() > MAX_MESSAGE_BYTES {
                let response = error_response(
                    Value::Null,
                    -32700,
                    &format!("message exceeds the {MAX_MESSAGE_BYTES}-byte limit"),
                )
                .to_string();
                writeln!(stdout, "{response}")?;
                stdout.flush()?;
                // Drain the rest of the oversized line so framing re-syncs.
                line.clear();
                let mut discard = String::new();
                reader.read_line(&mut discard)?;
                continue;
            }
            if line.trim().is_empty() {
                continue;
            }
            if let Some(response) = self.handle_line(&line) {
                writeln!(stdout, "{response}")?;
                stdout.flush()?;
            }
        }
    }

    /// Handle one line of input, returning the JSON response line (or `None` for
    /// notifications and unparseable input).
    pub fn handle_line(&mut self, line: &str) -> Option<String> {
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return Some(
                    error_response(Value::Null, -32700, &format!("parse error: {e}")).to_string(),
                )
            }
        };
        self.handle_message(&msg).map(|v| v.to_string())
    }

    /// Dispatch a parsed JSON-RPC message.
    pub fn handle_message(&mut self, msg: &Value) -> Option<Value> {
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let is_request = msg.get("id").is_some();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(Value::Null);

        match method {
            "initialize" => reply(is_request, id, self.initialize_result()),
            // Notifications never get a response.
            m if m.starts_with("notifications/") => None,
            "ping" => reply(is_request, id, json!({})),
            "tools/list" => reply(is_request, id, json!({ "tools": tool_defs() })),
            "tools/call" => reply(is_request, id, self.call_tool(&params)),
            "resources/list" => reply(is_request, id, json!({ "resources": resource_defs() })),
            "resources/read" => match self.read_resource(&params) {
                Ok(v) => reply(is_request, id, v),
                Err(e) => Some(error_response(id, -32602, &e)),
            },
            other => Some(error_response(
                id,
                -32601,
                &format!("method not found: {other}"),
            )),
        }
    }

    fn initialize_result(&self) -> Value {
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {}, "resources": {} },
            "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
            "instructions": "Camio: a fingerprint-transparent web security workbench. \
                Query history with CamioQL, check scope, and send requests through the \
                matched engine. Sending is policy-gated: out-of-scope/blocked destinations \
                are refused and in-scope sends require confirm:true."
        })
    }

    // --- Tools --------------------------------------------------------------

    fn call_tool(&mut self, params: &Value) -> Value {
        let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        let result = match name {
            "camioql_query" => self.tool_camioql_query(&args),
            "history_recent" => self.tool_history_recent(&args),
            "fingerprint_status" => Ok(self.fingerprint_status()),
            "scope_decide" => self.tool_scope_decide(&args),
            "findings_list" => self.tool_findings_list(),
            "send_request" => self.tool_send_request(&args),
            "convert" => self.tool_convert(&args),
            "scan" => self.tool_scan(&args),
            "review_start" => self.tool_review_start(&args),
            "review_workflows" => self.tool_review_workflows(),
            "review_workflow_run" => self.tool_review_workflow_run(&args),
            "review_tasks" => self.tool_review_tasks(),
            "review_task" => self.tool_review_task(&args),
            "review_cancel" => self.tool_review_cancel(&args),
            "review_report" => self.tool_review_report(&args),
            "report_export" => self.tool_report_export(&args),
            "review_evidence_bundle" => self.tool_review_evidence_bundle(&args),
            "inventory_list" => self.tool_inventory_list(&args),
            "inventory_asset" => self.tool_inventory_asset(&args),
            "inventory_evidence" => self.tool_inventory_evidence(&args),
            "findings_report" => self.tool_findings_report(),
            "sequencer_analyze" => self.tool_sequencer(&args),
            "discover_inputs" => self.tool_discover(&args),
            "sitemap" => self.tool_sitemap(&args),
            "fuzz_plan" => self.tool_fuzz_plan(&args),
            "import_file" => self.tool_import(&args),
            "payloads_list" => Ok(self.tool_payloads()),
            "active_scan" => self.tool_active_scan(&args),
            "autopilot" => self.tool_autopilot(&args),
            "analyze_js" => self.tool_analyze_js(&args),
            "oast_new_token" => self.tool_oast_new_token(),
            "oast_interactions" => self.tool_oast_interactions(&args),
            "subfinder_enum" => self.tool_subfinder(&args),
            "findings_set_status" => self.tool_findings_set_status(&args),
            "saved_searches" => self.tool_saved_searches(),
            "tasks_list" => self.tool_tasks_list(&args),
            "captcha_detect" => self.tool_captcha_detect(&args),
            "pow_detect" => self.tool_pow_detect(&args),
            "pow_solve" => self.tool_pow_solve(&args),
            "random_persona" => self.tool_random_persona(&args),
            "jwt_analyze" => self.tool_jwt_analyze(&args),
            "favicon_hash" => self.tool_favicon_hash(&args),
            "tech_detect" => self.tool_tech_detect(&args),
            "attack_surface" => self.tool_attack_surface(&args),
            other => Err(format!("unknown tool: {other}")),
        };
        match result {
            Ok(v) => tool_text(&render_json(&v), false),
            Err(e) => tool_text(&e, true),
        }
    }

    fn tool_camioql_query(&self, args: &Value) -> Result<Value, String> {
        let query = match args.get("query") {
            None => String::new(),
            Some(_) => string_arg(args, "query")?,
        };
        let limit = bounded_limit(args.get("limit").and_then(|l| l.as_u64()), 50);
        let compiled =
            camio_core::Query::compile(&query).map_err(|e| format!("invalid CamioQL: {e}"))?;
        let store = self.store.as_ref().ok_or("no history store configured")?;
        let results = store
            .query(&compiled, limit)
            .map_err(|e| format!("query failed: {e}"))?;
        Ok(json!({
            "query": query,
            "count": results.len(),
            "exchanges": results.iter().map(exchange_summary).collect::<Vec<_>>(),
        }))
    }

    /// Detect CAPTCHA widgets in a supplied HTML body (passive, no traffic).
    fn tool_captcha_detect(&self, args: &Value) -> Result<Value, String> {
        let body = string_arg(args, "html")?;
        let hits = camio_scan::detect_captcha_in_html(&body);
        Ok(json!({
            "count": hits.len(),
            "captchas": hits.iter().map(|k| json!({
                "kind": k.as_str(),
                "solver_hint": k.solver_hint(),
            })).collect::<Vec<_>>(),
        }))
    }

    /// Detect a proof-of-work anti-bot wall in a supplied HTML body (passive).
    fn tool_pow_detect(&self, args: &Value) -> Result<Value, String> {
        let body = string_arg(args, "html")?;
        let hits = camio_scan::detect_pow_in_response(&body, None, None);
        Ok(json!({
            "count": hits.len(),
            "systems": hits.iter().map(|s| json!({
                "system": s.as_str(),
                "solver_hint": s.solver_hint(),
            })).collect::<Vec<_>>(),
        }))
    }

    /// Solve a SHA-256 proof-of-work challenge locally (pure compute; no
    /// traffic). Supports Anubis (leading-hex-zeros) and hashcash/mCaptcha
    /// (leading-bit-zeros). The solve is bounded, so a too-hard challenge
    /// returns an error rather than spinning.
    fn tool_pow_solve(&self, args: &Value) -> Result<Value, String> {
        use camio_automate::pow;
        let challenge = string_arg(args, "challenge")?;
        let difficulty = args
            .get("difficulty")
            .and_then(|d| d.as_u64())
            .unwrap_or(4) as u32;
        let bits = args.get("bits").and_then(|b| b.as_bool()).unwrap_or(false);
        let anubis = args.get("anubis").and_then(|b| b.as_bool()).unwrap_or(false);
        let ch = if anubis {
            pow::parse_anubis(&challenge)
                .ok_or("could not parse an Anubis challenge from `challenge`")?
        } else if bits {
            pow::PowChallenge::hashcash(challenge, difficulty)
        } else {
            pow::PowChallenge::anubis(challenge, difficulty)
        };
        match pow::solve(&ch) {
            Ok(sol) => Ok(json!({
                "nonce": sol.nonce,
                "nonce_string": sol.nonce_string,
                "hash_hex": sol.hash_hex,
                "iterations": sol.iterations,
            })),
            Err(e) => Err(format!("proof-of-work solve failed: {e}")),
        }
    }

    /// Generate a realistic, blend-in random persona (coherent OS/GPU/hardware/
    /// screen/locale), deterministic from `seed`. Read-only; produces no traffic.
    fn tool_random_persona(&self, args: &Value) -> Result<Value, String> {
        let seed = args.get("seed").and_then(|s| s.as_u64());
        let persona = match seed {
            Some(s) => camio_core::Persona::random(s),
            None => camio_core::Persona::random_from_entropy(),
        };
        Ok(json!({
            "seed": seed,
            "user_agent": persona.user_agent,
            "platform": persona.platform,
            "locale": persona.locale,
            "accept_language": persona.accept_language,
            "timezone": persona.timezone,
            "hardware_concurrency": persona.hardware_concurrency,
            "device_memory": persona.device_memory,
            "screen": { "width": persona.screen.width, "height": persona.screen.height },
            "webgl_vendor": persona.webgl_vendor,
            "webgl_renderer": persona.webgl_renderer,
            "note": "A Firefox persona consistent with the matched engine; apply via `camio fingerprint random --seed <seed>` or `camio send --persona-seed <seed>`.",
        }))
    }

    /// Analyze a JWT for weaknesses (alg:none, guessable HMAC secret, claim
    /// hygiene). Offline; the only "attack" is an offline secret guess against
    /// the built-in or supplied wordlist.
    fn tool_jwt_analyze(&self, args: &Value) -> Result<Value, String> {
        let token = string_arg(args, "token")?;
        let wordlist: Vec<String> = args
            .get("wordlist")
            .and_then(|w| w.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let a = camio_convert::analyze_jwt(&token, &wordlist, None)
            .map_err(|e| format!("jwt: {e}"))?;
        Ok(json!({
            "alg": a.alg,
            "header": a.header_json,
            "payload": a.payload_json,
            "cracked_secret": a.cracked_secret,
            "issues": a.issues.iter().map(|i| json!({
                "severity": format!("{:?}", i.severity).to_lowercase(),
                "title": i.title,
                "detail": i.detail,
            })).collect::<Vec<_>>(),
        }))
    }

    /// Compute the Shodan favicon hash (http.favicon.hash) of base64-encoded
    /// favicon bytes, for asset correlation across Shodan/Censys/FOFA.
    fn tool_favicon_hash(&self, args: &Value) -> Result<Value, String> {
        let b64 = string_arg(args, "base64")?;
        let hash = camio_convert::favicon_hash_base64(&b64).map_err(|e| format!("favicon: {e}"))?;
        Ok(json!({
            "hash": hash,
            "shodan_query": format!("http.favicon.hash:{hash}"),
        }))
    }

    /// Build the exchange to analyse: load a stored one by `exchange_id`, or
    /// synthesize from a supplied `url` + response `headers` + `body` (what an
    /// agent has after fetching a page). Read-only; sends nothing.
    fn exchange_from_args(&self, args: &Value) -> Result<HttpExchange, String> {
        if let Some(id) = args.get("exchange_id").and_then(|v| v.as_i64()) {
            let store = self.store.as_ref().ok_or("no history store configured")?;
            return store
                .get(ExchangeId(id))
                .map_err(|e| format!("loading exchange {id}: {e}"))?
                .ok_or_else(|| format!("no stored exchange with id {id}"));
        }
        let url = string_arg(args, "url")?;
        let mut headers = HeaderList::new();
        if let Some(obj) = args.get("headers").and_then(|v| v.as_object()) {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    headers.push(k, s);
                }
            }
        }
        if headers.get("Content-Type").is_none() {
            headers.push("Content-Type", "text/html");
        }
        let body = args.get("body").and_then(|v| v.as_str()).unwrap_or("");
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers,
            body: Body::from_text(body),
        };
        Ok(HttpExchange::new(HttpRequest::get(&url), Source::Mcp).with_response(resp))
    }

    /// Fingerprint the technology stack (Wappalyzer engine: versions +
    /// implies + confidence) of a stored or supplied response. Passive.
    fn tool_tech_detect(&self, args: &Value) -> Result<Value, String> {
        let ex = self.exchange_from_args(args)?;
        let resp = ex.response.as_ref().ok_or("exchange has no response")?;
        let techs = camio_scan::detect_tech(resp);
        Ok(json!({
            "count": techs.len(),
            "technologies": techs.iter().map(|t| json!({
                "name": t.name,
                "version": t.version,
                "categories": t.categories,
                "confidence": t.confidence,
                "implied": t.implied,
            })).collect::<Vec<_>>(),
        }))
    }

    /// Synthesize an attack surface: fuse tech/WAF/takeover recon into bounded
    /// guidance — which payload-DB categories to try, which evasion encodings a
    /// WAF warrants, and a scope rule to keep follow-up on this host. Pure
    /// analysis: it does NOT send. Execution stays with the scope/policy-gated
    /// tools (active_scan / fuzz_plan / send_request), so this cannot widen
    /// what is reachable — it only prioritises what is already authorized.
    fn tool_attack_surface(&self, args: &Value) -> Result<Value, String> {
        let ex = self.exchange_from_args(args)?;
        let s = camio_scan::analyze_attack_surface(&ex);
        Ok(json!({
            "host": s.host,
            "technologies": s.technologies.iter().map(|t| json!({
                "name": t.name, "version": t.version, "categories": t.categories,
                "confidence": t.confidence, "implied": t.implied,
            })).collect::<Vec<_>>(),
            "wafs": s.wafs,
            "takeover_candidate": s.takeover,
            "suggested_payload_categories": s.suggested_payload_categories,
            "suggested_evasion_encodings": s.suggested_encodings.iter()
                .map(|e| format!("{e:?}")).collect::<Vec<_>>(),
            "suggested_scope_rule": s.suggested_scope_rule,
            "notes": s.notes,
            "next_steps": "To act on this, call fuzz_plan/active_scan with these payload categories, or send_request — all scope- and policy-gated and requiring confirm:true. This tool only plans.",
        }))
    }

    fn tool_history_recent(&self, args: &Value) -> Result<Value, String> {
        let limit = bounded_limit(args.get("limit").and_then(|l| l.as_u64()), 50);
        let store = self.store.as_ref().ok_or("no history store configured")?;
        let results = store
            .recent(limit)
            .map_err(|e| format!("history failed: {e}"))?;
        Ok(json!({
            "count": results.len(),
            "exchanges": results.iter().map(exchange_summary).collect::<Vec<_>>(),
        }))
    }

    fn tool_scope_decide(&self, args: &Value) -> Result<Value, String> {
        let url = args
            .get("url")
            .and_then(|u| u.as_str())
            .ok_or("missing `url`")?;
        let ex = HttpExchange::new(HttpRequest::get(url), Source::Mcp);
        let decision = self.scope.decide(&ex);
        Ok(json!({ "url": url, "decision": decision.as_str() }))
    }

    fn tool_findings_list(&self) -> Result<Value, String> {
        let store = self.store.as_ref().ok_or("no store configured")?;
        let findings = store.list_findings().map_err(|e| e.to_string())?;
        Ok(serde_json::to_value(findings).unwrap_or(json!([])))
    }

    /// Set a finding's triage status (plan §F14).
    fn tool_findings_set_status(&mut self, args: &Value) -> Result<Value, String> {
        let id = args
            .get("finding_id")
            .and_then(serde_json::Value::as_i64)
            .ok_or("missing `finding_id`")?;
        let status = args
            .get("status")
            .and_then(|s| s.as_str())
            .and_then(FindingStatus::parse)
            .ok_or("`status` must be open|confirmed|false_positive|fixed|ignored")?;
        let note = args.get("note").and_then(|n| n.as_str());
        let store = self.store.as_mut().ok_or("no store configured")?;
        store
            .set_finding_status(FindingId(id), status, note)
            .map_err(|e| e.to_string())?;
        Ok(json!({ "finding_id": id, "status": status.as_str() }))
    }

    /// List saved CamioQL searches (plan §F07).
    fn tool_saved_searches(&self) -> Result<Value, String> {
        let store = self.store.as_ref().ok_or("no store configured")?;
        let items = store.list_saved_searches().map_err(|e| e.to_string())?;
        Ok(json!(items
            .iter()
            .map(|(name, query)| json!({ "name": name, "query": query }))
            .collect::<Vec<_>>()))
    }

    /// Durable background-task records (plan §4.2): the same rows `camio tasks`
    /// prints and the web API serves, so a run that finished — or was
    /// interrupted by a restart — is visible instead of vanishing.
    fn tool_tasks_list(&self, args: &Value) -> Result<Value, String> {
        let store = self.store.as_ref().ok_or("no store configured")?;
        let limit = args
            .get("limit")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(50)
            .clamp(1, 200);
        let rows = store.tasks(limit).map_err(|e| e.to_string())?;
        Ok(json!({ "tasks": rows }))
    }

    /// Lazily start a loopback OAST collector so `oast_*` tools share one.
    fn ensure_oast(&mut self) -> Result<&OastState, String> {
        if self.oast.is_none() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
            let addr = listener.local_addr().map_err(|e| e.to_string())?;
            let collector = camio_oast::Collector::new(addr.to_string());
            let handle = camio_oast::OastServer::new(collector.clone())
                .spawn(listener)
                .map_err(|e| e.to_string())?;
            self.oast = Some(OastState {
                collector,
                base: addr.to_string(),
                _handle: handle,
            });
        }
        // Reading back what was just stored: an error, not an assumption, so a
        // future refactor that moves the assignment cannot turn this into a
        // panic inside an MCP tool call.
        self.oast
            .as_ref()
            .ok_or_else(|| "oast collector failed to start".into())
    }

    /// Mint a correlated OAST token and its callback URLs. The collector listens
    /// on loopback, so it only records callbacks the target can route to this host.
    fn tool_oast_new_token(&mut self) -> Result<Value, String> {
        let st = self.ensure_oast()?;
        let token = st
            .collector
            .new_token()
            .map_err(|e| format!("minting an OAST token: {e}"))?;
        Ok(json!({
            "token": token,
            "callback_url": st.collector.callback_url(&token),
            "dns_callback_url": st.collector.dns_callback_url(&token),
            "base": st.base,
            "note": "Plant callback_url in a payload (SSRF/blind injection), then poll oast_interactions with this token. Loopback base: only callbacks the target can route here are seen."
        }))
    }

    /// Enumerate subdomains of a domain with subfinder (external, passive OSINT).
    fn tool_subfinder(&self, args: &Value) -> Result<Value, String> {
        let domain = string_arg(args, "domain")?;
        let confirm = bool_arg(args, "confirm").unwrap_or(false);
        // Enumeration sends traffic about a domain, so it runs the same
        // authorization path as every other network action (plan §16).
        let decision = self.scope.decide(&HttpExchange::new(
            HttpRequest::get(format!("https://{domain}/")),
            Source::Mcp,
        ));
        match self
            .policy
            .gate_action_with(ActionClass::Active, &self.scope, decision, confirm)
        {
            PolicyOutcome::Deny(reason) => return Err(format!("refused: {reason}")),
            PolicyOutcome::NeedsConfirmation(reason) => {
                return Ok(json!({
                    "status": "confirmation_required",
                    "reason": reason,
                    "scope": decision.as_str(),
                    "note": "re-call subfinder_enum with confirm:true to enumerate",
                }));
            }
            PolicyOutcome::Allow => {}
        }
        let timeout_secs = args
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(60)
            .clamp(5, 180);
        let opts = camio_integrations::SubfinderOptions {
            all_sources: args
                .get("all_sources")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            timeout: std::time::Duration::from_secs(timeout_secs),
            ..Default::default()
        };
        let subs = camio_integrations::run_subfinder(std::slice::from_ref(&domain), &opts)
            .map_err(|e| e.to_string())?;
        let hosts = camio_integrations::unique_hosts(&subs);
        Ok(json!({ "domain": domain, "count": hosts.len(), "hosts": hosts }))
    }

    /// List recorded OAST interactions, optionally filtered to one token.
    fn tool_oast_interactions(&mut self, args: &Value) -> Result<Value, String> {
        let token = args
            .get("token")
            .and_then(|t| t.as_str())
            .map(str::to_string);
        let st = self.ensure_oast()?;
        let items = match &token {
            Some(t) => st.collector.for_token(t),
            None => st.collector.all(),
        };
        let interactions: Vec<Value> = items
            .iter()
            .map(|i| {
                json!({
                    "id": i.id,
                    "token": i.token,
                    "method": i.method,
                    "target": i.target,
                    "host": i.host,
                    "source": i.source,
                    "received_at_ms": i.received_at_ms,
                })
            })
            .collect();
        Ok(json!({ "count": interactions.len(), "interactions": interactions }))
    }

    fn tool_send_request(&mut self, args: &Value) -> Result<Value, String> {
        let url = string_arg(args, "url")?;
        let method = match args.get("method") {
            None => "GET".to_string(),
            Some(_) => string_arg(args, "method")?,
        };
        let confirm = bool_arg(args, "confirm")?;

        let mut req = HttpRequest::get(&url);
        req.method = method.to_string();
        if let Some(headers) = args.get("headers") {
            apply_headers(&mut req, headers);
        }
        if let Some(body) = args.get("body").and_then(|b| b.as_str()) {
            req.body = camio_core::Body::from_text(body);
        }

        // One scope-decision path, shared with the UI.
        let probe = HttpExchange::new(req.clone(), Source::Mcp);
        let decision = self.scope.decide(&probe);

        // Sending is a mutating action — gate it through the shared policy.
        match self.policy.gate(ActionClass::Mutating, decision, confirm) {
            PolicyOutcome::Deny(reason) => Err(format!("refused: {reason}")),
            PolicyOutcome::NeedsConfirmation(reason) => Ok(json!({
                "status": "confirmation_required",
                "reason": reason,
                "preview": {
                    "method": method,
                    "url": url,
                    "scope": decision.as_str(),
                    "engine": self.engine.label(),
                    "fingerprint_matched": self.engine.is_fingerprint_matched(),
                    "fingerprint_target": self.engine.spec().target_label(),
                },
                "note": "re-call send_request with confirm:true to execute",
            })),
            PolicyOutcome::Allow => {
                let ex = self
                    .engine
                    .send(req, Source::Mcp)
                    .map_err(|e| format!("send failed: {e}"))?;
                // A failed persist must be distinguishable from "no store":
                // silently dropping the exchange would report a successful send
                // of traffic that is no longer recoverable.
                let stored_id = match self.store.as_mut() {
                    Some(store) => Some(store.insert(&ex).map_err(|e| e.to_string())?.0),
                    None => None,
                };
                let mut summary = exchange_summary(&ex);
                if let Some(id) = stored_id {
                    summary["stored_id"] = json!(id);
                }
                summary["fingerprint_matched"] = json!(self.engine.is_fingerprint_matched());
                Ok(summary)
            }
        }
    }

    // --- Capability tools (plan §11 MCP coverage) ---------------------------

    /// Apply a Convert/Decoder pipeline to a string input.
    fn tool_convert(&self, args: &Value) -> Result<Value, String> {
        let input = args
            .get("input")
            .and_then(|i| i.as_str())
            .ok_or("missing `input`")?;
        let steps = parse_transforms(args.get("steps"))?;
        if steps.is_empty() {
            return Err("no transforms given in `steps`".into());
        }
        let out =
            camio_convert::apply_pipeline(input.as_bytes(), &steps).map_err(|e| e.to_string())?;
        // Present binary output as hex via the same crate (no extra dependency).
        let hex = Transform::HexEncode
            .apply(&out)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        Ok(json!({
            "steps": steps.iter().map(|t| t.name()).collect::<Vec<_>>(),
            "output_len": out.len(),
            "output_text": String::from_utf8_lossy(&out),
            "output_hex": hex,
        }))
    }

    /// Run the passive scanner over stored history matching an optional CamioQL
    /// query, optionally persisting findings.
    fn tool_scan(&mut self, args: &Value) -> Result<Value, String> {
        let query = match args.get("query") {
            None => String::new(),
            Some(_) => string_arg(args, "query")?,
        };
        let limit = bounded_limit(args.get("limit").and_then(|l| l.as_u64()), 1000);
        let save = args.get("save").and_then(|s| s.as_bool()).unwrap_or(false);
        let compiled =
            camio_core::Query::compile(&query).map_err(|e| format!("invalid CamioQL: {e}"))?;
        let store = self.store.as_mut().ok_or("no history store configured")?;
        let exchanges = store
            .query_with_bodies(&compiled, limit)
            .map_err(|e| e.to_string())?;
        let report = camio_scan::scan_all(&exchanges);
        let saved = if save {
            store
                .insert_findings(&report.findings)
                .map_err(|e| e.to_string())?
        } else {
            0
        };
        Ok(json!({
            "exchanges_scanned": report.exchanges_scanned,
            "checks_run": report.checks_run,
            "finding_count": report.findings.len(),
            "saved": saved,
            "findings": serde_json::to_value(&report.findings).unwrap_or(json!([])),
        }))
    }

    fn review_store(&self) -> Result<&Store, String> {
        self.store
            .as_ref()
            .ok_or_else(|| "no history store configured".into())
    }

    fn tool_review_start(&self, args: &Value) -> Result<Value, String> {
        let path = self
            .review_store()?
            .path()
            .ok_or("a file-backed workspace is required for review tasks")?;
        let query = match args.get("query") {
            None => "",
            Some(value) => value.as_str().ok_or("query must be a string")?,
        };
        let limit = match args.get("limit") {
            None => 200,
            Some(value) => value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or("limit must be a positive integer")?,
        };
        let save = match args.get("save") {
            None => false,
            Some(value) => value.as_bool().ok_or("save must be a boolean")?,
        };
        let id = camio_scan::start_passive_review(path, query, limit, save)
            .map_err(|error| format!("{error:#}"))?;
        Ok(json!({ "id": id }))
    }

    fn tool_review_workflows(&self) -> Result<Value, String> {
        let workflows = self
            .review_store()?
            .review_workflows()
            .map_err(|error| error.to_string())?;
        Ok(
            json!({ "workflows": workflows.into_iter().map(|workflow| workflow.revision).collect::<Vec<_>>() }),
        )
    }

    fn tool_review_workflow_run(&self, args: &Value) -> Result<Value, String> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Archive {
            name: String,
            content: String,
        }
        let path = self
            .review_store()?
            .path()
            .ok_or("a file-backed workspace is required for review tasks")?;
        let id = args
            .get("id")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .ok_or("enter a positive workflow ID")?;
        let version = args
            .get("version")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .ok_or("select a saved workflow version")?;
        let task = if let Some(archive) = args.get("archive") {
            let archive: Archive =
                serde::Deserialize::deserialize(archive).map_err(|error| error.to_string())?;
            camio_scan::start_archive_review(
                path,
                id,
                Some(version),
                camio_scan::ReviewArchiveInput::Bytes {
                    name: archive.name,
                    data: archive.content.into_bytes(),
                },
            )
        } else {
            camio_scan::start_review_workflow(path, id, Some(version))
        }
        .map_err(|error| format!("{error:#}"))?;
        Ok(json!({ "id": task }))
    }

    fn tool_review_tasks(&self) -> Result<Value, String> {
        let tasks = self
            .review_store()?
            .review_tasks()
            .map_err(|error| error.to_string())?;
        Ok(json!({ "tasks": tasks.iter().map(review_summary).collect::<Vec<_>>() }))
    }

    fn tool_review_task(&self, args: &Value) -> Result<Value, String> {
        let id = review_id(args)?;
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        if offset > 1_000_000 {
            return Err("offset exceeds supported range".into());
        }
        let store = self.review_store()?;
        let task = store
            .review_task(id)
            .map_err(|error| error.to_string())?
            .ok_or("review task was not found")?;
        let findings = store
            .review_results(id, offset as usize)
            .map_err(|error| error.to_string())?;
        let rows: Vec<_> = findings.iter().map(|finding| json!({
            "id": (finding.id.0 != 0).then_some(finding.id),
            "severity": finding.severity, "confidence": finding.confidence, "evidence": finding.evidence,
        })).collect();
        Ok(json!({ "task": review_summary(&task), "findings": rows,
            "next_offset": (rows.len() == 50).then_some(offset + 50) }))
    }

    fn tool_review_cancel(&self, args: &Value) -> Result<Value, String> {
        let cancelled = self
            .review_store()?
            .cancel_review(review_id(args)?)
            .map_err(|error| error.to_string())?;
        Ok(json!({ "cancelled": cancelled }))
    }

    fn tool_findings_report(&self) -> Result<Value, String> {
        let report = self
            .review_store()?
            .finding_report(None)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(report).map_err(|error| error.to_string())
    }

    fn tool_review_report(&self, args: &Value) -> Result<Value, String> {
        let report = self
            .review_store()?
            .review_report(review_id(args)?)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(report).map_err(|error| error.to_string())
    }

    /// Export every stored finding as a redacted report (Markdown/JSON/HTML/
    /// SARIF), optionally filtered to one review state. Reuses the same shareable
    /// projection as `review_report` (no titles/detail/raw evidence), so it is
    /// safe to hand to CI or a ticket.
    fn tool_report_export(&self, args: &Value) -> Result<Value, String> {
        let store = self.review_store()?;
        let state = match args.get("status").and_then(Value::as_str) {
            None | Some("all") => None,
            Some("open") => Some(camio_store::ReviewState::Open),
            Some("confirmed") => Some(camio_store::ReviewState::Confirmed),
            Some("resolved") => Some(camio_store::ReviewState::Resolved),
            Some("dismissed") => Some(camio_store::ReviewState::Dismissed),
            Some(other) => {
                return Err(format!(
                    "unknown status `{other}` (use open|confirmed|resolved|dismissed|all)"
                ))
            }
        };
        let format = match args
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or("json")
        {
            "markdown" | "md" => camio_store::ReportFormat::Markdown,
            "json" => camio_store::ReportFormat::Json,
            "html" => camio_store::ReportFormat::Html,
            "sarif" => camio_store::ReportFormat::Sarif,
            other => {
                return Err(format!(
                    "unknown format `{other}` (use markdown|json|html|sarif)"
                ))
            }
        };
        let report = store.finding_report(state).map_err(|e| e.to_string())?;
        let rendered = report.render(format).map_err(|e| e.to_string())?;
        Ok(json!({
            "format": format.label(),
            "count": report.findings.len(),
            "report": rendered,
        }))
    }

    fn tool_review_evidence_bundle(&self, args: &Value) -> Result<Value, String> {
        let bundle = self
            .review_store()?
            .review_evidence_bundle(review_id(args)?)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(bundle).map_err(|error| error.to_string())
    }

    fn tool_inventory_list(&self, args: &Value) -> Result<Value, String> {
        let filter = args
            .get("filter")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let after = args.get("after").and_then(Value::as_str);
        let page = self
            .review_store()?
            .inventory(filter, after)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(page).map_err(|error| error.to_string())
    }

    fn tool_inventory_asset(&self, args: &Value) -> Result<Value, String> {
        let origin = args
            .get("origin")
            .and_then(Value::as_str)
            .ok_or("select a recorded origin")?;
        let after = args.get("after").and_then(Value::as_str);
        let page = self
            .review_store()?
            .asset_inventory(origin, after)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(page).map_err(|error| error.to_string())
    }

    fn tool_inventory_evidence(&self, args: &Value) -> Result<Value, String> {
        let location = args
            .get("location")
            .and_then(Value::as_str)
            .ok_or("select a recorded endpoint")?;
        let before = args.get("before").and_then(Value::as_i64);
        let page = self
            .review_store()?
            .endpoint_evidence(location, before)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(page).map_err(|error| error.to_string())
    }

    /// Estimate the randomness of a set of tokens (plan §8 Sequencer).
    fn tool_sequencer(&self, args: &Value) -> Result<Value, String> {
        let arr = args
            .get("tokens")
            .and_then(|t| t.as_array())
            .ok_or("missing `tokens` array")?;
        let tokens: Vec<String> = arr
            .iter()
            .filter_map(|t| t.as_str().map(|s| s.to_string()))
            .collect();
        let report = camio_sequencer::analyze(&tokens);
        serde_json::to_value(&report).map_err(|e| e.to_string())
    }

    /// Enumerate the injectable inputs of a request (plan §10 input discovery).
    fn tool_discover(&self, args: &Value) -> Result<Value, String> {
        let req = request_from_args(args)?;
        let inputs = camio_automate::discover_inputs(&req);
        Ok(json!({
            "count": inputs.len(),
            "inputs": serde_json::to_value(&inputs).unwrap_or(json!([])),
        }))
    }

    /// Build a site map tree from stored history (plan §7.2 Discover).
    fn tool_sitemap(&self, args: &Value) -> Result<Value, String> {
        let query = match args.get("query") {
            None => String::new(),
            Some(_) => string_arg(args, "query")?,
        };
        let limit = bounded_limit(args.get("limit").and_then(|l| l.as_u64()), 5000);
        let compiled =
            camio_core::Query::compile(&query).map_err(|e| format!("invalid CamioQL: {e}"))?;
        let store = self.store.as_ref().ok_or("no history store configured")?;
        let exchanges = store.query(&compiled, limit).map_err(|e| e.to_string())?;
        let map = SiteMap::build(&exchanges);
        Ok(json!({
            "origin_count": map.origin_count(),
            "url_count": map.url_count(),
            "tree": map.render_tree(),
        }))
    }

    /// Plan an Intruder-style campaign: report the projected request count and
    /// insertion points. Read-only — nothing is sent (plan §10: show the count
    /// and get approval; execution still goes through the policy-gated send).
    fn tool_fuzz_plan(&self, args: &Value) -> Result<Value, String> {
        let req = request_from_args(args)?;
        let attack = parse_attack(
            args.get("attack")
                .and_then(|a| a.as_str())
                .unwrap_or("sniper"),
        )?;
        let sets = resolve_payload_sets(args.get("payloads"))?;
        let budget = args.get("budget").and_then(|b| b.as_u64());
        let target = req.url.trim().to_string();
        let campaign = Campaign {
            base: req,
            attack,
            sets,
            budget,
        };
        let plan = camio_automate::plan(&campaign).map_err(|e| e.to_string())?;
        // The plan hash an operator must approve before an ACTIVE run (plan
        // §4.3): identical in meaning to the CLI's preview hash.
        let summary = PlanSummary::new(ActionClass::Active, vec![target]).with_policy(&self.policy);
        let summary = match budget {
            Some(b) => summary.with_max_requests(b),
            None => summary,
        };
        Ok(json!({
            "attack": attack.as_str(),
            "num_positions": plan.num_positions,
            "projected_requests": plan.projected_requests,
            "within_budget": plan.within_budget,
            "plan_hash": summary.plan_hash(),
            "note": "planning only — no requests sent. An ACTIVE run must bind to this plan_hash.",
            "positions": plan
                .positions
                .iter()
                .map(|p| json!({ "index": p.index, "baseline": p.baseline }))
                .collect::<Vec<_>>(),
        }))
    }

    /// Import a Burp XML or HAR file from a local path into history.
    fn tool_import(&mut self, args: &Value) -> Result<Value, String> {
        let path = args
            .get("path")
            .and_then(|p| p.as_str())
            .ok_or("missing `path`")?;
        let save = bool_arg(args, "save")?;
        let openapi = args.get("openapi").and_then(Value::as_bool).unwrap_or(false);
        let graphql = args.get("graphql").and_then(Value::as_bool).unwrap_or(false);
        let data = std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
        let result = if openapi {
            let text = String::from_utf8(data).map_err(|_| "OpenAPI spec must be UTF-8 JSON")?;
            let base = args.get("base").and_then(Value::as_str);
            camio_import::import_openapi(&text, base).map_err(|e| e.to_string())?
        } else if graphql {
            let text =
                String::from_utf8(data).map_err(|_| "GraphQL introspection must be UTF-8 JSON")?;
            let endpoint = args
                .get("base")
                .and_then(Value::as_str)
                .ok_or("graphql import requires `base` (the GraphQL endpoint URL)")?;
            camio_import::import_graphql(&text, endpoint).map_err(|e| e.to_string())?
        } else {
            camio_import::import_bytes(&data).map_err(|e| e.to_string())?
        };
        let mut stored = 0u64;
        if save {
            // Storing is only possible with a configured store — report the
            // gap instead of answering `stored: 0` as if it succeeded.
            let store = self.store.as_mut().ok_or("no history store configured")?;
            for ex in &result.exchanges {
                store
                    .insert(ex)
                    .map_err(|e| format!("storing imported exchange: {e}"))?;
                stored += 1;
            }
        }
        Ok(json!({
            "format": result.format,
            "imported": result.exchanges.len(),
            "stored": stored,
            "warnings": result.warnings,
        }))
    }

    /// List the built-in payload packs and their sizes.
    fn tool_payloads(&self) -> Value {
        let packs: Vec<Value> = camio_automate::builtin_packs()
            .iter()
            .map(|name| {
                let size = camio_automate::builtin_pack(name)
                    .map(|s| s.len())
                    .unwrap_or(0);
                json!({ "name": name, "size": size })
            })
            .collect();
        json!({ "packs": packs })
    }

    /// Run the opt-in ACTIVE scan (reflected XSS, error-based SQLi, open redirect)
    /// against a target. Policy-gated: Active class, in-scope + confirm required
    /// (plan §16); the sender re-checks scope on every probe.
    fn tool_active_scan(&mut self, args: &Value) -> Result<Value, String> {
        let base = request_from_args(args)?;
        let confirm = bool_arg(args, "confirm")?;
        // Approval binding (plan §4.3): an operator-approved plan hash must
        // cover this scan, exactly like the CLI's `--approve`.
        if let Some(approved) = args.get("approval").and_then(Value::as_str) {
            let summary = PlanSummary::new(ActionClass::Active, vec![base.url.trim().to_string()])
                .with_policy(&self.policy);
            let approval = Approval::bind(summary.clone(), now_ms()).granted_by("camio mcp");
            if approved.trim() != approval.plan_hash {
                return Err(format!(
                    "this approval does not cover the current plan (approved {approved}, plan is {})",
                    approval.plan_hash
                ));
            }
            if let Err(reason) = approval.allows(&summary, now_ms()) {
                return Err(format!("approval does not cover this plan: {reason}"));
            }
        }
        let decision = self
            .scope
            .decide(&HttpExchange::new(base.clone(), Source::Mcp));
        match self
            .policy
            .gate_action_with(ActionClass::Active, &self.scope, decision, confirm)
        {
            PolicyOutcome::Deny(reason) => return Err(format!("refused: {reason}")),
            PolicyOutcome::NeedsConfirmation(reason) => {
                return Ok(json!({
                    "status": "confirmation_required",
                    "reason": reason,
                    "scope": decision.as_str(),
                    "note": "re-call active_scan with confirm:true to run the active probes",
                }));
            }
            PolicyOutcome::Allow => {}
        }
        let findings = {
            let engine = self.engine.as_ref();
            let scope = &self.scope;
            let send_errors: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
            let send = |req: HttpRequest| -> Option<HttpExchange> {
                if !scope
                    .decide(&HttpExchange::new(req.clone(), Source::Mcp))
                    .is_sendable()
                {
                    send_errors
                        .borrow_mut()
                        .push("request refused by scope/policy".to_string());
                    return None;
                }
                match engine.send(req, Source::Mcp) {
                    Ok(ex) => Some(ex),
                    Err(e) => {
                        send_errors.borrow_mut().push(e.to_string());
                        None
                    }
                }
            };
            // Optional check selection by id (plan §F13).
            let only = string_list(args.get("only"));
            let exclude = string_list(args.get("exclude"));
            let found = camio_active::run_active_filtered(&base, &send, &only, &exclude);
            // A run where nothing could be sent is not a clean scan (plan §4.2:
            // record outcomes distinctly instead of reporting success).
            if found.is_empty() && !send_errors.borrow().is_empty() {
                return Err(format!(
                    "no probe could be sent: {}",
                    send_errors.borrow().join("; ")
                ));
            }
            found
        };
        let mut saved = 0u64;
        if let Some(store) = self.store.as_mut() {
            for f in &findings {
                if store.insert_finding(f).is_ok() {
                    saved += 1;
                }
            }
        }
        Ok(json!({
            "status": "done",
            "count": findings.len(),
            "saved": saved,
            "findings": serde_json::to_value(&findings).unwrap_or(json!([])),
        }))
    }

    /// One-shot automated recon + active sweep (plan §8/§10): baseline send →
    /// attack-surface synthesis → every active check (incl. the HTTP method
    /// audit) → responses bucketed by status class. Scope- and policy-gated,
    /// confirmation-required. `aggressive` adds PUT/DELETE/PATCH capability
    /// probes (aimed at a non-existent sub-path, never the real resource) and is
    /// gated as DESTRUCTIVE. It probes; it does not fuzz payloads.
    fn tool_autopilot(&mut self, args: &Value) -> Result<Value, String> {
        let base = request_from_args(args)?;
        let aggressive = args
            .get("aggressive")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let confirm = bool_arg(args, "confirm")?;
        let class = if aggressive {
            ActionClass::Destructive
        } else {
            ActionClass::Active
        };

        // Optional approval binding (parity with active_scan, plan §4.3).
        if let Some(approved) = args.get("approval").and_then(Value::as_str) {
            let summary =
                PlanSummary::new(class, vec![base.url.trim().to_string()]).with_policy(&self.policy);
            let approval = Approval::bind(summary.clone(), now_ms()).granted_by("camio mcp");
            if approved.trim() != approval.plan_hash {
                return Err(format!(
                    "this approval does not cover the current plan (approved {approved}, plan is {})",
                    approval.plan_hash
                ));
            }
            if let Err(reason) = approval.allows(&summary, now_ms()) {
                return Err(format!("approval does not cover this plan: {reason}"));
            }
        }

        let decision = self
            .scope
            .decide(&HttpExchange::new(base.clone(), Source::Mcp));
        match self
            .policy
            .gate_action_with(class, &self.scope, decision, confirm)
        {
            PolicyOutcome::Deny(reason) => return Err(format!("refused: {reason}")),
            PolicyOutcome::NeedsConfirmation(reason) => {
                return Ok(json!({
                    "status": "confirmation_required",
                    "reason": reason,
                    "scope": decision.as_str(),
                    "note": if aggressive {
                        "re-call autopilot with confirm:true to run the sweep (aggressive: DESTRUCTIVE write-method probes)"
                    } else {
                        "re-call autopilot with confirm:true to run the sweep"
                    },
                }));
            }
            PolicyOutcome::Allow => {}
        }

        let fuzz_arg = args.get("fuzz").and_then(Value::as_bool).unwrap_or(false);
        let fuzz_budget = args
            .get("fuzz_budget")
            .and_then(Value::as_u64)
            .unwrap_or(200)
            .min(2000) as usize;
        let crawl_arg = args.get("crawl").and_then(Value::as_bool).unwrap_or(false);
        let crawl_pages = args
            .get("crawl_pages")
            .and_then(Value::as_u64)
            .unwrap_or(15)
            .min(100) as usize;

        let (surface_json, findings, summary, fuzz) = {
            let engine = self.engine.as_ref();
            let scope = &self.scope;
            let statuses: std::cell::RefCell<Vec<Option<u16>>> = std::cell::RefCell::new(Vec::new());
            let send_errors: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
            let send = |req: HttpRequest| -> Option<HttpExchange> {
                if !scope
                    .decide(&HttpExchange::new(req.clone(), Source::Mcp))
                    .is_sendable()
                {
                    send_errors
                        .borrow_mut()
                        .push("request refused by scope/policy".to_string());
                    return None;
                }
                match engine.send(req, Source::Mcp) {
                    Ok(ex) => {
                        statuses
                            .borrow_mut()
                            .push(ex.response.as_ref().map(|r| r.status));
                        Some(ex)
                    }
                    Err(e) => {
                        send_errors.borrow_mut().push(e.to_string());
                        None
                    }
                }
            };

            // 1. Baseline send → attack-surface synthesis.
            let baseline_ex = send(base.clone());
            let surface = baseline_ex
                .as_ref()
                .map(camio_scan::analyze_attack_surface);
            let surface_json = surface.as_ref().map(|s| {
                json!({
                    "host": s.host,
                    "technologies": s.technologies.iter().map(|t| json!({
                        "name": t.name, "version": t.version, "categories": t.categories,
                        "confidence": t.confidence, "implied": t.implied,
                    })).collect::<Vec<_>>(),
                    "wafs": s.wafs,
                    "takeover_candidate": s.takeover,
                    "suggested_payload_categories": s.suggested_payload_categories,
                    "suggested_evasion_encodings": s.suggested_encodings.iter()
                        .map(|e| format!("{e:?}")).collect::<Vec<_>>(),
                    "suggested_scope_rule": s.suggested_scope_rule,
                    "notes": s.notes,
                })
            });

            // 2. Active sweep: every default check (incl. the read-only method
            //    audit), plus the opt-in write-method probes when aggressive.
            let mut found = camio_active::run_active(&base, &send);
            if aggressive {
                found.extend(
                    camio_active::HttpMethodAudit::with_write_methods()
                        .run_write_probes(&base, &send),
                );
            }

            // 2b. Optional crawl: discover more same-origin pages (scope-gated)
            //     and run the active checks on each — a site sweep, not one URL.
            let mut crawl_targets: Vec<HttpRequest> = Vec::new();
            if crawl_arg {
                let opts = camio_active::CrawlOptions {
                    max_pages: crawl_pages.max(1),
                    same_origin_only: true,
                };
                let result = camio_active::crawl(&base.url, &send, &opts);
                for url in result
                    .discovered
                    .iter()
                    .filter(|u| u.as_str() != base.url)
                    .take(crawl_pages)
                {
                    let page = HttpRequest::get(url);
                    if scope
                        .decide(&HttpExchange::new(page.clone(), Source::Mcp))
                        .is_sendable()
                    {
                        // The seed already reports host-level method findings;
                        // keep only resource-specific findings per crawled page.
                        found.extend(
                            camio_active::run_active(&page, &send)
                                .into_iter()
                                .filter(|f| !camio_active::is_host_level_finding(f)),
                        );
                        crawl_targets.push(page);
                    }
                }
            }

            // 3. Optional bounded payload-DB fuzz of the stack-suggested
            //    categories — the hand-off from "recon recommends" to "act on
            //    it", still gated: every probe flows through the scope-checked
            //    `send` closure above (plan §16).
            let fuzz = if fuzz_arg {
                let baseline = baseline_ex
                    .as_ref()
                    .and_then(|ex| ex.response.as_ref())
                    .map(|r| camio_automate::Baseline {
                        status: r.status,
                        body_len: r.body.len(),
                    });
                let db = camio_automate::load_payload_db();
                let cats: Vec<camio_active::FuzzCategory> = surface
                    .as_ref()
                    .map(|s| {
                        s.suggested_payload_categories
                            .iter()
                            .filter_map(|c| {
                                db.categories.get(c).map(|set| camio_active::FuzzCategory {
                                    name: c.clone(),
                                    set,
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                if cats.is_empty() {
                    None
                } else {
                    // Fuzz the seed and every crawled page, sharing the budget.
                    let targets: Vec<&HttpRequest> =
                        std::iter::once(&base).chain(crawl_targets.iter()).collect();
                    let per_target = (fuzz_budget / targets.len().max(1)).max(1);
                    let mut agg = camio_active::AutoFuzzSummary::default();
                    for target in targets {
                        let s = camio_active::run_auto_fuzz(
                            target,
                            &cats,
                            per_target,
                            baseline.as_ref(),
                            None,
                            &send,
                        );
                        agg.attempts += s.attempts;
                        agg.sent += s.sent;
                        agg.results.extend(s.results);
                    }
                    Some(agg)
                }
            } else {
                None
            };

            // A run where the baseline failed and nothing could be sent is not a
            // clean sweep (plan §4.2).
            if baseline_ex.is_none() && found.is_empty() && !send_errors.borrow().is_empty() {
                return Err(format!(
                    "no probe could be sent: {}",
                    send_errors.borrow().join("; ")
                ));
            }

            // 4. Response status summary across every probe sent above (incl. fuzz).
            let summary =
                camio_automate::StatusSummary::from_statuses(statuses.borrow().iter().copied());
            (surface_json, found, summary, fuzz)
        };

        let mut saved = 0u64;
        if let Some(store) = self.store.as_mut() {
            for f in &findings {
                if store.insert_finding(f).is_ok() {
                    saved += 1;
                }
            }
        }

        let next_steps = if fuzz.is_some() {
            "Flagged fuzz results are in `fuzz.results` (server-error/reflected/status-changed). Deepen with fuzz_plan on a specific category/input, all scope/policy-gated."
        } else {
            "Act on attack_surface.suggested_payload_categories by re-calling autopilot with fuzz:true, or fuzz_plan on a category — both scope/policy-gated, confirm-required. This sweep probed inputs and methods; it did not fuzz payloads."
        };
        Ok(json!({
            "status": "done",
            "scope": decision.as_str(),
            "attack_surface": surface_json,
            "finding_count": findings.len(),
            "saved": saved,
            "findings": serde_json::to_value(&findings).unwrap_or(json!([])),
            "status_summary": serde_json::to_value(&summary).unwrap_or(json!({})),
            "fuzz": serde_json::to_value(&fuzz).unwrap_or(json!(null)),
            "next_steps": next_steps,
        }))
    }

    /// Passively extract hard-coded secrets and endpoints from a JS (or any) blob.
    fn tool_analyze_js(&self, args: &Value) -> Result<Value, String> {
        let body = args
            .get("body")
            .and_then(|b| b.as_str())
            .ok_or("missing `body`")?;
        let a = camio_scan::analyze_js(body);
        Ok(json!({ "secrets": a.secrets, "endpoints": a.endpoints }))
    }

    // --- Resources ----------------------------------------------------------

    fn read_resource(&self, params: &Value) -> Result<Value, String> {
        let uri = params
            .get("uri")
            .and_then(|u| u.as_str())
            .ok_or("missing `uri`")?;
        let text = match uri {
            "camio://fingerprint/status" => render_json(&self.fingerprint_status()),
            "camio://history/recent" => {
                let store = self.store.as_ref().ok_or("no store configured")?;
                let ex = store.recent(50).map_err(|e| e.to_string())?;
                let summaries: Vec<_> = ex.iter().map(exchange_summary).collect();
                render_json(&summaries)
            }
            "camio://findings" => {
                let store = self.store.as_ref().ok_or("no store configured")?;
                let f = store.list_findings().map_err(|e| e.to_string())?;
                render_json(&f)
            }
            other => return Err(format!("unknown resource: {other}")),
        };
        Ok(json!({
            "contents": [ { "uri": uri, "mimeType": "application/json", "text": text } ]
        }))
    }

    /// The fingerprint status surface (plan §6.3, §7.2 status indicator).
    pub fn fingerprint_status(&self) -> Value {
        json!({
            "profile": self.profile.name,
            "camoufox_build": self.profile.camoufox_build,
            "persona_user_agent": self.profile.persona.user_agent,
            "engine": self.engine.label(),
            "fingerprint_matched": self.engine.is_fingerprint_matched(),
            "fingerprint_target": self.engine.spec().target_label(),
            "parity_note": self.engine.parity_note(),
            "disclaimer": "Parity is measured, not asserted. This never claims invisibility.",
        })
    }
}

/// Apply a JSON `headers` value (object `{name:value}` or array of
/// `{name, value}`) to a request, preserving order for the array form.
fn apply_headers(req: &mut HttpRequest, headers: &Value) {
    match headers {
        Value::Object(map) => {
            for (k, v) in map {
                if let Some(s) = v.as_str() {
                    req.headers.push(k.clone(), s.to_string());
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                let name = item.get("name").and_then(|n| n.as_str());
                let value = item.get("value").and_then(|v| v.as_str());
                if let (Some(n), Some(v)) = (name, value) {
                    req.headers.push(n.to_string(), v.to_string());
                }
            }
        }
        _ => {}
    }
}

/// Build an [`HttpRequest`] from the common `{url, method?, headers?, body?}`
/// tool arguments (shared by discover/fuzz).
fn request_from_args(args: &Value) -> Result<HttpRequest, String> {
    let url = args
        .get("url")
        .and_then(|u| u.as_str())
        .ok_or("missing `url`")?;
    let mut req = HttpRequest::get(url);
    if let Some(m) = args.get("method").and_then(|m| m.as_str()) {
        req.method = m.to_string();
    }
    if let Some(headers) = args.get("headers") {
        apply_headers(&mut req, headers);
    }
    if let Some(body) = args.get("body").and_then(|b| b.as_str()) {
        req.body = camio_core::Body::from_text(body);
    }
    Ok(req)
}

/// Parse a `steps` value (array of names, or a comma-separated string) into a
/// Convert pipeline.
fn parse_transforms(v: Option<&Value>) -> Result<Vec<Transform>, String> {
    let mut steps = Vec::new();
    match v {
        Some(Value::Array(items)) => {
            for it in items {
                let name = it
                    .as_str()
                    .ok_or("each step must be a transform name string")?;
                steps.push(Transform::from_name(name).ok_or(format!("unknown transform: {name}"))?);
            }
        }
        Some(Value::String(s)) => {
            for name in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
                steps.push(Transform::from_name(name).ok_or(format!("unknown transform: {name}"))?);
            }
        }
        _ => return Err("`steps` must be an array of transform names or a comma string".into()),
    }
    Ok(steps)
}

/// Parse an attack-type token (`sniper`, `battering_ram`/`battering-ram`, …).
fn parse_attack(s: &str) -> Result<AttackType, String> {
    Ok(match s.to_ascii_lowercase().replace('-', "_").as_str() {
        "sniper" => AttackType::Sniper,
        "battering_ram" => AttackType::BatteringRam,
        "pitchfork" => AttackType::Pitchfork,
        "cluster_bomb" => AttackType::ClusterBomb,
        other => return Err(format!("unknown attack type: {other}")),
    })
}

/// Resolve a `payloads` argument (array of built-in pack names) to payload sets.
fn resolve_payload_sets(v: Option<&Value>) -> Result<Vec<PayloadSet>, String> {
    let arr = v
        .and_then(|x| x.as_array())
        .ok_or("missing `payloads`: an array of built-in pack names")?;
    let mut sets = Vec::new();
    for item in arr {
        let name = item
            .as_str()
            .ok_or("each payload entry must be a pack name string")?;
        let set = camio_automate::builtin_pack(name).ok_or(format!(
            "unknown payload pack `{name}` (known: {})",
            camio_automate::builtin_packs().join(", ")
        ))?;
        sets.push(set);
    }
    if sets.is_empty() {
        return Err("provide at least one payload pack".into());
    }
    Ok(sets)
}

/// A compact JSON summary of an exchange for tool/resource output.
fn exchange_summary(ex: &HttpExchange) -> Value {
    json!({
        "id": ex.id.0,
        "method": ex.request.method,
        "url": ex.request.url,
        "host": ex.request.host(),
        "status": ex.response.as_ref().map(|r| r.status),
        "resp_len": ex.response.as_ref().map(|r| r.body.len()),
        "source": ex.source.as_str(),
        "scope": ex.scope.map(|s| s.as_str()),
        "fingerprint": ex.fingerprint_used,
        "roundtrip_ms": ex.timings.map(|t| t.roundtrip_ms),
    })
}

fn tool_text(text: &str, is_error: bool) -> Value {
    json!({
        "content": [ { "type": "text", "text": text } ],
        "isError": is_error,
    })
}

fn review_id(args: &Value) -> Result<TaskId, String> {
    args.get("id")
        .and_then(Value::as_i64)
        .filter(|id| *id > 0)
        .map(TaskId)
        .ok_or_else(|| "enter a positive task ID".into())
}

fn review_summary(review: &ReviewTask) -> Value {
    let archive = review.archive.as_ref().map(|archive| {
        json!({
            "format": archive.format, "sha256": archive.sha256, "imported": archive.imported,
            "warning_count": archive.warning_count, "reused": archive.reused,
        })
    });
    json!({ "id": review.task.id, "state": review.task.state, "limit": review.limit, "save": review.save,
        "counts": review.counts, "workflow": review.workflow, "archive": archive,
        "created_at_ms": review.task.created_at_ms, "updated_at_ms": review.updated_at_ms })
}

fn tool_defs() -> Value {
    json!([
            {
                "name": "camioql_query",
                "description": "Run a CamioQL (HTTPQL-compatible) query over captured history and return matching exchanges.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "CamioQL, e.g. resp.code.gte:500 AND req.host.cont:\"example\"" },
                        "limit": { "type": "integer", "description": "Max results (default 50)" }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "history_recent",
                "description": "Return the most recent captured exchanges.",
                "inputSchema": { "type": "object", "properties": { "limit": { "type": "integer" } } }
            },
            {
                "name": "fingerprint_status",
                "description": "Report the active fingerprint profile, the matched-engine target, and whether traffic is fingerprint-matched. Never claims invisibility.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "scope_decide",
                "description": "Return the scope decision (in_scope / out_of_scope / blocked) for a URL, via the one shared scope path.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "url": { "type": "string" } },
                    "required": ["url"]
                }
            },
            {
                "name": "findings_list",
                "description": "List recorded findings, most severe first.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "send_request",
                "description": "Send a request through the fingerprint-matched engine. Policy-gated: out-of-scope/blocked destinations are refused; in-scope sends require confirm:true (a dry call returns a preview with the scope decision and fingerprint).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" },
                        "method": { "type": "string", "description": "default GET" },
                        "headers": { "type": "object", "description": "name:value map" },
                        "body": { "type": "string" },
                        "confirm": { "type": "boolean", "description": "must be true to actually send" }
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "convert",
                "description": "Apply a Convert/Decoder pipeline (base64, url, html, hex, gzip/deflate, md5/sha1/sha256/sha512) to a string. Steps run left to right.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "input": { "type": "string" },
                        "steps": { "type": "array", "items": { "type": "string" }, "description": "e.g. [\"base64\",\"gzip\"] or a comma string \"base64,hex\"" }
                    },
                    "required": ["input", "steps"]
                }
            },
            {
                "name": "scan",
                "description": "Run passive security checks over stored history matching an optional CamioQL query; returns findings. Set save:true to persist them.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "CamioQL filter; empty = all history" },
                        "limit": { "type": "integer" },
                        "save": { "type": "boolean", "description": "persist findings to the findings store" }
                    }
                }
            },
            {
                "name": "sequencer_analyze",
                "description": "Estimate the randomness/entropy of a set of tokens (session ids, CSRF tokens). Statistical estimate, not a cryptographic proof.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "tokens": { "type": "array", "items": { "type": "string" } } },
                    "required": ["tokens"]
                }
            },
            {
                "name": "discover_inputs",
                "description": "Enumerate the injectable inputs (query/body params, cookies, notable headers, JSON fields) of a request.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" },
                        "method": { "type": "string" },
                        "headers": { "type": "object" },
                        "body": { "type": "string" }
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "sitemap",
                "description": "Build a site map tree (origin -> paths, with methods and statuses) from stored history matching an optional CamioQL query.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "query": { "type": "string" }, "limit": { "type": "integer" } }
                }
            },
            {
                "name": "fuzz_plan",
                "description": "Plan an Intruder-style campaign: report the projected request count and insertion points for a §-marked request. Read-only; nothing is sent.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string", "description": "URL; mark insertion points with §…§" },
                        "method": { "type": "string" },
                        "headers": { "type": "object" },
                        "body": { "type": "string" },
                        "attack": { "type": "string", "description": "sniper | battering_ram | pitchfork | cluster_bomb" },
                        "payloads": { "type": "array", "items": { "type": "string" }, "description": "built-in pack names (see payloads_list)" },
                        "budget": { "type": "integer" }
                    },
                    "required": ["url", "payloads"]
                }
            },
            {
                "name": "import_file",
                "description": "Import a Burp items XML export, a HAR archive, an OpenAPI 3.x / Swagger 2.0 spec (openapi:true), or a GraphQL introspection result (graphql:true) from a local path into history. OpenAPI generates one request-only exchange per path+method op (`base` overrides the server/host); GraphQL generates one POST per root Query/Mutation field (`base` is the GraphQL endpoint URL). Nothing is sent. save:true (default) persists the exchanges.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "save": { "type": "boolean" },
                        "openapi": { "type": "boolean", "description": "parse the file as an OpenAPI/Swagger spec" },
                        "graphql": { "type": "boolean", "description": "parse the file as a GraphQL introspection result" },
                        "base": { "type": "string", "description": "OpenAPI: origin override; GraphQL: endpoint URL" }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "payloads_list",
                "description": "List the built-in payload packs and their sizes.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "active_scan",
                "description": "Opt-in ACTIVE scan (reflected XSS, error-based SQLi, open redirect) against a target. Sends probes via the matched engine. Policy-gated: out-of-scope/blocked refused; requires confirm:true (a dry call returns the scope decision).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" },
                        "method": { "type": "string" },
                        "headers": { "type": "object" },
                        "body": { "type": "string" },
                        "only": { "type": "array", "items": { "type": "string" }, "description": "run only these active checks by id (reflected-xss, error-based-sqli, open-redirect, http-method-audit)" },
                        "exclude": { "type": "array", "items": { "type": "string" }, "description": "skip these active checks by id" },
                        "confirm": { "type": "boolean", "description": "must be true to run the active probes" }
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "autopilot",
                "description": "One-shot automated recon + active sweep: send a baseline request, fingerprint the stack (tech/WAF/takeover via the Wappalyzer engine), run every active check (reflected XSS, error-based SQLi, open redirect, HTTP method audit), and bucket every response by status class (2xx/3xx/4xx/5xx). Scope- and policy-gated; requires confirm:true (a dry call returns the scope decision). aggressive:true also probes PUT/DELETE/PATCH capability against a non-existent sub-path (never the real resource) and is gated as DESTRUCTIVE. fuzz:true closes the loop: after the sweep it fuzzes the stack-suggested payload-DB categories against discovered query/body inputs (bounded by fuzz_budget, split across categories) and returns the flagged results in `fuzz.results`. Every probe — including fuzz — flows through the same scope-checked sender.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" },
                        "method": { "type": "string" },
                        "headers": { "type": "object" },
                        "body": { "type": "string" },
                        "aggressive": { "type": "boolean", "description": "also run PUT/DELETE/PATCH capability probes (DESTRUCTIVE class; requires the server policy to allow destructive testing)" },
                        "crawl": { "type": "boolean", "description": "crawl same-origin pages first (scope-gated) and run the active checks on each — a site sweep, not one URL" },
                        "crawl_pages": { "type": "integer", "minimum": 1, "maximum": 100, "description": "max pages to crawl/sweep when crawl:true (default 15)" },
                        "fuzz": { "type": "boolean", "description": "after the sweep, fuzz the stack-suggested payload-DB categories against discovered inputs (bounded, gated)" },
                        "fuzz_budget": { "type": "integer", "minimum": 1, "maximum": 2000, "description": "max fuzz probe attempts, split across categories (default 200, capped 2000)" },
                        "confirm": { "type": "boolean", "description": "must be true to run the sweep" },
                        "approval": { "type": "string", "description": "optional approved plan hash binding this run" }
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "analyze_js",
                "description": "Passively extract hard-coded secrets (redacted) and referenced endpoints from a JavaScript (or any) body.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "body": { "type": "string" } },
                    "required": ["body"]
                }
            },
            {
                "name": "oast_new_token",
                "description": "Mint a correlated OAST token and callback URLs (a local Collaborator-style collector starts on first use). Plant the URL in a payload, then poll oast_interactions. Loopback-bound: only callbacks that can reach this host are seen.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "oast_interactions",
                "description": "List out-of-band interactions the OAST collector recorded, optionally filtered to one token — evidence of blind SSRF/injection callbacks.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "token": { "type": "string", "description": "Correlation token from oast_new_token; omit for all interactions." } }
                }
            },
            {
                "name": "subfinder_enum",
                "description": "Enumerate subdomains of a domain with subfinder (external, passive OSINT). Bounded run; returns the unique host list. Requires subfinder on PATH.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": { "type": "string", "description": "Root domain, e.g. example.com" },
                        "all_sources": { "type": "boolean" },
                        "timeout_secs": { "type": "integer", "minimum": 5, "maximum": 180 }
                    },
                    "required": ["domain"]
                }
            },
            {
                "name": "findings_set_status",
                "description": "Triage a stored finding: set its lifecycle status (open|confirmed|false_positive|fixed|ignored) with an optional note.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "finding_id": { "type": "integer" },
                        "status": { "type": "string" },
                        "note": { "type": "string" }
                    },
                    "required": ["finding_id", "status"]
                }
            },
            {
                    "name": "tasks_list",
                    "description": "List durable background-task records (state, progress, outcome); \
                                   read-only — restart reconciliation happens at startup or via \
                                   `camio tasks --reconcile`.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 }
                        }
                    }
                },
    {
                "name": "saved_searches",
                "description": "List saved CamioQL searches (name + query) stored in the workspace.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "captcha_detect",
                "description": "Passively detect CAPTCHA widgets (reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile, inline image CAPTCHAs) in a supplied HTML body, with a routing hint per hit. No traffic is sent.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "html": { "type": "string", "description": "The HTML body to inspect." } },
                    "required": ["html"]
                }
            },
            {
                "name": "pow_detect",
                "description": "Passively detect a proof-of-work anti-bot wall (Anubis, mCaptcha, generic hashcash) in a supplied HTML body. Unlike a CAPTCHA, a PoW wall is solvable locally via pow_solve.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "html": { "type": "string", "description": "The HTML body to inspect." } },
                    "required": ["html"]
                }
            },
            {
                "name": "pow_solve",
                "description": "Solve a SHA-256 proof-of-work challenge locally (pure compute, no traffic). Default is Anubis-style leading-zero-hex difficulty; set bits:true for hashcash/mCaptcha leading-zero-bit difficulty, or anubis:true to parse an Anubis challenge JSON blob. Bounded — a too-hard challenge returns an error.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "challenge": { "type": "string", "description": "The challenge string (or Anubis JSON when anubis:true)." },
                        "difficulty": { "type": "integer", "description": "Leading zero hex chars (default) or bits (bits:true). Default 4." },
                        "bits": { "type": "boolean", "description": "Interpret difficulty as leading zero BITS (hashcash/mCaptcha)." },
                        "anubis": { "type": "boolean", "description": "Parse `challenge` as an Anubis challenge JSON blob." }
                    },
                    "required": ["challenge"]
                }
            },
            {
                "name": "random_persona",
                "description": "Generate a realistic, blend-in random browser persona (coherent OS/GPU/hardware/screen/locale drawn from real-world distributions), deterministic from seed. A Firefox persona consistent with the matched engine; apply via `camio send --persona-seed <seed>`. No traffic.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "seed": { "type": "integer", "description": "Seed for reproducibility; omit for a one-off identity." } }
                }
            },
            {
                "name": "jwt_analyze",
                "description": "Analyze a JWT for weaknesses (jwt_tool-style): the alg:none bypass, a guessable HMAC secret (offline guess against a built-in or supplied wordlist), and claim hygiene (missing/expired exp, future nbf). Offline — no traffic; the only 'attack' is the offline secret guess.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "token": { "type": "string", "description": "The compact JWT (header.payload.signature)." },
                        "wordlist": { "type": "array", "items": { "type": "string" }, "description": "HMAC secrets to try; omit to use the built-in common-secret list." }
                    },
                    "required": ["token"]
                }
            },
            {
                "name": "favicon_hash",
                "description": "Compute the Shodan favicon hash (http.favicon.hash) of a favicon, for asset correlation across Shodan/Censys/FOFA (find other hosts serving the same favicon — shadow IT, origin servers behind a CDN). Pass the favicon bytes base64-encoded.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "base64": { "type": "string", "description": "Standard-base64 of the favicon file bytes." } },
                    "required": ["base64"]
                }
            },
            {
                "name": "tech_detect",
                "description": "Fingerprint a target's technology stack (Wappalyzer engine: servers, languages, frameworks, CMSes, JS libraries — with versions, confidence and implied technologies). Pass exchange_id to read a stored response, or url + headers (object) + body to analyze a supplied one. Passive; no traffic.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "exchange_id": { "type": "integer", "description": "A stored exchange id to analyze." },
                        "url": { "type": "string", "description": "Target URL (when supplying a response directly)." },
                        "headers": { "type": "object", "description": "Response headers as a name->value map." },
                        "body": { "type": "string", "description": "Response body (HTML)." }
                    }
                }
            },
            {
                "name": "attack_surface",
                "description": "Synthesize a bounded attack plan from passive recon: detect the tech stack + WAF/CDN + takeover candidate, then recommend which payload-DB categories to test, which evasion encodings a WAF warrants, and a CamioQL scope rule to keep follow-up on this host. Use this to turn recon into a prioritized plan, then act via the gated fuzz_plan/active_scan/send_request tools. Pure analysis — it does NOT send and cannot widen scope. Input like tech_detect (exchange_id, or url+headers+body).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "exchange_id": { "type": "integer" },
                        "url": { "type": "string" },
                        "headers": { "type": "object" },
                        "body": { "type": "string" }
                    }
                }
            },
            {
                "name": "review_start",
                "description": "Start a background passive review of previously stored traffic. Returns a task ID.",
                "inputSchema": { "type": "object", "properties": {
                    "query": { "type": "string", "maxLength": 1024 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "save": { "type": "boolean" }
                } }
            },
            {
                "name": "review_tasks",
                "description": "List recent passive review tasks.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "review_workflows",
                "description": "List the current versions of saved offline review workflows.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "review_workflow_run",
                "description": "Run an exact saved workflow version on stored exchanges or an explicitly supplied capture archive. Returns a passive review task ID.",
                "inputSchema": { "type": "object", "properties": {
                    "id": { "type": "integer", "minimum": 1 }, "version": { "type": "integer", "minimum": 1 },
                    "archive": { "type": "object", "properties": {
                        "name": { "type": "string", "maxLength": 512 },
                        "content": { "type": "string", "maxLength": 4194304, "description": "Content of a recorded HAR or Burp items XML archive" }
                    }, "required": ["name", "content"], "additionalProperties": false }
                }, "required": ["id", "version"], "additionalProperties": false }
            },
            {
                "name": "review_task",
                "description": "Read progress and paginated evidence references from a passive review.",
                "inputSchema": { "type": "object", "properties": {
                    "id": { "type": "integer", "minimum": 1 }, "offset": { "type": "integer", "minimum": 0 }
                }, "required": ["id"] }
            },
            {
                "name": "review_cancel",
                "description": "Stop a queued or running passive review while retaining committed results.",
                "inputSchema": { "type": "object", "properties": {
                    "id": { "type": "integer", "minimum": 1 }
                }, "required": ["id"] }
            },
            {
                "name": "findings_report",
                "description": "Export finding statuses and evidence references without free text or captured messages.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "review_report",
                "description": "Export a finished review task's redacted results and capture provenance.",
                "inputSchema": { "type": "object", "properties": {
                    "id": { "type": "integer", "minimum": 1 }
                }, "required": ["id"], "additionalProperties": false }
            },
            {
                "name": "report_export",
                "description": "Export every stored finding as a redacted, shareable report. format: markdown|json|html|sarif (default json). status filters to a review state: open|confirmed|resolved|dismissed|all (default all). Returns the rendered report text and finding count; no titles/detail/raw evidence are included, so it is safe for CI or a ticket.",
                "inputSchema": { "type": "object", "properties": {
                    "format": { "type": "string", "enum": ["markdown", "json", "html", "sarif"] },
                    "status": { "type": "string", "enum": ["open", "confirmed", "resolved", "dismissed", "all"] }
                }, "additionalProperties": false }
            },
            {
                "name": "review_evidence_bundle",
                "description": "Export checksummed, redacted evidence linked to a finished review task.",
                "inputSchema": { "type": "object", "properties": {
                    "id": { "type": "integer", "minimum": 1 }
                }, "required": ["id"], "additionalProperties": false }
            },
            {
                "name": "inventory_list",
                "description": "List normalized origins recorded in local captures and imported observations.",
                "inputSchema": { "type": "object", "properties": {
                    "filter": { "type": "string", "maxLength": 256 }, "after": { "type": "string" }
                }, "additionalProperties": false }
            },
            {
                "name": "inventory_asset",
                "description": "Read a recorded origin's endpoints and local notes.",
                "inputSchema": { "type": "object", "properties": {
                    "origin": { "type": "string" }, "after": { "type": "string" }
                }, "required": ["origin"], "additionalProperties": false }
            },
            {
                "name": "inventory_evidence",
                "description": "Read local evidence pointers for a recorded endpoint.",
                "inputSchema": { "type": "object", "properties": {
                    "location": { "type": "string" }, "before": { "type": "integer" }
                }, "required": ["location"], "additionalProperties": false }
            }
        ])
}

fn resource_defs() -> Value {
    json!([
        { "uri": "camio://fingerprint/status", "name": "Fingerprint status", "description": "Active profile, matched-engine target, parity note.", "mimeType": "application/json" },
        { "uri": "camio://history/recent", "name": "Recent history", "description": "The 50 most recent exchanges.", "mimeType": "application/json" },
        { "uri": "camio://findings", "name": "Findings", "description": "Recorded findings.", "mimeType": "application/json" }
    ])
}

fn reply(is_request: bool, id: Value, result: Value) -> Option<Value> {
    if !is_request {
        return None;
    }
    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> McpServer {
        let profile = FingerprintProfile::new("win-firefox-158-balanced", "158.0.1-beta.41");
        McpServer::new(profile).with_store(Store::open_in_memory().unwrap())
    }

    fn call(server: &mut McpServer, line: &str) -> Value {
        let out = server.handle_line(line).expect("expected a response");
        serde_json::from_str(&out).unwrap()
    }

    fn tool_payload(resp: &Value) -> Value {
        // Unwrap the MCP tool-result envelope back into the tool's JSON.
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        serde_json::from_str(text).unwrap_or(json!({ "raw": text }))
    }

    #[test]
    fn initialize_reports_capabilities() {
        let mut s = server();
        let resp = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#);
        assert_eq!(resp["result"]["serverInfo"]["name"], "camio");
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
    }

    #[test]
    fn notifications_get_no_response() {
        let mut s = server();
        assert!(s
            .handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .is_none());
    }

    #[test]
    fn new_tools_are_listed() {
        let mut s = server();
        let resp = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for expected in ["captcha_detect", "pow_detect", "pow_solve", "random_persona"] {
            assert!(names.contains(&expected), "{expected} not listed");
        }
    }

    #[test]
    fn captcha_detect_tool_flags_recaptcha() {
        let mut s = server();
        let resp = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"captcha_detect","arguments":{"html":"<div class=\"g-recaptcha\"></div>"}}}"#,
        );
        let payload = tool_payload(&resp);
        assert_eq!(payload["count"], 1);
        assert_eq!(payload["captchas"][0]["kind"], "reCAPTCHA v2");
    }

    #[test]
    fn pow_detect_and_solve_tools_work() {
        let mut s = server();
        // Detect an Anubis wall.
        let d = tool_payload(&call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pow_detect","arguments":{"html":"<script src=\"/.within.website/x/cmd/anubis/x.js\"></script>"}}}"#,
        ));
        assert_eq!(d["systems"][0]["system"], "Anubis");

        // Solve a small challenge and confirm the hash meets the difficulty.
        let r = tool_payload(&call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pow_solve","arguments":{"challenge":"mcp","difficulty":2}}}"#,
        ));
        assert!(r["hash_hex"].as_str().unwrap().starts_with("00"));
        assert!(r["iterations"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn tech_detect_tool_reports_versions_and_implies() {
        let mut s = server();
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tech_detect","arguments":{"url":"https://x.test/","headers":{"X-Powered-By":"Next.js 14.1.0"},"body":""}}}"#;
        let p = tool_payload(&call(&mut s, req));
        let techs = p["technologies"].as_array().unwrap();
        let next = techs.iter().find(|t| t["name"] == "Next.js").unwrap();
        assert_eq!(next["version"], "14.1.0");
        // React is implied by Next.js.
        assert!(techs
            .iter()
            .any(|t| t["name"] == "React" && t["implied"] == true));
    }

    #[test]
    fn attack_surface_tool_fuses_recon_into_a_plan() {
        let mut s = server();
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"attack_surface","arguments":{"url":"https://shop.test/","headers":{"Server":"cloudflare","X-Powered-By":"PHP/8.1"},"body":"<link href=\"/wp-content/x.css\">"}}}"#;
        let p = tool_payload(&call(&mut s, req));
        assert_eq!(p["host"], "shop.test");
        assert!(p["wafs"].as_array().unwrap().iter().any(|w| w == "Cloudflare"));
        let cats = p["suggested_payload_categories"].as_array().unwrap();
        assert!(cats.iter().any(|c| c == "lfi")); // from PHP
        assert!(cats.iter().any(|c| c == "fuzz")); // baseline
        // WAF present → evasion encodings suggested.
        assert!(!p["suggested_evasion_encodings"].as_array().unwrap().is_empty());
        assert_eq!(p["suggested_scope_rule"], "host:shop.test");
        // Integrity note: it does not send / cannot widen scope.
        assert!(p["notes"].as_array().unwrap().iter().any(|n| n
            .as_str()
            .unwrap()
            .contains("scope- and policy-gated")));
    }

    #[test]
    fn jwt_analyze_tool_cracks_weak_secret() {
        let mut s = server();
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"jwt_analyze","arguments":{{"token":"{token}"}}}}}}"#
        );
        let p = tool_payload(&call(&mut s, &req));
        assert_eq!(p["alg"], "hs256");
        assert_eq!(p["cracked_secret"], "your-256-bit-secret");
    }

    #[test]
    fn favicon_hash_tool_matches_the_pure_fn() {
        let mut s = server();
        // "YWJj" is standard-base64 of b"abc"; assert the tool agrees with the
        // pure function on the decoded bytes.
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"favicon_hash","arguments":{"base64":"YWJj"}}}"#;
        let p = tool_payload(&call(&mut s, req));
        assert_eq!(
            p["hash"].as_i64().unwrap() as i32,
            camio_convert::favicon_hash(b"abc")
        );
    }

    #[test]
    fn random_persona_tool_is_deterministic_and_consistent() {
        let mut s = server();
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"random_persona","arguments":{"seed":4242}}}"#;
        let a = tool_payload(&call(&mut s, req));
        let b = tool_payload(&call(&mut s, req));
        assert_eq!(a["user_agent"], b["user_agent"], "seed must be reproducible");
        assert!(a["user_agent"].as_str().unwrap().contains("Firefox/"));
        // Platform ↔ UA must agree.
        let ua = a["user_agent"].as_str().unwrap();
        let plat = a["platform"].as_str().unwrap();
        if plat == "Win32" {
            assert!(ua.contains("Windows NT"));
        } else if plat == "MacIntel" {
            assert!(ua.contains("Mac OS X"));
        }
    }

    #[test]
    fn oast_tools_mint_record_and_correlate() {
        use std::io::Write;
        let mut s = server();

        // Mint a token + callback URL.
        let resp = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"oast_new_token","arguments":{}}}"#,
        );
        let payload = tool_payload(&resp);
        let token = payload["token"].as_str().unwrap().to_string();
        let url = payload["callback_url"].as_str().unwrap().to_string();

        // Simulate a target's blind callback to that URL.
        let authority_path = url.strip_prefix("http://").unwrap();
        let (authority, path) = authority_path.split_once('/').unwrap();
        let (authority, path) = (authority.to_string(), format!("/{path}"));
        let mut c = std::net::TcpStream::connect(&authority).unwrap();
        c.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
        use std::io::Read as _;
        let mut buf = Vec::new();
        let _ = c.read_to_end(&mut buf);

        // The interaction is recorded and correlates to the token.
        let resp2 = call(
            &mut s,
            &format!(
                r#"{{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{{"name":"oast_interactions","arguments":{{"token":"{token}"}}}}}}"#
            ),
        );
        let p2 = tool_payload(&resp2);
        assert_eq!(p2["count"].as_u64().unwrap(), 1, "payload: {p2}");
        assert_eq!(p2["interactions"][0]["token"].as_str().unwrap(), token);
    }

    #[test]
    fn tools_list_includes_core_tools() {
        let mut s = server();
        let resp = call(&mut s, r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for expected in [
            "camioql_query",
            "send_request",
            "fingerprint_status",
            "scope_decide",
        ] {
            assert!(names.contains(&expected), "missing tool {expected}");
        }
    }

    #[test]
    fn fingerprint_status_is_honest() {
        let mut s = server();
        let resp = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fingerprint_status","arguments":{}}}"#,
        );
        let payload = tool_payload(&resp);
        assert_eq!(payload["profile"], "win-firefox-158-balanced");
        // Dry-run engine must not claim a matched fingerprint.
        assert_eq!(payload["fingerprint_matched"], json!(false));
        assert!(payload["disclaimer"]
            .as_str()
            .unwrap()
            .contains("never claims invisibility"));
    }

    #[test]
    fn scope_decide_blocks_ssrf() {
        let mut s = server();
        let resp = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"scope_decide","arguments":{"url":"http://169.254.169.254/"}}}"#,
        );
        assert_eq!(tool_payload(&resp)["decision"], "blocked");
    }

    #[test]
    fn send_request_requires_confirmation_then_refuses_out_of_scope() {
        let mut s = server();
        // In-scope (public) but unconfirmed → confirmation_required, not sent.
        let resp = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"send_request","arguments":{"url":"https://example.com/"}}}"#,
        );
        assert_eq!(tool_payload(&resp)["status"], "confirmation_required");

        // Blocked destination → refused even with confirm.
        let resp = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"send_request","arguments":{"url":"http://127.0.0.1/","confirm":true}}}"#,
        );
        assert_eq!(resp["result"]["isError"], json!(true));
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("refused"));
    }

    #[test]
    fn autopilot_requires_confirmation_then_refuses_blocked() {
        let scope = camio_core::Scope::new().with_rule(
            camio_core::ScopeRule::include(r#"req.host.cont:"example.com""#).unwrap(),
        );
        // Autopilot is ACTIVE, so the server policy must permit active testing
        // (exactly like active_scan); confirmation is still required.
        let policy = camio_core::Policy {
            allow_active: true,
            allow_destructive: false,
            require_confirmation: true,
        };
        let mut s = server().with_scope(scope).with_policy(policy);
        // In scope but unconfirmed → confirmation_required, nothing sent.
        let resp = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":80,"method":"tools/call","params":{"name":"autopilot","arguments":{"url":"https://example.com/"}}}"#,
        );
        assert_eq!(tool_payload(&resp)["status"], "confirmation_required");

        // A blocked destination is refused even with confirm (SSRF guard wins).
        let resp = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":81,"method":"tools/call","params":{"name":"autopilot","arguments":{"url":"http://127.0.0.1/","confirm":true}}}"#,
        );
        assert_eq!(resp["result"]["isError"], json!(true));
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("refused"));
    }

    #[test]
    fn report_export_renders_stored_findings() {
        let mut s = server();
        {
            let store = s.store.as_mut().unwrap();
            let f = camio_core::Finding {
                id: camio_core::FindingId(0),
                title: "Reflected XSS".into(),
                severity: camio_core::Severity::High,
                confidence: camio_core::Confidence::Firm,
                detail: "d".into(),
                evidence: vec![],
                created_at_ms: 0,
                rule: Some("reflected-xss".into()),
            };
            store.insert_finding(&f).unwrap();
        }
        // SARIF export carries the stored finding.
        let resp = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"report_export","arguments":{"format":"sarif"}}}"#,
        );
        let p = tool_payload(&resp);
        assert_eq!(p["format"], "SARIF");
        assert!(p["count"].as_u64().unwrap() >= 1);
        assert!(p["report"].as_str().unwrap().contains("\"version\": \"2.1.0\""));

        // An unknown format is a clean error, not a panic.
        let resp = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":"report_export","arguments":{"format":"pdf"}}}"#,
        );
        assert_eq!(resp["result"]["isError"], json!(true));
    }

    #[test]
    fn autopilot_is_listed_as_a_tool() {
        let mut s = server();
        let resp = call(&mut s, r#"{"jsonrpc":"2.0","id":82,"method":"tools/list"}"#);
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"autopilot"));
    }

    #[test]
    fn camioql_query_runs_over_store() {
        let mut s = server();
        // Seed one exchange directly into the store.
        {
            let store = s.store.as_mut().unwrap();
            let mut req = HttpRequest::get("https://seed.test/");
            req.method = "GET".into();
            let ex = HttpExchange::new(req, Source::Browser);
            store.insert(&ex).unwrap();
        }
        let resp = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"camioql_query","arguments":{"query":"req.host.cont:\"seed\""}}}"#,
        );
        assert_eq!(tool_payload(&resp)["count"], json!(1));
    }

    #[test]
    fn an_absurd_limit_argument_is_not_honoured() {
        // Regression: `limit` was cast straight to usize and handed to
        // `Store::query`, which walks the table with no SQL LIMIT. A huge value
        // turned one MCP call into a full-table materialisation; the store now
        // caps it.
        let mut s = server();
        {
            let store = s.store.as_mut().unwrap();
            for i in 0..3 {
                let mut req = HttpRequest::get(format!("https://seed{i}.test/"));
                req.method = "GET".into();
                store
                    .insert(&HttpExchange::new(req, Source::Browser))
                    .unwrap();
            }
        }
        for tool in ["camioql_query", "history_recent"] {
            let resp = call(
                &mut s,
                &format!(
                    r#"{{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{{"name":"{tool}","arguments":{{"limit":18446744073709551615}}}}}}"#
                ),
            );
            assert_eq!(
                tool_payload(&resp)["count"],
                json!(3),
                "{tool} must answer the rows, bounded — not walk the table \
                 byte for byte"
            );
        }
    }

    #[test]
    fn unknown_method_is_json_rpc_error() {
        let mut s = server();
        let resp = call(&mut s, r#"{"jsonrpc":"2.0","id":9,"method":"no/such"}"#);
        assert_eq!(resp["error"]["code"], json!(-32601));
    }

    #[test]
    fn resources_read_fingerprint_status() {
        let mut s = server();
        let resp = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":10,"method":"resources/read","params":{"uri":"camio://fingerprint/status"}}"#,
        );
        let text = resp["result"]["contents"][0]["text"].as_str().unwrap();
        assert!(text.contains("fingerprint_target"));
    }
}
