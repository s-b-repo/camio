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

use camio_automate::{AttackType, Campaign, PayloadSet};
use camio_convert::Transform;
use camio_core::{
    ActionClass, FindingId, FingerprintProfile, HttpExchange, HttpRequest, Policy, PolicyOutcome,
    Scope, SiteMap, Source, TaskId,
};
use camio_request::{DryRunEngine, FingerprintSpec, RequestEngine};
use camio_store::{FindingStatus, ReviewTask, Store};
use serde_json::{json, Value};
use std::io::{BufRead, Write};

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "camio";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The MCP server state.
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
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        for line in stdin.lock().lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Some(response) = self.handle_line(&line) {
                writeln!(stdout, "{response}")?;
                stdout.flush()?;
            }
        }
        Ok(())
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
            "analyze_js" => self.tool_analyze_js(&args),
            "oast_new_token" => self.tool_oast_new_token(),
            "oast_interactions" => self.tool_oast_interactions(&args),
            "subfinder_enum" => self.tool_subfinder(&args),
            "findings_set_status" => self.tool_findings_set_status(&args),
            "saved_searches" => self.tool_saved_searches(),
            other => Err(format!("unknown tool: {other}")),
        };
        match result {
            Ok(v) => tool_text(&serde_json::to_string_pretty(&v).unwrap_or_default(), false),
            Err(e) => tool_text(&e, true),
        }
    }

    fn tool_camioql_query(&self, args: &Value) -> Result<Value, String> {
        let query = args.get("query").and_then(|q| q.as_str()).unwrap_or("");
        let limit = args.get("limit").and_then(|l| l.as_u64()).unwrap_or(50) as usize;
        let compiled =
            camio_core::Query::compile(query).map_err(|e| format!("invalid CamioQL: {e}"))?;
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

    fn tool_history_recent(&self, args: &Value) -> Result<Value, String> {
        let limit = args.get("limit").and_then(|l| l.as_u64()).unwrap_or(50) as usize;
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
        Ok(self.oast.as_ref().expect("oast just initialized"))
    }

    /// Mint a correlated OAST token and its callback URLs. The collector listens
    /// on loopback, so it only records callbacks the target can route to this host.
    fn tool_oast_new_token(&mut self) -> Result<Value, String> {
        let st = self.ensure_oast()?;
        let token = st.collector.new_token();
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
        let domain = args
            .get("domain")
            .and_then(|d| d.as_str())
            .ok_or("missing `domain`")?
            .to_string();
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
        let url = args
            .get("url")
            .and_then(|u| u.as_str())
            .ok_or("missing `url`")?;
        let method = args.get("method").and_then(|m| m.as_str()).unwrap_or("GET");
        let confirm = args
            .get("confirm")
            .and_then(|c| c.as_bool())
            .unwrap_or(false);

        let mut req = HttpRequest::get(url);
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
                let stored_id = match self.store.as_mut() {
                    Some(store) => store.insert(&ex).ok().map(|id| id.0),
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
        let query = args.get("query").and_then(|q| q.as_str()).unwrap_or("");
        let limit = args.get("limit").and_then(|l| l.as_u64()).unwrap_or(1000) as usize;
        let save = args.get("save").and_then(|s| s.as_bool()).unwrap_or(false);
        let compiled =
            camio_core::Query::compile(query).map_err(|e| format!("invalid CamioQL: {e}"))?;
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
        let query = args.get("query").and_then(|q| q.as_str()).unwrap_or("");
        let limit = args.get("limit").and_then(|l| l.as_u64()).unwrap_or(5000) as usize;
        let compiled =
            camio_core::Query::compile(query).map_err(|e| format!("invalid CamioQL: {e}"))?;
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
        let campaign = Campaign {
            base: req,
            attack,
            sets,
            budget,
        };
        let plan = camio_automate::plan(&campaign).map_err(|e| e.to_string())?;
        Ok(json!({
            "attack": attack.as_str(),
            "num_positions": plan.num_positions,
            "projected_requests": plan.projected_requests,
            "within_budget": plan.within_budget,
            "note": "planning only — no requests sent. Execute via send_request (policy-gated).",
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
        let save = args.get("save").and_then(|s| s.as_bool()).unwrap_or(true);
        let data = std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
        let result = camio_import::import_bytes(&data).map_err(|e| e.to_string())?;
        let mut stored = 0u64;
        if save {
            if let Some(store) = self.store.as_mut() {
                for ex in &result.exchanges {
                    if store.insert(ex).is_ok() {
                        stored += 1;
                    }
                }
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
        let confirm = args
            .get("confirm")
            .and_then(|c| c.as_bool())
            .unwrap_or(false);
        let decision = self
            .scope
            .decide(&HttpExchange::new(base.clone(), Source::Mcp));
        match self.policy.gate(ActionClass::Active, decision, confirm) {
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
            let send = |req: HttpRequest| -> Option<HttpExchange> {
                if !scope
                    .decide(&HttpExchange::new(req.clone(), Source::Mcp))
                    .is_sendable()
                {
                    return None;
                }
                engine.send(req, Source::Mcp).ok()
            };
            camio_active::run_active(&base, &send)
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
            "camio://fingerprint/status" => {
                serde_json::to_string_pretty(&self.fingerprint_status()).unwrap_or_default()
            }
            "camio://history/recent" => {
                let store = self.store.as_ref().ok_or("no store configured")?;
                let ex = store.recent(50).map_err(|e| e.to_string())?;
                let summaries: Vec<_> = ex.iter().map(exchange_summary).collect();
                serde_json::to_string_pretty(&summaries).unwrap_or_default()
            }
            "camio://findings" => {
                let store = self.store.as_ref().ok_or("no store configured")?;
                let f = store.list_findings().map_err(|e| e.to_string())?;
                serde_json::to_string_pretty(&f).unwrap_or_default()
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
            "description": "Import a Burp items XML export or a HAR archive from a local path into history. save:true (default) persists the exchanges.",
            "inputSchema": {
                "type": "object",
                "properties": { "path": { "type": "string" }, "save": { "type": "boolean" } },
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
                    "confirm": { "type": "boolean", "description": "must be true to run the active probes" }
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
            "name": "saved_searches",
            "description": "List saved CamioQL searches (name + query) stored in the workspace.",
            "inputSchema": { "type": "object", "properties": {} }
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
    fn oast_tools_mint_record_and_correlate() {
        use std::io::{Read, Write};
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
