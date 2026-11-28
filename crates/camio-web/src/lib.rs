//! `camio-web` — a local, loopback-only web UI that exposes every Camio
//! capability (plan §7 UX/IA, §13 "Rust desktop shell … local API", §16
//! "bind management/UI endpoints to loopback by default").
//!
//! It is a thin HTTP layer over the same crates the CLI and MCP server use, so
//! the UI cannot do anything the CLI cannot, and every send goes through the one
//! shared scope + policy engine (plan §16). There is no bundled JS runtime and no
//! Electron: the server ships one static HTML page (served from memory) that the
//! operator opens in their own browser. State is read fresh from the SQLite store
//! per request, so the UI always reflects the on-disk history.
//!
//! Safety: the server binds `127.0.0.1` by default; active actions (send, fuzz)
//! are refused unless the request carries `confirm:true` AND the destination is
//! in scope, exactly as on the CLI.

use anyhow::{anyhow, Result};
use camio_automate::{AttackType, Baseline, Campaign, PayloadSet};
use camio_convert::Transform;
use camio_core::{
    ActionClass, Approval, Body, Finding, FingerprintProfile, HttpExchange, HttpRequest,
    PlanSummary, Policy, PolicyOutcome, Scope, Severity, SiteMap, Source,
};
use camio_request::{matched_engine, DryRunEngine, FingerprintSpec, RequestEngine};
use camio_store::{bounded_limit, Store, ARTIFACT_BYTES};
use serde_json::{json, Value};
use std::io::Read;
use std::path::PathBuf;
use tiny_http::{Header, Method, Response, Server};

mod access;
mod workbench;

use access::LocalAccess;
type WebResponse = Response<std::io::Cursor<Vec<u8>>>;
const MAX_BODY: u64 = 8 * 1024 * 1024;

/// Everything the server needs: where to listen, the history DB, and the shared
/// profile/scope/policy it enforces.
pub struct WebConfig {
    pub addr: String,
    pub db: PathBuf,
    pub profile: FingerprintProfile,
    pub scope: Scope,
    pub policy: Policy,
}

/// Serve the UI until the process is stopped. Requests are handled sequentially
/// on one thread, so the store and request engine need no locking.
pub fn serve(cfg: WebConfig) -> Result<()> {
    let bind = access::loopback(&cfg.addr)?;
    let server = Server::http(bind).map_err(|e| anyhow!("binding {bind}: {e}"))?;
    let socket = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| anyhow!("expected a TCP address"))?;
    let access = LocalAccess::new(socket)?;
    open(&cfg).map_err(|error| anyhow!(error))?;
    let spec = FingerprintSpec::from_profile(&cfg.profile);
    // The matched engine is the only transport that preserves the browser
    // fingerprint. If it cannot be built (no backend, bad upstream proxy), fall
    // back to the honest no-network dry-run engine and say so loudly — never
    // silently swap the transport a user believes they are testing through.
    let mut engine_error: Option<String> = None;
    let engine: Box<dyn RequestEngine> = match matched_engine(&cfg.profile) {
        Ok(engine) => engine,
        Err(e) => {
            let note = format!(
                "fingerprint-matched engine unavailable ({e}); sends will not leave this machine"
            );
            eprintln!("camio: {note}");
            engine_error = Some(note.clone());
            Box::new(DryRunEngine::new(spec))
        }
    };

    println!(
        "Camio web workbench (Ctrl-C to stop)\n{}",
        access.open_url()
    );
    if let Some(note) = &engine_error {
        println!("WARNING: {note}");
    }

    // A bounded worker pool: handling connections sequentially means a single
    // slow or hostile client (a stalled body read, a huge scan) blocks every
    // other request, including the UI's status poll. Each worker pulls from the
    // shared queue, so total in-flight work is bounded and isolation is real.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(2, 16);
    let server = std::sync::Arc::new(server);
    let engine: std::sync::Arc<dyn RequestEngine> = engine.into();
    let access = std::sync::Arc::new(access);
    let cfg = std::sync::Arc::new(cfg);
    let mut handles = Vec::with_capacity(workers);
    for id in 0..workers {
        let (server, engine, access, cfg) =
            (server.clone(), engine.clone(), access.clone(), cfg.clone());
        // Thread-spawn failure is not something a retry fixes on a loaded host:
        // report how many workers came up and serve on those. A panic here used
        // to take the whole server down with the pool half-built.
        let spawned = std::thread::Builder::new()
            .name(format!("camio-web-{id}"))
            .spawn(move || loop {
                // A bounded wait so a worker can be joined on shutdown.
                match server.recv_timeout(std::time::Duration::from_secs(1)) {
                    Ok(Some(mut request)) => {
                        let method = request.method().clone();
                        let path = request.url().split('?').next().unwrap_or("").to_string();
                        let response =
                            route(&cfg, engine.as_ref(), &access, &mut request, &method, &path);
                        if let Err(e) = request.respond(access::secure_headers(response)) {
                            // The client is gone, or the socket failed
                            // mid-write: the request is answered as far as
                            // this process can tell, but a silent drop
                            // would hide a systematically broken write.
                            eprintln!("camio-web: could not send response: {e}");
                        }
                    }
                    Ok(None) => continue,
                    // A queue error means the server closed (shutdown) or the
                    // queue was dropped; either way this worker has nothing
                    // left to serve.
                    Err(e) => {
                        eprintln!("camio-web: request queue closed: {e}");
                        break;
                    }
                }
            });
        match spawned {
            Ok(handle) => handles.push(handle),
            Err(e) => eprintln!(
                "camio-web: worker {id} could not start ({e}); serving with \
                 {} worker(s) instead of {}",
                handles.len(),
                workers
            ),
        }
    }
    for handle in handles {
        // A panicked worker is a bug in the request path, not something to
        // absorb: say so instead of joining it silently.
        if let Err(panic) = handle.join() {
            camio_core::note_failure("a web worker", camio_core::describe_panic(panic));
        }
    }
    Ok(())
}

fn route(
    cfg: &WebConfig,
    engine: &dyn RequestEngine,
    access: &LocalAccess,
    request: &mut tiny_http::Request,
    method: &Method,
    path: &str,
) -> WebResponse {
    if !access.same_origin(request.headers()) {
        return error_response(403, "open the local address printed by Camio");
    }
    if method == &Method::Get {
        if let Some((mime, bytes)) = static_asset(path) {
            return match header("Content-Type", mime) {
                Some(h) => Response::from_data(bytes).with_header(h),
                // A mime from `static_asset` is always valid; if one ever were
                // not, serve the bytes untyped rather than dropping the asset.
                None => Response::from_data(bytes),
            };
        }
    }
    if !path.starts_with("/api/") {
        return error_response(404, "not found");
    }
    if !access.authorized(request.headers()) {
        return error_response(401, "open the session URL printed by Camio");
    }
    if method == &Method::Get && path == "/api/meta" {
        return json_response(&meta(cfg, engine));
    }
    // Durable background-task records (plan §4.2): read-only, so it stays a GET
    // like /api/meta. The web server runs jobs in its request loop; the durable
    // rows let the UI show runs that finished — or were interrupted by a
    // restart — rather than pretending they never happened.
    if method == &Method::Get && path == "/api/tasks" {
        return match open(cfg).and_then(|store| {
            let rows = store
                .tasks(50)
                .map_err(|e| format!("reading task records: {e}"))?;
            serde_json::to_value(rows).map_err(|e| e.to_string())
        }) {
            Ok(v) => json_response(&v),
            Err(e) => error_response(500, &e),
        };
    }
    if method != &Method::Post {
        return error_response(404, "not found");
    }

    let args = match read_json(request) {
        Ok(args) => args,
        Err((status, message)) => return error_response(status, message),
    };

    let result: Result<Value, String> = match path {
        "/api/scan" => api_scan(cfg, &args),
        "/api/attack_surface" => api_attack_surface(cfg, &args),
        "/api/report" => api_report(cfg, &args),
        "/api/sitemap" => api_sitemap(cfg, &args),
        "/api/convert" => api_convert(&args),
        "/api/jwt" => api_jwt(&args),
        "/api/sequencer" => api_sequencer(&args),
        "/api/discover" => api_discover(&args),
        "/api/workflow_validate" => api_workflow_validate(&args),
        "/api/scope" => api_scope(cfg, &args),
        "/api/payloads" => Ok(api_payloads()),
        "/api/fuzz_plan" => api_fuzz_plan(&args),
        "/api/import" => api_import(cfg, &args),
        "/api/send" => api_send(cfg, engine, &args),
        "/api/fuzz_run" => api_fuzz_run(cfg, engine, &args),
        "/api/autopilot" => api_autopilot(cfg, engine, &args),
        "/api/combo" => api_combo(&args),
        "/api/encode" => api_encode(&args),
        "/api/faviconhash" => api_faviconhash(&args),
        "/api/useragent" => api_useragent(&args),
        "/api/captcha" => api_captcha(&args),
        "/api/pow" => api_pow(&args),
        "/api/diff" => api_diff(cfg, &args),
        "/api/sbom" => api_sbom(&args),
        "/api/audit" => api_audit(cfg, &args),
        "/api/collection" => api_collection(cfg, &args),
        "/api/baseline" => api_baseline(cfg, &args),
        "/api/label" => api_label(cfg, &args),
        "/api/retest" => api_retest(cfg, engine, &args),
        "/api/dast" => api_dast(cfg, engine, &args),
        "/api/activescan" => api_activescan(cfg, engine, &args),
        "/api/crawl" => api_crawl(cfg, engine, &args),
        "/api/encode_chain" => api_encode_chain(&args),
        "/api/attack_chains" => api_attack_chains(cfg, &args),
        other => match workbench::dispatch(cfg, other, &args) {
            Some(result) => result,
            None => return error_response(404, "unknown endpoint"),
        },
    };

    match result {
        Ok(v) => json_response(&v),
        Err(e) => {
            // Log the detail server-side; the client gets a stable class of
            // error rather than the database path or raw SQL diagnostics.
            eprintln!("api error on {path}: {e}");
            error_response(400, sanitized_error(&e))
        }
    }
}

/// Strip local filesystem paths and raw store diagnostics from an error before
/// it leaves the process. The bearer token lives in the URL fragment, terminal
/// scrollback and pasted links, so a leaked path is reconnaissance.
fn sanitized_error(message: &str) -> String {
    let mut out = message.to_string();
    // Absolute paths (POSIX and home-relative) → a placeholder.
    let mut cleaned = String::with_capacity(out.len());
    for token in out.split_whitespace() {
        if token.starts_with('/') || token.starts_with("~/") {
            cleaned.push_str("<path> ");
        } else {
            cleaned.push_str(token);
            cleaned.push(' ');
        }
    }
    out = cleaned.trim().to_string();
    // rusqlite/anyhow diagnostics carry SQL text.
    for needle in ["SQLite", "rusqlite", "no such column", "syntax error"] {
        if out.contains(needle) {
            return "internal error (see the Camio log)".to_string();
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Handlers (mirror the CLI/MCP surface)
// ---------------------------------------------------------------------------

fn meta(cfg: &WebConfig, engine: &dyn RequestEngine) -> Value {
    json!({
        "profile": cfg.profile.name,
        "camoufox_build": cfg.profile.camoufox_build,
        "user_agent": cfg.profile.persona.user_agent,
        "engine": engine.label(),
        "fingerprint_matched": engine.is_fingerprint_matched(),
        "fingerprint_target": engine.spec().target_label(),
        "parity_note": engine.parity_note(),
        "payload_packs": camio_automate::builtin_packs(),
        "transforms": Transform::all().iter().map(|t| t.name()).collect::<Vec<_>>(),
        "db": cfg.db.display().to_string(),
        "disclaimer": "Parity is measured, not asserted. Camio never claims invisibility.",
    })
}

fn open(cfg: &WebConfig) -> Result<Store, String> {
    Store::open(&cfg.db).map_err(|e| format!("opening {}: {e}", cfg.db.display()))
}

fn api_scan(cfg: &WebConfig, args: &Value) -> Result<Value, String> {
    let q = args.get("query").and_then(|q| q.as_str()).unwrap_or("");
    let limit = bounded_limit(args.get("limit").and_then(|l| l.as_u64()), 1000).min(1000);
    let save = args.get("save").and_then(|s| s.as_bool()).unwrap_or(false);
    let compiled = workbench::compile(q).map_err(|e| format!("{e:#}"))?;
    let mut store = open(cfg)?;
    // Bounded by a cumulative body-byte budget as well as a row count: loading
    // 1000 exchanges' real bodies inside one single-threaded request can be
    // gigabytes, and oversized bodies are skipped (and reported) instead.
    const SCAN_BODY_BUDGET: usize = 64 * 1024 * 1024;
    let (rows, skipped_oversize) = store
        .query_for_scan(&compiled, limit.min(1000), SCAN_BODY_BUDGET)
        .map_err(|e| e.to_string())?;
    let report = camio_scan::scan_all(&rows);
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
        "skipped_oversize": skipped_oversize,
        "saved": saved,
        "findings": serde_json::to_value(&report.findings).unwrap_or(json!([])),
    }))
}

fn api_attack_surface(cfg: &WebConfig, args: &Value) -> Result<Value, String> {
    let q = args.get("query").and_then(|q| q.as_str()).unwrap_or("");
    let compiled = workbench::compile(q).map_err(|e| format!("{e:#}"))?;
    let store = open(cfg)?;
    let exchanges = store
        .query_with_bodies(&compiled, 1)
        .map_err(|e| e.to_string())?;
    let ex = exchanges
        .into_iter()
        .next()
        .ok_or("no stored exchange matched — capture traffic first, or widen the query")?;
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
    }))
}

fn api_report(cfg: &WebConfig, args: &Value) -> Result<Value, String> {
    let state = match args.get("status").and_then(Value::as_str) {
        None | Some("") | Some("all") => None,
        Some("open") => Some(camio_store::ReviewState::Open),
        Some("confirmed") => Some(camio_store::ReviewState::Confirmed),
        Some("resolved") => Some(camio_store::ReviewState::Resolved),
        Some("dismissed") => Some(camio_store::ReviewState::Dismissed),
        Some(other) => return Err(format!("unknown status `{other}`")),
    };
    let format = match args.get("format").and_then(Value::as_str).unwrap_or("markdown") {
        "markdown" | "md" => camio_store::ReportFormat::Markdown,
        "json" => camio_store::ReportFormat::Json,
        "html" => camio_store::ReportFormat::Html,
        "sarif" => camio_store::ReportFormat::Sarif,
        other => return Err(format!("unknown format `{other}`")),
    };
    let store = open(cfg)?;
    let report = store.finding_report(state).map_err(|e| e.to_string())?;
    let rendered = report.render(format).map_err(|e| e.to_string())?;
    Ok(json!({
        "format": format.label(),
        "count": report.findings.len(),
        "report": rendered,
    }))
}

fn api_sitemap(cfg: &WebConfig, args: &Value) -> Result<Value, String> {
    let q = args.get("query").and_then(|q| q.as_str()).unwrap_or("");
    // A bound on rows (the site map only needs URL metadata) — an unbounded
    // user limit would let one request walk the whole store.
    let limit = bounded_limit(args.get("limit").and_then(|l| l.as_u64()), 5000);
    let compiled = workbench::compile(q).map_err(|e| format!("{e:#}"))?;
    let store = open(cfg)?;
    let rows = store
        .query_metadata(&compiled, limit)
        .map_err(|e| e.to_string())?;
    let map = SiteMap::build(&rows);
    Ok(
        json!({ "origin_count": map.origin_count(), "url_count": map.url_count(), "tree": map.render_tree() }),
    )
}

fn api_convert(args: &Value) -> Result<Value, String> {
    let input = args
        .get("input")
        .and_then(|i| i.as_str())
        .ok_or("missing `input`")?;
    let steps = parse_transforms(args.get("steps"))?;
    if steps.is_empty() {
        return Err("no transforms given".into());
    }
    if steps.len() > 16 {
        return Err("use at most 16 transforms per pipeline".into());
    }
    let out = camio_convert::apply_pipeline_limited(input.as_bytes(), &steps, 2 * 1024 * 1024)
        .map_err(|e| e.to_string())?;
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

fn api_jwt(args: &Value) -> Result<Value, String> {
    let token = args
        .get("token")
        .and_then(|t| t.as_str())
        .ok_or("missing `token`")?;
    let parts = camio_convert::decode_jwt(token).map_err(|e| e.to_string())?;
    Ok(json!({
        "header": parts.header_json,
        "payload": parts.payload_json,
        "signature_b64url": parts.signature_b64url,
        "note": "signature NOT verified",
    }))
}

fn api_sequencer(args: &Value) -> Result<Value, String> {
    let tokens: Vec<String> = if let Some(arr) = args.get("tokens").and_then(|t| t.as_array()) {
        // A non-string entry must be an error: silently dropping it would make
        // the entropy estimate quietly disagree with the operator's input.
        arr.iter()
            .enumerate()
            .map(|(i, t)| {
                t.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("token #{i} must be a string"))
            })
            .collect::<Result<Vec<_>, _>>()?
    } else if let Some(text) = args.get("text").and_then(|t| t.as_str()) {
        text.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        return Err("provide `tokens` (array) or `text` (newline-separated)".into());
    };
    serde_json::to_value(camio_sequencer::analyze(&tokens)).map_err(|e| e.to_string())
}

fn api_discover(args: &Value) -> Result<Value, String> {
    let req = request_from_args(args)?;
    let inputs = camio_automate::discover_inputs(&req);
    Ok(
        json!({ "count": inputs.len(), "inputs": serde_json::to_value(&inputs).unwrap_or(json!([])) }),
    )
}

/// Validate a typed workflow document (F12) for the web visual builder. Accepts
/// the document under `doc` (a JSON object or a JSON string) or as the request
/// body itself, and runs the real `camio-automate` validator — so the builder
/// shows exactly the errors the CLI executor would reject. Validation only; this
/// never executes a workflow (execution stays in the gated CLI path).
fn api_workflow_validate(args: &Value) -> Result<Value, String> {
    let doc: camio_automate::WorkflowDoc = match args.get("doc") {
        Some(Value::String(s)) => {
            serde_json::from_str(s).map_err(|e| format!("invalid workflow JSON: {e}"))?
        }
        Some(other) => serde_json::from_value(other.clone())
            .map_err(|e| format!("invalid workflow document: {e}"))?,
        None => serde_json::from_value(args.clone())
            .map_err(|e| format!("invalid workflow document: {e}"))?,
    };
    let steps: Vec<Value> = doc
        .steps
        .iter()
        .map(|s| json!({ "id": s.id, "action": s.action.kind() }))
        .collect();
    Ok(match doc.validate() {
        Ok(()) => json!({ "valid": true, "name": doc.name, "steps": steps, "errors": [] }),
        Err(errs) => json!({ "valid": false, "name": doc.name, "steps": steps, "errors": errs }),
    })
}

fn api_scope(cfg: &WebConfig, args: &Value) -> Result<Value, String> {
    let url = args
        .get("url")
        .and_then(|u| u.as_str())
        .ok_or("missing `url`")?;
    let ex = HttpExchange::new(HttpRequest::get(url), Source::Replay);
    Ok(json!({ "url": url, "decision": cfg.scope.decide(&ex).as_str() }))
}

fn api_payloads() -> Value {
    let packs: Vec<Value> = camio_automate::builtin_packs()
        .iter()
        .map(|name| {
            let set = camio_automate::builtin_pack(name);
            json!({
                "name": name,
                "size": set.as_ref().map(|s| s.len()).unwrap_or(0),
                "sample": set.map(|s| s.payloads.iter().take(5).cloned().collect::<Vec<_>>()).unwrap_or_default(),
            })
        })
        .collect();
    json!({ "packs": packs })
}

fn api_fuzz_plan(args: &Value) -> Result<Value, String> {
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
        "positions": plan.positions.iter().map(|p| json!({ "index": p.index, "baseline": p.baseline })).collect::<Vec<_>>(),
    }))
}

fn api_import(cfg: &WebConfig, args: &Value) -> Result<Value, String> {
    let save = args.get("save").and_then(|s| s.as_bool()).unwrap_or(true);
    let content = args
        .get("content")
        .and_then(Value::as_str)
        .ok_or("select a file or paste its contents")?;
    if content.len() > ARTIFACT_BYTES {
        return Err("traffic archives support up to 4 MiB in the web workbench".into());
    }
    let base = args.get("base").and_then(Value::as_str).filter(|s| !s.is_empty());
    let result = match args.get("format").and_then(Value::as_str).unwrap_or("auto") {
        "openapi" => camio_import::import_openapi(content, base).map_err(|e| e.to_string())?,
        "graphql" => {
            let endpoint = base.ok_or("GraphQL import needs the endpoint URL (fill in Base/endpoint)")?;
            camio_import::import_graphql(content, endpoint).map_err(|e| e.to_string())?
        }
        _ => camio_import::import_bytes(content.as_bytes()).map_err(|e| e.to_string())?,
    };
    let stored = if save {
        open(cfg)?
            .insert_exchanges(&result.exchanges)
            .map_err(|e| e.to_string())?
    } else {
        0
    };
    Ok(
        json!({ "format": result.format, "imported": result.exchanges.len(), "stored": stored, "warnings": result.warnings }),
    )
}

fn api_send(cfg: &WebConfig, engine: &dyn RequestEngine, args: &Value) -> Result<Value, String> {
    let req = request_from_args(args)?;
    let confirm = args
        .get("confirm")
        .and_then(|c| c.as_bool())
        .unwrap_or(false);
    let decision = cfg
        .scope
        .decide(&HttpExchange::new(req.clone(), Source::Replay));
    match cfg.policy.gate(ActionClass::Mutating, decision, confirm) {
        PolicyOutcome::Deny(reason) => Err(format!("refused: {reason}")),
        PolicyOutcome::NeedsConfirmation(reason) => Ok(json!({
            "status": "confirmation_required",
            "reason": reason,
            "preview": { "method": req.method, "url": req.url, "scope": decision.as_str(),
                         "engine": engine.label(), "fingerprint_matched": engine.is_fingerprint_matched() },
        })),
        PolicyOutcome::Allow => {
            let mut ex = engine
                .send(req, Source::Replay)
                .map_err(|e| format!("send failed: {e}"))?;
            let mut store = open(cfg)?;
            let mut id = store
                .insert(&ex)
                .map(|i| i.0)
                .map_err(|e| format!("storing the exchange: {e}"))?;

            // Follow redirects (F09), re-deciding scope on every hop.
            let follow = args.get("follow_redirects").and_then(Value::as_bool).unwrap_or(false);
            let max_redirects = args.get("max_redirects").and_then(Value::as_u64).unwrap_or(5).min(20);
            let mut hops = 0u64;
            if follow {
                while hops < max_redirects {
                    let Some(resp) = ex.response.as_ref() else { break };
                    if !(300..=399).contains(&resp.status) {
                        break;
                    }
                    let Some(location) = resp.headers.get("Location") else { break };
                    let status = resp.status;
                    let Some(next_url) = camio_core::resolve_redirect(&ex.request.url, location)
                    else {
                        break;
                    };
                    let mut next = HttpRequest::get(&next_url);
                    if status == 307 || status == 308 {
                        next.method = ex.request.method.clone();
                        next.body = ex.request.body.clone();
                    }
                    if !cfg
                        .scope
                        .decide(&HttpExchange::new(next.clone(), Source::Replay))
                        .is_sendable()
                    {
                        break;
                    }
                    hops += 1;
                    ex = engine
                        .send(next, Source::Replay)
                        .map_err(|e| format!("redirect send failed: {e}"))?;
                    id = store
                        .insert(&ex)
                        .map(|i| i.0)
                        .map_err(|e| format!("storing redirect exchange: {e}"))?;
                }
            }
            let mut s = summary(&ex);
            s["redirects_followed"] = json!(hops);
            s["stored_id"] = json!(id);
            s["engine"] = json!(engine.label());
            s["fingerprint_matched"] = json!(engine.is_fingerprint_matched());
            if !engine.is_fingerprint_matched() {
                s["transport_warning"] = json!(format!(
                    "sends used {}: no traffic left this machine",
                    engine.label()
                ));
            }
            s["response_headers"] = ex
                .response
                .as_ref()
                .map(|r| {
                    r.headers
                        .iter()
                        .map(|h| json!([h.name, h.value]))
                        .collect::<Vec<_>>()
                })
                .map(Value::from)
                .unwrap_or(json!([]));
            s["response_body"] = ex
                .response
                .as_ref()
                .map(|r| Value::from(r.body.as_text().chars().take(20000).collect::<String>()))
                .unwrap_or(json!(""));
            Ok(s)
        }
    }
}

/// Build the approval-bearing plan summary for a campaign (plan §4.3).
///
/// Covers the same facts as the CLI: target set, action class, request budget,
/// and policy revision. Any drift changes the hash, so a stale approval is
/// refused instead of silently reused.
fn fuzz_plan_summary(url: &str, budget: u64, policy: &Policy) -> PlanSummary {
    PlanSummary::new(ActionClass::Active, vec![url.trim().to_string()])
        .with_max_requests(budget)
        .with_policy(policy)
}

/// Verify an approval hash against the current plan (fails closed).
fn verify_approval(approved: &str, summary: &PlanSummary) -> Result<(), String> {
    let approval =
        Approval::bind(summary.clone(), camio_core::approval::now_ms()).granted_by("camio web");
    if approved.trim() != approval.plan_hash {
        return Err(format!(
            "this approval does not cover the current plan (approved {approved}, plan is {})",
            approval.plan_hash
        ));
    }
    approval
        .allows(summary, camio_core::approval::now_ms())
        .map_err(|reason| format!("approval does not cover this plan: {reason}"))
}

fn api_fuzz_run(
    cfg: &WebConfig,
    engine: &dyn RequestEngine,
    args: &Value,
) -> Result<Value, String> {
    let base = request_from_args(args)?;
    let attack = parse_attack(
        args.get("attack")
            .and_then(|a| a.as_str())
            .unwrap_or("sniper"),
    )?;
    let sets = resolve_payload_sets(args.get("payloads"))?;
    let budget = args.get("budget").and_then(|b| b.as_u64()).unwrap_or(200);
    let confirm = args
        .get("confirm")
        .and_then(|c| c.as_bool())
        .unwrap_or(false);
    let campaign = Campaign {
        base: base.clone(),
        attack,
        sets,
        budget: Some(budget),
    };
    let plan = camio_automate::plan(&campaign).map_err(|e| e.to_string())?;

    let clean = strip_to_clean(&base);
    let decision = cfg
        .scope
        .decide(&HttpExchange::new(clean.clone(), Source::Automate));

    // The plan hash an operator must approve (plan §4.3), identical in meaning
    // to the CLI's preview hash.
    let summary = fuzz_plan_summary(&base.url, budget, &cfg.policy);
    let plan_hash = summary.plan_hash();

    match cfg
        .policy
        .gate_action_with(ActionClass::Active, &cfg.scope, decision, confirm)
    {
        PolicyOutcome::Deny(reason) => return Err(format!("refused: {reason}")),
        PolicyOutcome::NeedsConfirmation(reason) => {
            return Ok(json!({
                "status": "confirmation_required",
                "reason": reason,
                "plan_hash": plan_hash,
                "plan": { "attack": attack.as_str(), "num_positions": plan.num_positions,
                          "projected_requests": plan.projected_requests, "within_budget": plan.within_budget,
                          "scope": decision.as_str() },
                "note": "re-call with confirm:true and approval:<plan_hash>",
            }));
        }
        PolicyOutcome::Allow => {}
    }
    if !plan.within_budget {
        return Err(format!(
            "projected {} exceeds budget {budget}; raise the budget",
            plan.projected_requests
        ));
    }

    // Approval binding (plan §4.3): the operator must approve the printed plan
    // hash; any drift is refused rather than executed under a stale approval.
    match args.get("approval").and_then(Value::as_str) {
        Some(approved) => verify_approval(approved, &summary)?,
        None => {
            return Ok(json!({
                "status": "approval_required",
                "plan_hash": plan_hash,
                "plan": {
                    "attack": attack.as_str(),
                    "num_positions": plan.num_positions,
                    "projected_requests": plan.projected_requests,
                    "within_budget": plan.within_budget,
                    "scope": decision.as_str(),
                },
                "note": "re-call with approval:<plan_hash> to bind this run to the approved plan",
            }));
        }
    }

    let generated = camio_automate::generate(&campaign).map_err(|e| e.to_string())?;
    // A failed baseline send is reported, not silently dropped: classification
    // without a baseline answers a different question than the operator asked.
    let baseline_error = match engine.send(clean, Source::Automate) {
        Ok(ex) => ex.response.as_ref().map(|r| Baseline {
            status: r.status,
            body_len: r.body.len(),
        }),
        Err(e) => {
            return Err(format!("baseline request failed: {e}"));
        }
    };
    let mut store = open(cfg)?;
    let mut results = Vec::new();
    let mut sent = 0u64;
    let mut failed = 0u64;
    let mut out_of_scope = 0u64;
    let mut unsaved = 0u64;
    for g in &generated {
        if !cfg
            .scope
            .decide(&HttpExchange::new(g.request.clone(), Source::Automate))
            .is_sendable()
        {
            // A payload that injects an out-of-scope host never leaves the box.
            out_of_scope += 1;
            continue;
        }
        match engine.send(g.request.clone(), Source::Automate) {
            Ok(ex) => {
                sent += 1;
                if store.insert(&ex).is_err() {
                    unsaved += 1;
                }
                results.push((g.payloads.clone(), ex));
            }
            Err(e) => {
                failed += 1;
                eprintln!("campaign send failed: {e}");
            }
        }
    }
    let classified = camio_automate::classify(&results, baseline_error.as_ref(), None);
    Ok(json!({
        "status": "done",
        "sent": sent,
        "failed": failed,
        "out_of_scope": out_of_scope,
        "unsaved": unsaved,
        "results": serde_json::to_value(&classified).unwrap_or(json!([])),
    }))
}

/// One-shot automated recon + active sweep (same flow as `camio autopilot`):
/// baseline → attack surface → active checks (incl. HTTP method audit) →
/// optional bounded payload-DB fuzz → responses bucketed by status. Gated
/// ACTIVE and confirmation-required; every probe is re-checked against scope.
fn api_autopilot(cfg: &WebConfig, engine: &dyn RequestEngine, args: &Value) -> Result<Value, String> {
    let base = request_from_args(args)?;
    let confirm = args
        .get("confirm")
        .and_then(|c| c.as_bool())
        .unwrap_or(false);
    let do_fuzz = args.get("fuzz").and_then(Value::as_bool).unwrap_or(false);
    let fuzz_budget = args
        .get("fuzz_budget")
        .and_then(Value::as_u64)
        .unwrap_or(200)
        .min(2000) as usize;

    let decision = cfg
        .scope
        .decide(&HttpExchange::new(base.clone(), Source::Scanner));
    match cfg
        .policy
        .gate_action_with(ActionClass::Active, &cfg.scope, decision, confirm)
    {
        PolicyOutcome::Deny(reason) => return Err(format!("refused: {reason}")),
        PolicyOutcome::NeedsConfirmation(reason) => {
            return Ok(json!({
                "status": "confirmation_required",
                "reason": reason,
                "scope": decision.as_str(),
                "note": "re-call autopilot with confirm:true to run the sweep",
            }));
        }
        PolicyOutcome::Allow => {}
    }

    let store = std::cell::RefCell::new(open(cfg)?);
    let statuses = std::cell::RefCell::new(Vec::<Option<u16>>::new());
    let send = |req: HttpRequest| -> Option<HttpExchange> {
        if !cfg
            .scope
            .decide(&HttpExchange::new(req.clone(), Source::Scanner))
            .is_sendable()
        {
            return None;
        }
        match engine.send(req, Source::Scanner) {
            Ok(mut ex) => {
                statuses
                    .borrow_mut()
                    .push(ex.response.as_ref().map(|r| r.status));
                // Adopt the stored row id so findings link to real evidence.
                if let Ok(id) = store.borrow_mut().insert(&ex) {
                    ex.id = id;
                }
                Some(ex)
            }
            Err(e) => {
                eprintln!("autopilot probe failed: {e}");
                None
            }
        }
    };

    let baseline_ex = send(base.clone());
    let surface = baseline_ex.as_ref().map(camio_scan::analyze_attack_surface);
    let findings = camio_active::run_active(&base, &send);

    let fuzz = if do_fuzz {
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
            Some(camio_active::run_auto_fuzz(
                &base,
                &cats,
                fuzz_budget,
                baseline.as_ref(),
                None,
                &send,
            ))
        }
    } else {
        None
    };

    let summary = camio_automate::StatusSummary::from_statuses(statuses.borrow().iter().copied());
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
        })
    });
    Ok(json!({
        "status": "done",
        "scope": decision.as_str(),
        "attack_surface": surface_json,
        "finding_count": findings.len(),
        "findings": serde_json::to_value(&findings).unwrap_or(json!([])),
        "status_summary": serde_json::to_value(&summary).unwrap_or(json!({})),
        "fuzz": serde_json::to_value(&fuzz).unwrap_or(json!(null)),
    }))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn request_from_args(args: &Value) -> Result<HttpRequest, String> {
    let url = args
        .get("url")
        .and_then(|u| u.as_str())
        .ok_or("missing `url`")?;
    let mut req = HttpRequest::get(url);
    if let Some(m) = args.get("method").and_then(|m| m.as_str()) {
        req.method = m.to_string();
    }
    match args.get("headers") {
        Some(Value::Object(map)) => {
            for (k, v) in map {
                if let Some(s) = v.as_str() {
                    req.headers.push(k.clone(), s.to_string());
                }
            }
        }
        Some(Value::String(raw)) => {
            for line in raw.lines() {
                if let Some((n, v)) = line.split_once(':') {
                    req.headers.push(n.trim().to_string(), v.trim().to_string());
                }
            }
        }
        _ => {}
    }
    if let Some(body) = args.get("body").and_then(|b| b.as_str()) {
        if !body.is_empty() {
            req.body = Body::from_text(body);
        }
    }
    Ok(req)
}

fn parse_transforms(v: Option<&Value>) -> Result<Vec<Transform>, String> {
    let mut steps = Vec::new();
    match v {
        Some(Value::Array(items)) => {
            for it in items {
                let name = it.as_str().ok_or("each step must be a name")?;
                steps.push(Transform::from_name(name).ok_or(format!("unknown transform: {name}"))?);
            }
        }
        Some(Value::String(s)) => {
            for name in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
                steps.push(Transform::from_name(name).ok_or(format!("unknown transform: {name}"))?);
            }
        }
        _ => return Err("`steps` must be an array or comma string".into()),
    }
    Ok(steps)
}

fn parse_attack(s: &str) -> Result<AttackType, String> {
    Ok(match s.to_ascii_lowercase().replace('-', "_").as_str() {
        "sniper" => AttackType::Sniper,
        "battering_ram" => AttackType::BatteringRam,
        "pitchfork" => AttackType::Pitchfork,
        "cluster_bomb" => AttackType::ClusterBomb,
        other => return Err(format!("unknown attack type: {other}")),
    })
}

fn resolve_payload_sets(v: Option<&Value>) -> Result<Vec<PayloadSet>, String> {
    let arr = v
        .and_then(|x| x.as_array())
        .ok_or("missing `payloads` (pack names)")?;
    let mut sets = Vec::new();
    for item in arr {
        let name = item.as_str().ok_or("each payload entry must be a name")?;
        sets.push(
            camio_automate::builtin_pack(name).ok_or(format!("unknown payload pack `{name}`"))?,
        );
    }
    if sets.is_empty() {
        return Err("provide at least one payload pack".into());
    }
    Ok(sets)
}

fn strip_to_clean(req: &HttpRequest) -> HttpRequest {
    let m = camio_automate::DEFAULT_MARKER;
    let mut out = req.clone();
    out.url = camio_automate::strip_markers(&req.url, m);
    let mut headers = camio_core::HeaderList::new();
    for h in req.headers.iter() {
        headers.push(h.name.clone(), camio_automate::strip_markers(&h.value, m));
    }
    out.headers = headers;
    // a non-UTF-8 body is skipped on purpose: it is not editable as text.
    // audit-allow: B4
    if let Ok(t) = std::str::from_utf8(req.body.as_bytes()) {
        out.body = Body::from_text(camio_automate::strip_markers(t, m));
    }
    out
}

fn summary(ex: &HttpExchange) -> Value {
    json!({
        "id": ex.id.0,
        "method": ex.request.method,
        "url": ex.request.url,
        "host": ex.request.host(),
        "status": ex.response.as_ref().map(|r| r.status),
        "resp_len": ex.response.as_ref().map(|r| r.body.len()),
        "source": ex.source.as_str(),
        "fingerprint": ex.fingerprint_used,
        "roundtrip_ms": ex.timings.map(|t| t.roundtrip_ms),
    })
}

fn read_json(request: &mut tiny_http::Request) -> Result<Value, (u16, String)> {
    let content_type = access::single_header(request.headers(), "Content-Type")
        .ok()
        .flatten();
    if !content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err((415, "expected application/json".to_string()));
    }
    let length = request.body_length();
    if length.is_some_and(|size| size as u64 > MAX_BODY) {
        return Err((413, "request exceeds 8 MiB".to_string()));
    }
    let mut bytes = Vec::new();
    request
        .as_reader()
        .take(MAX_BODY + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| {
            // `String`, not `&'static str`: the read failure reaches the
            // client instead of being flattened to a generic message.
            (400, format!("could not read request body: {e}"))
        })?;
    if bytes.len() as u64 > MAX_BODY {
        return Err((413, "request exceeds 8 MiB".to_string()));
    }
    if length.is_some_and(|size| size != bytes.len()) {
        return Err((400, "incomplete request body".to_string()));
    }
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(args) if args.is_object() => Ok(args),
        _ => Err((400, "expected a JSON object".to_string())),
    }
}

/// `application/json` — a constant, valid by construction, so the header is
/// built once instead of re-validated per response. `Header` is not `Clone`,
/// so the bytes are re-parsed for each response: cheap, and there is no panic
/// path at all.
fn json_header() -> Option<Header> {
    header("Content-Type", "application/json; charset=utf-8")
}

fn json_response(v: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string());
    json_headers(Response::from_string(body))
}

/// Attach the JSON content type to a response. Returns the response unchanged
/// if the constant header cannot be built, which cannot happen for this pair —
/// the point is that "cannot happen" never becomes a panic on a request path.
fn json_headers(
    response: Response<std::io::Cursor<Vec<u8>>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    match json_header() {
        Some(h) => response.with_header(h),
        None => response,
    }
}

fn error_response(code: u16, msg: impl std::fmt::Display) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = json!({ "error": msg.to_string() }).to_string();
    json_headers(Response::from_string(body).with_status_code(code))
}

/// Build a response header, or `None` if the name/value is not a valid header
/// (callers then serve without it rather than with a wrong-shaped substitute).
/// Every call site here passes a `Content-Type` from the closed set in
/// [`static_asset`], so `None` is unreachable in practice; returning it keeps
/// the helper correct if it is ever reused for another header.
fn header(name: &str, value: &str) -> Option<Header> {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).ok()
}

fn static_asset(path: &str) -> Option<(&'static str, &'static [u8])> {
    Some(match path {
        "/" | "/index.html" => ("text/html; charset=utf-8", include_bytes!("ui.html")),
        "/ui.css" => ("text/css; charset=utf-8", include_bytes!("ui.css")),
        "/ui.js" => ("text/javascript; charset=utf-8", include_bytes!("ui.js")),
        "/favicon.svg" => ("image/svg+xml", include_bytes!("favicon.svg")),
        "/fonts/chakrapetch-600.woff2" => {
            ("font/woff2", include_bytes!("fonts/chakrapetch-600.woff2"))
        }
        "/fonts/chakrapetch-700.woff2" => {
            ("font/woff2", include_bytes!("fonts/chakrapetch-700.woff2"))
        }
        "/fonts/ibmplexsans-var.woff2" => {
            ("font/woff2", include_bytes!("fonts/ibmplexsans-var.woff2"))
        }
        "/fonts/jetbrainsmono-var.woff2" => (
            "font/woff2",
            include_bytes!("fonts/jetbrainsmono-var.woff2"),
        ),
        "/fonts/ChakraPetch-OFL.txt" => (
            "text/plain; charset=utf-8",
            include_bytes!("fonts/ChakraPetch-OFL.txt"),
        ),
        "/fonts/IBMPlexSans-OFL.txt" => (
            "text/plain; charset=utf-8",
            include_bytes!("fonts/IBMPlexSans-OFL.txt"),
        ),
        "/fonts/JetBrainsMono-OFL.txt" => (
            "text/plain; charset=utf-8",
            include_bytes!("fonts/JetBrainsMono-OFL.txt"),
        ),
        _ => return None,
    })
}

// ===========================================================================
// CLI-parity panels (plan §F02/F04/F09/F10/F11/F13/F14/F18/F25/F26): every
// safe CLI capability reachable from the web crate, surfaced as an endpoint.
// ===========================================================================

// --- small shared helpers for the active handlers ---
fn parse_severity_opt(s: Option<&str>) -> Option<Severity> {
    match s?.to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

fn severity_breakdown_json(findings: &[Finding]) -> Value {
    let mut out = Vec::new();
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let n = findings.iter().filter(|f| f.severity == sev).count();
        if n > 0 {
            out.push(json!({ "severity": sev.as_str(), "count": n }));
        }
    }
    json!(out)
}

fn csv_list(v: Option<&str>) -> Vec<String> {
    v.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

// --- F11 combo: combine payload-DB categories ---
fn api_combo(args: &Value) -> Result<Value, String> {
    let categories = args.get("categories").and_then(|v| v.as_str()).unwrap_or("");
    let names: Vec<&str> = categories
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if names.len() < 2 {
        return Err("combo needs at least two categories (e.g. `xss,sqli`)".into());
    }
    let mode = match args
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("parallel")
        .to_ascii_lowercase()
        .replace('-', "_")
        .as_str()
    {
        "parallel" => camio_automate::ComboMode::Parallel,
        "chain" => camio_automate::ComboMode::Chain,
        "cross_product" | "crossproduct" => camio_automate::ComboMode::CrossProduct,
        other => return Err(format!("unknown mode `{other}` (parallel|chain|cross-product)")),
    };
    let join = args.get("join").and_then(|v| v.as_str()).unwrap_or(";");
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(50)
        .min(5000) as usize;
    let db = camio_automate::load_payload_db();
    let mut sets = Vec::with_capacity(names.len());
    for n in &names {
        let set = if let Some(rest) = n.strip_prefix("db:") {
            db.categories.get(rest).cloned()
        } else if let Some(s) = db.categories.get(*n).cloned() {
            Some(s)
        } else {
            camio_automate::builtin_pack(n)
        }
        .ok_or_else(|| format!("unknown category `{n}` (see Payloads)"))?;
        sets.push(set);
    }
    let out = camio_automate::combo(&sets, mode, join, limit)
        .ok_or("combo generation yielded no payloads")?;
    let total = out.payloads.len();
    let payloads: Vec<&str> = out.payloads.iter().take(500).map(String::as_str).collect();
    Ok(json!({
        "name": out.name.clone(),
        "count": total,
        "truncated": total > payloads.len(),
        "payloads": payloads,
    }))
}

// --- F11 encode: expand payloads through an encoding list ---
fn api_encode(args: &Value) -> Result<Value, String> {
    let payloads = args.get("payloads").and_then(|v| v.as_str()).unwrap_or("");
    let set = camio_automate::PayloadSet::from_lines("web", payloads);
    if set.payloads.is_empty() {
        return Err("provide one or more payloads (one per line)".into());
    }
    let enc_spec = args.get("encodings").and_then(|v| v.as_str()).unwrap_or("");
    let mut encs: Vec<camio_automate::Encoding> = Vec::new();
    for name in enc_spec.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let enc = camio_automate::Encoding::from_name(name)
            .ok_or_else(|| format!("unknown encoding `{name}`"))?;
        encs.push(enc);
    }
    if encs.is_empty() {
        return Err("provide one or more encodings (e.g. `raw,url,url-double,html,b64`)".into());
    }
    let expanded = camio_automate::expand_with_encodings(&set, &encs);
    let total = expanded.len();
    let encoded: Vec<Value> = expanded
        .iter()
        .take(500)
        .map(|e| json!({ "encoding": e.encoding.name(), "body": e.body }))
        .collect();
    Ok(json!({ "count": total, "truncated": total > encoded.len(), "encoded": encoded }))
}

// --- favicon hash (Shodan pivot) ---
fn api_faviconhash(args: &Value) -> Result<Value, String> {
    let b64 = args.get("b64").and_then(|v| v.as_str()).unwrap_or("");
    if b64.trim().is_empty() {
        return Err("paste a base64-encoded favicon".into());
    }
    let hash = camio_convert::favicon_hash_base64(b64).map_err(|e| e.to_string())?;
    Ok(json!({ "hash": hash, "shodan_query": format!("http.favicon.hash:{hash}") }))
}

// --- random User-Agents ---
fn api_useragent(args: &Value) -> Result<Value, String> {
    let count = args.get("count").and_then(|v| v.as_u64()).unwrap_or(5).clamp(1, 50);
    let seed = args.get("seed").and_then(|v| v.as_u64());
    let mut user_agents: Vec<String> = Vec::with_capacity(count as usize);
    match seed {
        Some(base) => {
            for i in 0..count {
                let s = base ^ i.wrapping_mul(0x9E37_79B9);
                user_agents.push(camio_core::random_user_agent(s).string);
            }
        }
        None => {
            for _ in 0..count {
                user_agents.push(camio_core::random_user_agent_from_entropy().string);
            }
        }
    }
    Ok(json!({ "user_agents": user_agents }))
}

// --- captcha detect (passive, scan-side; never the AI OCR path) ---
fn api_captcha(args: &Value) -> Result<Value, String> {
    let body = args.get("body").and_then(|v| v.as_str()).unwrap_or("");
    let detections = camio_scan::detect_captcha_in_html(body)
        .into_iter()
        .map(|k| json!({ "kind": k.as_str(), "evidence": k.solver_hint() }))
        .collect::<Vec<_>>();
    Ok(json!({ "detections": detections }))
}

// --- proof-of-work wall detect (passive) ---
fn api_pow(args: &Value) -> Result<Value, String> {
    let body = args.get("body").and_then(|v| v.as_str()).unwrap_or("");
    let server = args.get("server").and_then(|v| v.as_str());
    let powered_by = args.get("powered_by").and_then(|v| v.as_str());
    let hits = camio_scan::detect_pow_in_response(body, server, powered_by);
    if hits.is_empty() {
        return Ok(json!({ "detected": false }));
    }
    let systems = hits
        .iter()
        .map(|s| json!({ "kind": s.as_str(), "detail": s.solver_hint() }))
        .collect::<Vec<_>>();
    let first = hits[0];
    Ok(json!({ "detected": true, "kind": first.as_str(), "detail": first.solver_hint(), "systems": systems }))
}

// --- F09 diff: unified diff of two stored exchanges ---
fn api_diff(cfg: &WebConfig, args: &Value) -> Result<Value, String> {
    let id1 = args.get("id1").and_then(|v| v.as_i64()).ok_or("missing `id1`")?;
    let id2 = args.get("id2").and_then(|v| v.as_i64()).ok_or("missing `id2`")?;
    let request = args.get("request").and_then(|v| v.as_bool()).unwrap_or(false);
    let context = args.get("context").and_then(|v| v.as_u64()).unwrap_or(3) as usize;
    let store = open(cfg)?;
    let load = |id: i64| -> Result<HttpExchange, String> {
        store
            .get(camio_core::ExchangeId(id))
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("no exchange #{id}"))
    };
    let a = load(id1)?;
    let b = load(id2)?;
    let (ta, tb) = if request {
        (a.request.raw(), b.request.raw())
    } else {
        let raw = |ex: &HttpExchange| ex.response.as_ref().map(|r| r.raw()).unwrap_or_default();
        (raw(&a), raw(&b))
    };
    let diff = camio_convert::unified_diff(&ta, &tb, context);
    Ok(json!({ "diff": &diff, "identical": diff.trim().is_empty() }))
}

// --- F26 sbom: CycloneDX SBOM of the build ---
fn api_sbom(_args: &Value) -> Result<Value, String> {
    Ok(camio_core::sbom::generate(
        camio_core::sbom::EMBEDDED_LOCK,
        "camio",
        env!("CARGO_PKG_VERSION"),
    ))
}

// --- F14 retest: replay a finding's evidence request and re-run checks ---
fn api_retest(cfg: &WebConfig, engine: &dyn RequestEngine, args: &Value) -> Result<Value, String> {
    let finding_id = args
        .get("finding_id")
        .and_then(Value::as_i64)
        .ok_or("finding_id (integer) is required")?;
    let confirm = args.get("confirm").and_then(Value::as_bool).unwrap_or(false);
    let mark = args.get("mark").and_then(Value::as_bool).unwrap_or(false);
    let store = open(cfg)?;
    let finding = store
        .list_findings()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|f| f.id.0 == finding_id)
        .ok_or_else(|| format!("no finding #{finding_id}"))?;
    let origin_id = *finding
        .evidence
        .first()
        .ok_or_else(|| format!("finding #{finding_id} has no evidence exchange to replay"))?;
    let origin = store
        .get(origin_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("evidence exchange #{} is no longer stored", origin_id.0))?;
    let base = origin.request.clone();
    let decision = cfg
        .scope
        .decide(&HttpExchange::new(base.clone(), Source::Scanner));
    match cfg
        .policy
        .gate_action_with(ActionClass::Active, &cfg.scope, decision, confirm)
    {
        PolicyOutcome::Deny(reason) => return Err(format!("refused: {reason}")),
        PolicyOutcome::NeedsConfirmation(reason) => {
            return Ok(json!({
                "status": "confirmation_required", "reason": reason, "scope": decision.as_str(),
                "preview": { "method": base.method, "url": base.url, "rule": finding.rule, "title": finding.title },
            }))
        }
        PolicyOutcome::Allow => {}
    }
    let store_cell = std::cell::RefCell::new(store);
    let send = |req: HttpRequest| -> Option<HttpExchange> {
        if !cfg
            .scope
            .decide(&HttpExchange::new(req.clone(), Source::Scanner))
            .is_sendable()
        {
            return None;
        }
        match engine.send(req, Source::Scanner) {
            Ok(mut ex) => {
                if let Ok(id) = store_cell.borrow_mut().insert(&ex) {
                    ex.id = id;
                }
                Some(ex)
            }
            Err(_) => None,
        }
    };
    let mut reproduced = camio_active::run_active(&base, &send);
    if let Some(ex) = send(base.clone()) {
        reproduced.extend(camio_scan::scan_exchange(&ex));
    }
    let still = reproduced.iter().any(|f| match (&finding.rule, &f.rule) {
        (Some(o), Some(n)) => o == n,
        _ => f.title == finding.title,
    });
    let mut marked: Option<&str> = None;
    if mark {
        let status = if still {
            camio_store::FindingStatus::Confirmed
        } else {
            camio_store::FindingStatus::Fixed
        };
        store_cell
            .borrow_mut()
            .set_finding_status(camio_core::FindingId(finding_id), status, Some("set by retest"))
            .map_err(|e| e.to_string())?;
        marked = Some(status.as_str());
    }
    Ok(json!({ "finding_id": finding_id, "rule": finding.rule, "title": finding.title, "still_present": still, "marked": marked }))
}

// --- F25 dast: headless baseline+active+passive sweep → result contract ---
fn api_dast(cfg: &WebConfig, engine: &dyn RequestEngine, args: &Value) -> Result<Value, String> {
    let base = request_from_args(args)?;
    let confirm = args.get("confirm").and_then(Value::as_bool).unwrap_or(false);
    let fail_on = parse_severity_opt(args.get("fail_on").and_then(Value::as_str));
    let decision = cfg
        .scope
        .decide(&HttpExchange::new(base.clone(), Source::Scanner));
    match cfg
        .policy
        .gate_action_with(ActionClass::Active, &cfg.scope, decision, confirm)
    {
        PolicyOutcome::Deny(reason) => return Err(format!("refused: {reason}")),
        PolicyOutcome::NeedsConfirmation(reason) => {
            return Ok(json!({ "status": "confirmation_required", "reason": reason, "scope": decision.as_str(),
                              "note": "re-call dast with confirm:true to run the sweep" }))
        }
        PolicyOutcome::Allow => {}
    }
    let sent = std::cell::RefCell::new(0u64);
    let store_cell = std::cell::RefCell::new(open(cfg)?);
    let send = |req: HttpRequest| -> Option<HttpExchange> {
        if !cfg
            .scope
            .decide(&HttpExchange::new(req.clone(), Source::Scanner))
            .is_sendable()
        {
            return None;
        }
        match engine.send(req, Source::Scanner) {
            Ok(mut ex) => {
                *sent.borrow_mut() += 1;
                if let Ok(id) = store_cell.borrow_mut().insert(&ex) {
                    ex.id = id;
                }
                Some(ex)
            }
            Err(_) => None,
        }
    };
    let baseline_ex = send(base.clone());
    let mut findings = camio_active::run_active(&base, &send);
    if let Some(ex) = &baseline_ex {
        findings.extend(camio_scan::scan_exchange(ex));
    }
    let over = fail_on
        .map(|t| findings.iter().filter(|f| f.severity >= t).count())
        .unwrap_or(0);
    Ok(json!({
        "tool": "camio", "target": base.url, "scope_decision": decision.as_str(),
        "engine": engine.label(), "fingerprint_matched": engine.is_fingerprint_matched(),
        "checks_run": camio_active::default_active_checks().len() + camio_scan::default_checks().len(),
        "exchanges_sent": *sent.borrow(), "total_findings": findings.len(),
        "severity_breakdown": severity_breakdown_json(&findings),
        "gate": { "threshold": fail_on.map(|t| t.as_str()), "over_threshold": over, "passed": over == 0 },
    }))
}

// --- F13 activescan: run the opt-in active checks (filterable) ---
fn api_activescan(cfg: &WebConfig, engine: &dyn RequestEngine, args: &Value) -> Result<Value, String> {
    let base = request_from_args(args)?;
    let confirm = args.get("confirm").and_then(Value::as_bool).unwrap_or(false);
    let only = csv_list(args.get("only").and_then(Value::as_str));
    let exclude = csv_list(args.get("exclude").and_then(Value::as_str));
    let decision = cfg
        .scope
        .decide(&HttpExchange::new(base.clone(), Source::Scanner));
    match cfg
        .policy
        .gate_action_with(ActionClass::Active, &cfg.scope, decision, confirm)
    {
        PolicyOutcome::Deny(reason) => return Err(format!("refused: {reason}")),
        PolicyOutcome::NeedsConfirmation(reason) => {
            return Ok(json!({ "status": "confirmation_required", "reason": reason, "scope": decision.as_str(),
                              "note": "re-call activescan with confirm:true to run" }))
        }
        PolicyOutcome::Allow => {}
    }
    let store_cell = std::cell::RefCell::new(open(cfg)?);
    let send = |req: HttpRequest| -> Option<HttpExchange> {
        if !cfg
            .scope
            .decide(&HttpExchange::new(req.clone(), Source::Scanner))
            .is_sendable()
        {
            return None;
        }
        match engine.send(req, Source::Scanner) {
            Ok(mut ex) => {
                if let Ok(id) = store_cell.borrow_mut().insert(&ex) {
                    ex.id = id;
                }
                Some(ex)
            }
            Err(_) => None,
        }
    };
    let findings = camio_active::run_active_filtered(&base, &send, &only, &exclude);
    Ok(json!({ "scope": decision.as_str(), "count": findings.len(), "findings": findings }))
}

// --- F10/F13 crawl: live bounded same-origin crawl from a seed ---
fn api_crawl(cfg: &WebConfig, engine: &dyn RequestEngine, args: &Value) -> Result<Value, String> {
    let seed = args
        .get("seed")
        .and_then(Value::as_str)
        .ok_or("seed url is required")?
        .to_string();
    let confirm = args.get("confirm").and_then(Value::as_bool).unwrap_or(false);
    let max_pages = args
        .get("max_pages")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .clamp(1, 500) as usize;
    let probe = HttpRequest::get(&seed);
    let decision = cfg.scope.decide(&HttpExchange::new(probe, Source::Scanner));
    match cfg
        .policy
        .gate_action_with(ActionClass::Active, &cfg.scope, decision, confirm)
    {
        PolicyOutcome::Deny(reason) => return Err(format!("refused: {reason}")),
        PolicyOutcome::NeedsConfirmation(reason) => {
            return Ok(json!({ "status": "confirmation_required", "reason": reason, "scope": decision.as_str(),
                              "note": "re-call crawl with confirm:true to fetch" }))
        }
        PolicyOutcome::Allow => {}
    }
    let store_cell = std::cell::RefCell::new(open(cfg)?);
    let send = |req: HttpRequest| -> Option<HttpExchange> {
        if !cfg
            .scope
            .decide(&HttpExchange::new(req.clone(), Source::Scanner))
            .is_sendable()
        {
            return None;
        }
        match engine.send(req, Source::Scanner) {
            Ok(mut ex) => {
                if let Ok(id) = store_cell.borrow_mut().insert(&ex) {
                    ex.id = id;
                }
                Some(ex)
            }
            Err(_) => None,
        }
    };
    let opts = camio_active::CrawlOptions {
        max_pages,
        same_origin_only: true,
    };
    let result = camio_active::crawl(&seed, &send, &opts);
    Ok(json!({
        "scope": decision.as_str(),
        "pages_fetched": result.fetched.len(),
        "fetched": result.fetched.iter().map(|e| e.0).collect::<Vec<_>>(),
        "discovered": result.discovered,
        "skipped": result.skipped,
    }))
}

// --- F02 audit: read the durable audit log ---
fn api_audit(cfg: &WebConfig, args: &Value) -> Result<Value, String> {
    let store = open(cfg)?;
    let limit = args
        .get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(100)
        .clamp(1, 1000);
    let class = args
        .get("class")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let rows = if class.is_empty() {
        store.audit_log(limit)
    } else {
        store.audit_log_by_class(&class.to_uppercase(), limit)
    }
    .map_err(|e| e.to_string())?;
    let total = store.audit_log_count().map_err(|e| e.to_string())?;
    let rows: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({ "id": r.id, "at_ms": r.at_ms, "actor": r.actor, "class": r.action_class,
                    "action": r.action, "target": r.target, "decision": r.decision, "detail": r.detail })
        })
        .collect();
    Ok(json!({ "total": total, "rows": rows }))
}

// --- F18 collection: manage named groups of exchanges/findings/tasks ---
fn api_collection(cfg: &WebConfig, args: &Value) -> Result<Value, String> {
    let store = open(cfg)?;
    let op = args.get("op").and_then(Value::as_str).unwrap_or("list");
    let name = || {
        args.get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let resolve = |n: &str| {
        store
            .collection_id(n)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("no collection `{n}`"))
    };
    match op {
        "list" => {
            let cols: Vec<Value> = store
                .collections()
                .map_err(|e| e.to_string())?
                .iter()
                .map(|c| json!({ "id": c.id, "name": c.name, "note": c.note, "item_count": c.item_count }))
                .collect();
            Ok(json!({ "collections": cols }))
        }
        "show" => {
            let id = resolve(&name())?;
            let items: Vec<Value> = store
                .collection_items(id)
                .map_err(|e| e.to_string())?
                .iter()
                .map(|it| json!({ "kind": it.kind.as_str(), "ref_id": it.ref_id }))
                .collect();
            Ok(json!({ "items": items }))
        }
        "add" => {
            let kind = camio_store::ItemKind::parse(args.get("kind").and_then(Value::as_str).unwrap_or(""))
                .ok_or("unknown kind (exchange|finding|task)")?;
            let ref_id = args.get("id").and_then(Value::as_i64).ok_or("missing item id")?;
            let id = store.collection_create(&name()).map_err(|e| e.to_string())?;
            let added = store.collection_add(id, kind, ref_id).map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true, "added": added }))
        }
        "remove" => {
            let kind = camio_store::ItemKind::parse(args.get("kind").and_then(Value::as_str).unwrap_or(""))
                .ok_or("unknown kind")?;
            let ref_id = args.get("id").and_then(Value::as_i64).ok_or("missing item id")?;
            let id = resolve(&name())?;
            let removed = store.collection_remove(id, kind, ref_id).map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true, "removed": removed }))
        }
        "delete" => {
            let id = resolve(&name())?;
            let deleted = store.collection_delete(id).map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true, "deleted": deleted }))
        }
        other => Err(format!("unknown op `{other}`")),
    }
}

// --- F09 baseline: pin a stored exchange and diff later ones against it ---
fn api_baseline(cfg: &WebConfig, args: &Value) -> Result<Value, String> {
    let store = open(cfg)?;
    let op = args.get("op").and_then(Value::as_str).unwrap_or("list");
    let load = |id: camio_core::ExchangeId| -> Result<HttpExchange, String> {
        store
            .get(id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("no exchange #{}", id.0))
    };
    match op {
        "list" => {
            let bs: Vec<Value> = store
                .baselines()
                .map_err(|e| e.to_string())?
                .iter()
                .map(|(n, id)| json!({ "name": n, "exchange_id": id.0 }))
                .collect();
            Ok(json!({ "baselines": bs }))
        }
        "set" => {
            let name = args.get("name").and_then(Value::as_str).ok_or("missing name")?;
            let eid = args.get("exchange_id").and_then(Value::as_i64).ok_or("missing exchange_id")?;
            let id = camio_core::ExchangeId(eid);
            if store.get(id).map_err(|e| e.to_string())?.is_none() {
                return Err(format!("no exchange #{eid}"));
            }
            store.set_baseline(name, id).map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true }))
        }
        "diff" => {
            let name = args.get("name").and_then(Value::as_str).ok_or("missing name")?;
            let eid = args.get("exchange_id").and_then(Value::as_i64).ok_or("missing exchange_id")?;
            let request = args.get("request").and_then(Value::as_bool).unwrap_or(false);
            let context = args.get("context").and_then(Value::as_u64).unwrap_or(3) as usize;
            let base_id = store
                .baseline(name)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("no baseline `{name}`"))?;
            let base = load(base_id)?;
            let other = load(camio_core::ExchangeId(eid))?;
            let raw = |ex: &HttpExchange| {
                if request {
                    ex.request.raw()
                } else {
                    ex.response.as_ref().map(|r| r.raw()).unwrap_or_default()
                }
            };
            let diff = camio_convert::unified_diff(&raw(&base), &raw(&other), context);
            Ok(json!({ "diff": &diff, "identical": diff.trim().is_empty(), "baseline_id": base_id.0 }))
        }
        "rm" => {
            let name = args.get("name").and_then(Value::as_str).ok_or("missing name")?;
            let removed = store.delete_baseline(name).map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true, "removed": removed }))
        }
        other => Err(format!("unknown op `{other}`")),
    }
}

// --- F18 label: organizer labels on exchanges ---
fn api_label(cfg: &WebConfig, args: &Value) -> Result<Value, String> {
    let mut store = open(cfg)?;
    let op = args.get("op").and_then(Value::as_str).unwrap_or("list");
    let eid = || args.get("id").and_then(Value::as_i64);
    match op {
        "list" => {
            let labels: Vec<Value> = store
                .all_labels()
                .map_err(|e| e.to_string())?
                .iter()
                .map(|(l, c)| json!({ "label": l, "count": c }))
                .collect();
            Ok(json!({ "labels": labels }))
        }
        "show" => {
            let id = eid().ok_or("missing exchange id")?;
            let labels = store
                .labels_for(camio_core::ExchangeId(id))
                .map_err(|e| e.to_string())?;
            Ok(json!({ "labels": labels }))
        }
        "add" => {
            let id = eid().ok_or("missing exchange id")?;
            let label = args.get("label").and_then(Value::as_str).ok_or("missing label")?;
            store
                .add_label(camio_core::ExchangeId(id), label)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true }))
        }
        "remove" => {
            let id = eid().ok_or("missing exchange id")?;
            let label = args.get("label").and_then(Value::as_str).ok_or("missing label")?;
            let removed = store
                .remove_label(camio_core::ExchangeId(id), label)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true, "removed": removed }))
        }
        other => Err(format!("unknown op `{other}`")),
    }
}

// --- F11 encode chain: compose encodings in sequence (WAF evasion) ---
fn api_encode_chain(args: &Value) -> Result<Value, String> {
    let payloads = args.get("payloads").and_then(|v| v.as_str()).unwrap_or("");
    let set = camio_automate::PayloadSet::from_lines("web", payloads);
    if set.payloads.is_empty() {
        return Err("provide one or more payloads (one per line)".into());
    }
    let spec = args.get("chain").and_then(|v| v.as_str()).unwrap_or("");
    let chain = camio_automate::parse_encoding_chain(spec)?;
    let mut chained = camio_automate::chain_payload_set(&set, &chain);
    let total = chained.len();
    chained.truncate(500);
    let label = chain.iter().map(|e| e.name()).collect::<Vec<_>>().join(">");
    Ok(json!({ "count": total, "truncated": total > chained.len(), "chain": label, "payloads": chained }))
}

// --- vector chaining: compose stored findings into attack chains ---
fn api_attack_chains(cfg: &WebConfig, _args: &Value) -> Result<Value, String> {
    let store = open(cfg)?;
    let findings = store.list_findings().map_err(|e| e.to_string())?;
    let chains = camio_automate::suggest_attack_chains(&findings);
    Ok(json!({ "finding_count": findings.len(), "chains": chains }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_validate_accepts_a_good_doc_and_lists_steps() {
        let doc = json!({
            "doc": {
                "name": "wf",
                "steps": [
                    { "id": "seed", "action": "request", "url": "https://x.test/" },
                    { "id": "scan", "action": "passive_scan", "on": "seed" }
                ]
            }
        });
        let out = api_workflow_validate(&doc).expect("endpoint ok");
        assert_eq!(out["valid"], true);
        assert_eq!(out["steps"].as_array().unwrap().len(), 2);
        assert_eq!(out["steps"][0]["action"], "request");
    }

    #[test]
    fn workflow_validate_reports_errors_for_a_bad_doc() {
        // Forward reference + unknown transform op — the real validator's errors.
        let doc = json!({
            "doc": {
                "name": "bad",
                "steps": [
                    { "id": "s", "action": "passive_scan", "on": "later" },
                    { "id": "later", "action": "transform", "input": "x", "op": "enigma" }
                ]
            }
        });
        let out = api_workflow_validate(&doc).expect("endpoint ok");
        assert_eq!(out["valid"], false);
        let errs = out["errors"].as_array().unwrap();
        assert!(errs.len() >= 2, "expected multiple errors, got {errs:?}");
    }

    #[test]
    fn workflow_validate_accepts_the_doc_as_a_json_string_too() {
        let doc = json!({ "doc": "{\"name\":\"w\",\"steps\":[{\"id\":\"t\",\"action\":\"transform\",\"input\":\"hi\",\"op\":\"rot13\"}]}" });
        let out = api_workflow_validate(&doc).expect("endpoint ok");
        assert_eq!(out["valid"], true);
    }

    #[test]
    fn workflow_validate_rejects_malformed_json() {
        let out = api_workflow_validate(&json!({ "doc": "{not json" }));
        assert!(out.is_err());
    }
}
