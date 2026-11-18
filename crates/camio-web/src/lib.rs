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
    ActionClass, Body, FingerprintProfile, HttpExchange, HttpRequest, Policy, PolicyOutcome, Scope,
    SiteMap, Source,
};
use camio_request::{matched_engine, DryRunEngine, FingerprintSpec, RequestEngine};
use camio_store::{Store, ARTIFACT_BYTES};
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
    // Best available engine; falls back to a no-network dry-run that is honest
    // about not being fingerprint-matched.
    let engine: Box<dyn RequestEngine> =
        matched_engine(&cfg.profile).unwrap_or_else(|_| Box::new(DryRunEngine::new(spec)));

    println!(
        "Camio web workbench (Ctrl-C to stop)\n{}",
        access.open_url()
    );

    for mut request in server.incoming_requests() {
        let method = request.method().clone();
        let url = request.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();

        let response = route(&cfg, engine.as_ref(), &access, &mut request, &method, &path);
        let _ = request.respond(access::secure_headers(response));
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
            return Response::from_data(bytes).with_header(header("Content-Type", mime));
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
    if method != &Method::Post {
        return error_response(404, "not found");
    }

    let args = match read_json(request) {
        Ok(args) => args,
        Err((status, message)) => return error_response(status, message),
    };

    let result: Result<Value, String> = match path {
        "/api/scan" => api_scan(cfg, &args),
        "/api/sitemap" => api_sitemap(cfg, &args),
        "/api/convert" => api_convert(&args),
        "/api/jwt" => api_jwt(&args),
        "/api/sequencer" => api_sequencer(&args),
        "/api/discover" => api_discover(&args),
        "/api/scope" => api_scope(cfg, &args),
        "/api/payloads" => Ok(api_payloads()),
        "/api/fuzz_plan" => api_fuzz_plan(&args),
        "/api/import" => api_import(cfg, &args),
        "/api/send" => api_send(cfg, engine, &args),
        "/api/fuzz_run" => api_fuzz_run(cfg, engine, &args),
        other => match workbench::dispatch(cfg, other, &args) {
            Some(result) => result,
            None => return error_response(404, "unknown endpoint"),
        },
    };

    match result {
        Ok(v) => json_response(&v),
        Err(e) => error_response(400, &e),
    }
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
    let limit = args.get("limit").and_then(|l| l.as_u64()).unwrap_or(1000) as usize;
    let save = args.get("save").and_then(|s| s.as_bool()).unwrap_or(false);
    let compiled = workbench::compile(q).map_err(|e| format!("{e:#}"))?;
    let mut store = open(cfg)?;
    let rows = store
        .query_with_bodies(&compiled, limit.min(1000))
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
        "saved": saved,
        "findings": serde_json::to_value(&report.findings).unwrap_or(json!([])),
    }))
}

fn api_sitemap(cfg: &WebConfig, args: &Value) -> Result<Value, String> {
    let q = args.get("query").and_then(|q| q.as_str()).unwrap_or("");
    let limit = args.get("limit").and_then(|l| l.as_u64()).unwrap_or(5000) as usize;
    let compiled = workbench::compile(q).map_err(|e| format!("{e:#}"))?;
    let store = open(cfg)?;
    let rows = store.query(&compiled, limit).map_err(|e| e.to_string())?;
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
        arr.iter()
            .filter_map(|t| t.as_str().map(|s| s.to_string()))
            .collect()
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
    let result = camio_import::import_bytes(content.as_bytes()).map_err(|e| e.to_string())?;
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
            let ex = engine
                .send(req, Source::Replay)
                .map_err(|e| format!("send failed: {e}"))?;
            let mut store = open(cfg)?;
            let id = store.insert(&ex).ok().map(|i| i.0);
            let mut s = summary(&ex);
            s["stored_id"] = json!(id);
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

    match cfg.policy.gate(ActionClass::Active, decision, confirm) {
        PolicyOutcome::Deny(reason) => return Err(format!("refused: {reason}")),
        PolicyOutcome::NeedsConfirmation(reason) => {
            return Ok(json!({
                "status": "confirmation_required",
                "reason": reason,
                "plan": { "attack": attack.as_str(), "num_positions": plan.num_positions,
                          "projected_requests": plan.projected_requests, "within_budget": plan.within_budget,
                          "scope": decision.as_str() },
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

    let generated = camio_automate::generate(&campaign).map_err(|e| e.to_string())?;
    let baseline = engine.send(clean, Source::Automate).ok().and_then(|ex| {
        ex.response.as_ref().map(|r| Baseline {
            status: r.status,
            body_len: r.body.len(),
        })
    });
    let mut store = open(cfg)?;
    let mut results = Vec::new();
    for g in &generated {
        if !cfg
            .scope
            .decide(&HttpExchange::new(g.request.clone(), Source::Automate))
            .is_sendable()
        {
            continue;
        }
        if let Ok(ex) = engine.send(g.request.clone(), Source::Automate) {
            let _ = store.insert(&ex);
            results.push((g.payloads.clone(), ex));
        }
    }
    let classified = camio_automate::classify(&results, baseline.as_ref(), None);
    Ok(
        json!({ "status": "done", "sent": results.len(), "results": serde_json::to_value(&classified).unwrap_or(json!([])) }),
    )
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

fn read_json(request: &mut tiny_http::Request) -> Result<Value, (u16, &'static str)> {
    let content_type = access::single_header(request.headers(), "Content-Type")
        .ok()
        .flatten();
    if !content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err((415, "expected application/json"));
    }
    let length = request.body_length();
    if length.is_some_and(|size| size as u64 > MAX_BODY) {
        return Err((413, "request exceeds 8 MiB"));
    }
    let mut bytes = Vec::new();
    request
        .as_reader()
        .take(MAX_BODY + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| (400, "could not read request body"))?;
    if bytes.len() as u64 > MAX_BODY {
        return Err((413, "request exceeds 8 MiB"));
    }
    if length.is_some_and(|size| size != bytes.len()) {
        return Err((400, "incomplete request body"));
    }
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(args) if args.is_object() => Ok(args),
        _ => Err((400, "expected a JSON object")),
    }
}

fn json_response(v: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string());
    Response::from_string(body)
        .with_header(header("Content-Type", "application/json; charset=utf-8"))
}

fn error_response(code: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = json!({ "error": msg }).to_string();
    Response::from_string(body)
        .with_status_code(code)
        .with_header(header("Content-Type", "application/json; charset=utf-8"))
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes())
        .unwrap_or_else(|_| Header::from_bytes(&b"X"[..], &b"x"[..]).unwrap())
}

fn static_asset(path: &str) -> Option<(&'static str, &'static [u8])> {
    Some(match path {
        "/" | "/index.html" => ("text/html; charset=utf-8", include_bytes!("ui.html")),
        "/ui.css" => ("text/css; charset=utf-8", include_bytes!("ui.css")),
        "/ui.js" => ("text/javascript; charset=utf-8", include_bytes!("ui.js")),
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
