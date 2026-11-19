//! `camio-app` — Camio's native desktop workbench (plan §7 UX/IA, §13 "Rust
//! desktop shell … No Electron / bundled JS runtime").
//!
//! A single egui/eframe window with a left rail of surfaces over the same crates
//! the CLI and MCP server use. It is a true native application: it calls
//! `camio-scan`, `camio-automate`, `camio-convert`, `camio-import`,
//! `camio-sequencer` and the fingerprint-matched request engine in-process, reads
//! history straight from the SQLite store, launches the managed LibreWolf/Camoufox
//! browser with the shared fingerprint profile, and enforces the one shared scope
//! + policy on every send (plan §16).
//!
//! Beyond the testing surfaces it has customizable [`theme`]s with a background
//! image, a process-based [`plugins`] system, and a [`browser`] launcher that
//! ports the Camoufox fingerprint onto the user's browser.

mod browser;
mod inventory;
mod plugins;
mod theme;
mod workbench;
mod workflows;

use camio_ai::{AiClient, AiConfig, Message};
use camio_automate::{AttackType, Baseline, Campaign, PayloadSet};
use camio_convert::Transform;
use camio_core::{
    ActionClass, Body, FingerprintProfile, HttpExchange, HttpRequest, MatchReplaceRule,
    MatchTarget, Policy, PolicyOutcome, Query, RuleSet, Scope, SiteMap, Source,
};
use camio_proxy::{
    CertAuthority, EngineForwarder, ExchangeSink, Interceptor, Pending, ProxyConfig, ProxyServer,
    QueueInterceptor, RequestDecision,
};
use camio_request::{matched_engine, DryRunEngine, FingerprintSpec, RequestEngine};
use camio_store::Store;
use plugins::Plugin;
use std::collections::HashMap;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use theme::Theme;

/// What the app needs to run: the history DB and the shared profile/scope/policy.
pub struct AppConfig {
    pub db: PathBuf,
    pub profile: FingerprintProfile,
    pub scope: Scope,
    pub policy: Policy,
}

/// Launch the native window. Blocks until the window is closed.
pub fn run(cfg: AppConfig) -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 780.0])
            .with_min_inner_size([780.0, 540.0])
            .with_title("Camio"),
        ..Default::default()
    };
    eframe::run_native(
        "Camio",
        options,
        Box::new(|_cc| Ok(Box::new(CamioApp::new(cfg)))),
    )
    .map_err(|e| e.to_string())
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Surface {
    Status,
    Workflows,
    Tasks,
    Library,
    Integrations,
    History,
    Query,
    Sitemap,
    Inventory,
    Replay,
    Discover,
    Fuzz,
    Scan,
    Findings,
    Convert,
    Comparer,
    Jwt,
    Sequencer,
    MatchReplace,
    Scope,
    Payloads,
    Import,
    Fingerprint,
    ActiveScan,
    AnalyzeJs,
    Ai,
    Proxy,
    Browser,
    Plugins,
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttackKind {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

impl AttackKind {
    fn to_attack(self) -> AttackType {
        match self {
            AttackKind::Sniper => AttackType::Sniper,
            AttackKind::BatteringRam => AttackType::BatteringRam,
            AttackKind::Pitchfork => AttackType::Pitchfork,
            AttackKind::ClusterBomb => AttackType::ClusterBomb,
        }
    }
    fn label(self) -> &'static str {
        match self {
            AttackKind::Sniper => "sniper",
            AttackKind::BatteringRam => "battering_ram",
            AttackKind::Pitchfork => "pitchfork",
            AttackKind::ClusterBomb => "cluster_bomb",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MrTarget {
    Url,
    Method,
    Body,
    Header,
}

impl MrTarget {
    fn label(self) -> &'static str {
        match self {
            MrTarget::Url => "url",
            MrTarget::Method => "method",
            MrTarget::Body => "body",
            MrTarget::Header => "header",
        }
    }
}

enum Output {
    None,
    Text(String),
    Table {
        cols: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    Error(String),
}

struct CamioApp {
    cfg: AppConfig,
    engine: Box<dyn RequestEngine>,
    surface: Surface,
    theme: Theme,
    bg_texture: Option<(PathBuf, Option<egui::TextureHandle>)>,
    workbench: workbench::Workbench,
    inventory: inventory::InventoryPane,
    workflows: workflows::WorkflowView,
    // request builder
    url: String,
    method: String,
    headers: String,
    body: String,
    confirm: bool,
    // query / history / scan / sitemap
    query: String,
    limit: String,
    scan_save: bool,
    // convert / jwt / sequencer / comparer
    convert_in: String,
    convert_steps: String,
    jwt_token: String,
    seq_text: String,
    cmp_a: String,
    cmp_b: String,
    // match & replace
    mr_target: MrTarget,
    mr_header: String,
    mr_find: String,
    mr_replace: String,
    // fuzz
    attack: AttackKind,
    payloads: String,
    budget: String,
    // import
    import_path: String,
    import_content: String,
    import_save: bool,
    archive_pending: Option<mpsc::Receiver<Result<(String, bool), String>>>,
    // browser
    browser_bin: String,
    install_root: String,
    marionette: bool,
    // plugins
    plugins_dir: String,
    plugins: Vec<Plugin>,
    selected_plugin: Option<usize>,
    plugin_input: String,
    // AI assistant (optional, BYO key; calls run on a background thread)
    ai_config: AiConfig,
    ai_prompt: String,
    ai_pending: Option<mpsc::Receiver<Result<String, String>>>,
    // analyze-js / active-scan
    js_blob: String,
    active_save: bool,
    // nuclei (external) runner, on a background thread
    nuclei_url: String,
    nuclei_pending: Option<mpsc::Receiver<Result<usize, String>>>,
    // intercepting proxy (runs on a background thread via a stoppable handle)
    proxy_listen: String,
    proxy_tls: bool,
    proxy_auto_scan: bool,
    proxy_intercept: bool,
    proxy_handle: Option<camio_proxy::ProxyHandle>,
    proxy_sink: std::sync::Arc<camio_proxy::VecSink>,
    proxy_queue: std::sync::Arc<QueueInterceptor>,
    proxy_ca_dir: PathBuf,
    proxy_status: String,
    // intercept editor (the request currently held in the queue)
    icept_id: Option<u64>,
    icept_method: String,
    icept_url: String,
    icept_headers: String,
    icept_body: String,
    // output
    out: Output,
    surface_outputs: HashMap<Surface, Output>,
}

impl CamioApp {
    fn new(cfg: AppConfig) -> Self {
        let spec = FingerprintSpec::from_profile(&cfg.profile);
        let engine: Box<dyn RequestEngine> =
            matched_engine(&cfg.profile).unwrap_or_else(|_| Box::new(DryRunEngine::new(spec)));
        let plugins_dir = "plugins".to_string();
        let plugins = plugins::discover(std::path::Path::new(&plugins_dir));
        // Optional deep-link / theme override via env (also handy for scripting).
        let theme = {
            let mut t = theme::load();
            if let Ok(name) = std::env::var("CAMIO_THEME") {
                if let Some(p) = Theme::presets()
                    .into_iter()
                    .find(|p| p.name.eq_ignore_ascii_case(name.trim()))
                {
                    t = p;
                }
            }
            t
        };
        let surface = std::env::var("CAMIO_SURFACE")
            .ok()
            .and_then(|s| surface_from_name(&s))
            .unwrap_or(Surface::Status);
        let mut app = CamioApp {
            cfg,
            engine,
            surface,
            theme,
            bg_texture: None,
            workbench: workbench::Workbench::default(),
            inventory: inventory::InventoryPane::default(),
            workflows: workflows::WorkflowView::default(),
            url: String::new(),
            method: "GET".to_string(),
            headers: String::new(),
            body: String::new(),
            confirm: false,
            query: String::new(),
            limit: "50".to_string(),
            scan_save: true,
            convert_in: String::new(),
            convert_steps: "base64".to_string(),
            jwt_token: String::new(),
            seq_text: String::new(),
            cmp_a: String::new(),
            cmp_b: String::new(),
            mr_target: MrTarget::Url,
            mr_header: "User-Agent".to_string(),
            mr_find: String::new(),
            mr_replace: String::new(),
            attack: AttackKind::Sniper,
            payloads: "sqli".to_string(),
            budget: "200".to_string(),
            import_path: String::new(),
            import_content: String::new(),
            import_save: true,
            archive_pending: None,
            browser_bin: String::new(),
            install_root: "vendor/camoufox/dist".to_string(),
            marionette: true,
            plugins_dir,
            plugins,
            selected_plugin: None,
            plugin_input: String::new(),
            ai_config: AiConfig::from_env(),
            ai_prompt: String::new(),
            ai_pending: None,
            js_blob: String::new(),
            active_save: true,
            nuclei_url: String::new(),
            nuclei_pending: None,
            proxy_listen: "127.0.0.1:8080".to_string(),
            proxy_tls: false,
            proxy_auto_scan: true,
            proxy_intercept: false,
            proxy_handle: None,
            proxy_sink: std::sync::Arc::new(camio_proxy::VecSink::new()),
            proxy_queue: std::sync::Arc::new(QueueInterceptor::new()),
            proxy_ca_dir: default_proxy_ca_dir(),
            proxy_status: String::new(),
            icept_id: None,
            icept_method: String::new(),
            icept_url: String::new(),
            icept_headers: String::new(),
            icept_body: String::new(),
            out: Output::None,
            surface_outputs: HashMap::new(),
        };
        app.enter_workbench(surface);
        app
    }

    fn navigate(&mut self, next: Surface) {
        if self.surface == next {
            return;
        }
        let previous = std::mem::replace(&mut self.surface, next);
        let next_output = self.surface_outputs.remove(&next).unwrap_or(Output::None);
        self.surface_outputs
            .insert(previous, std::mem::replace(&mut self.out, next_output));
        self.enter_workbench(next);
    }

    fn open(&self) -> Result<Store, String> {
        Store::open(&self.cfg.db).map_err(|e| format!("opening {}: {e}", self.cfg.db.display()))
    }

    fn built_request(&self) -> Result<HttpRequest, String> {
        if self.url.trim().is_empty() {
            return Err("enter a URL".into());
        }
        let mut req = HttpRequest::get(self.url.trim());
        req.method = if self.method.trim().is_empty() {
            "GET".into()
        } else {
            self.method.trim().to_string()
        };
        for line in self.headers.lines() {
            if let Some((n, v)) = line.split_once(':') {
                req.headers.push(n.trim().to_string(), v.trim().to_string());
            }
        }
        if !self.body.is_empty() {
            req.body = Body::from_text(self.body.clone());
        }
        Ok(req)
    }

    fn limit_usize(&self, default: usize) -> usize {
        self.limit.trim().parse().unwrap_or(default)
    }

    // --- actions -----------------------------------------------------------

    fn run_sitemap(&mut self) {
        let res = (|| {
            let q =
                Query::compile(self.query.trim()).map_err(|e| format!("invalid CamioQL: {e}"))?;
            let rows = self.open()?.query(&q, 5000).map_err(|e| e.to_string())?;
            Ok::<_, String>(SiteMap::build(&rows))
        })();
        self.out = match res {
            Ok(map) => Output::Text(format!(
                "{}\n— {} origin(s), {} URL(s)",
                map.render_tree(),
                map.origin_count(),
                map.url_count()
            )),
            Err(e) => Output::Error(e),
        };
    }

    fn run_convert(&mut self) {
        let res = (|| {
            let mut steps = Vec::new();
            for name in self
                .convert_steps
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                steps
                    .push(Transform::from_name(name).ok_or(format!("unknown transform `{name}`"))?);
            }
            if steps.is_empty() {
                return Err("enter a pipeline, e.g. base64,gzip".into());
            }
            camio_convert::apply_pipeline(self.convert_in.as_bytes(), &steps)
                .map_err(|e| e.to_string())
        })();
        self.out = match res {
            Ok(out) => {
                let hex = Transform::HexEncode
                    .apply(&out)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_default();
                Output::Text(format!(
                    "{} bytes\n\ntext:\n{}\n\nhex:\n{}",
                    out.len(),
                    String::from_utf8_lossy(&out),
                    hex
                ))
            }
            Err(e) => Output::Error(e),
        };
    }

    fn run_compare(&mut self) {
        let d = camio_convert::diff_bytes(self.cmp_a.as_bytes(), self.cmp_b.as_bytes());
        let unified = camio_convert::unified_diff(&self.cmp_a, &self.cmp_b, 3);
        let summary =
            format!(
            "equal: {}  ·  a={} b={} bytes  ·  common prefix {}, suffix {}  ·  first diff at {}",
            d.equal, d.a_len, d.b_len, d.common_prefix, d.common_suffix,
            d.first_diff_offset.map(|o| o.to_string()).unwrap_or_else(|| "-".into())
        );
        self.out = Output::Text(if unified.trim().is_empty() {
            format!("{summary}\n\n(identical)")
        } else {
            format!("{summary}\n\n{unified}")
        });
    }

    fn run_jwt(&mut self) {
        self.out = match camio_convert::decode_jwt(self.jwt_token.trim()) {
            Ok(p) => Output::Text(format!(
                "header:\n{}\n\npayload:\n{}\n\nsignature (b64url, NOT verified):\n{}",
                p.header_json, p.payload_json, p.signature_b64url
            )),
            Err(e) => Output::Error(e.to_string()),
        };
    }

    fn run_sequencer(&mut self) {
        let tokens: Vec<String> = self
            .seq_text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        let report = camio_sequencer::analyze(&tokens);
        self.out =
            Output::Text(serde_json::to_string_pretty(&report).unwrap_or_else(|e| e.to_string()));
    }

    fn run_matchreplace(&mut self) {
        let res = (|| {
            let target = match self.mr_target {
                MrTarget::Url => MatchTarget::Url,
                MrTarget::Method => MatchTarget::Method,
                MrTarget::Body => MatchTarget::RequestBody,
                MrTarget::Header => MatchTarget::RequestHeader(self.mr_header.trim().to_string()),
            };
            let rule = MatchReplaceRule::literal(
                "ui",
                target,
                self.mr_find.clone(),
                self.mr_replace.clone(),
                None,
            )
            .map_err(|e| e.to_string())?;
            let mut req = self.built_request()?;
            let before = req.raw();
            let n = RuleSet::new().with(rule).apply_to_request(&mut req);
            Ok::<_, String>(format!(
                "applied {n} rule(s)\n\n--- before ---\n{before}\n--- after ---\n{}",
                req.raw()
            ))
        })();
        self.out = match res {
            Ok(t) => Output::Text(t),
            Err(e) => Output::Error(e),
        };
    }

    fn run_discover(&mut self) {
        self.out = match self.built_request() {
            Ok(req) => {
                let inputs = camio_automate::discover_inputs(&req);
                Output::Table {
                    cols: vec!["Kind".into(), "Name".into(), "Value".into()],
                    rows: inputs
                        .iter()
                        .map(|i| {
                            vec![
                                format!("{:?}", i.kind).to_lowercase(),
                                i.name.clone(),
                                i.value.clone(),
                            ]
                        })
                        .collect(),
                }
            }
            Err(e) => Output::Error(e),
        };
    }

    fn run_scope(&mut self) {
        if self.url.trim().is_empty() {
            self.out = Output::Error("enter a URL".into());
            return;
        }
        let d = self.cfg.scope.decide(&HttpExchange::new(
            HttpRequest::get(self.url.trim()),
            Source::Replay,
        ));
        self.out = Output::Text(format!("{}  ->  {}", self.url.trim(), d.as_str()));
    }

    fn run_payloads(&mut self) {
        let rows = camio_automate::builtin_packs()
            .iter()
            .map(|name| {
                let set = camio_automate::builtin_pack(name);
                vec![
                    name.to_string(),
                    set.as_ref()
                        .map(|s| s.len().to_string())
                        .unwrap_or_default(),
                    set.map(|s| {
                        s.payloads
                            .iter()
                            .take(4)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("  ")
                    })
                    .unwrap_or_default(),
                ]
            })
            .collect();
        self.out = Output::Table {
            cols: vec!["Pack".into(), "Size".into(), "Sample".into()],
            rows,
        };
    }

    fn run_import(&mut self, ctx: &egui::Context) {
        if self.archive_pending.is_some() {
            return;
        }
        let path = self.import_path.clone();
        let content = self.import_content.clone();
        let save = self.import_save;
        let db = self.cfg.db.clone();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("camio-archive-import".into())
            .spawn(move || {
                let result = (|| {
                    let data = workbench::local_input(&path, &content)?;
                    let result =
                        camio_import::import_bytes(&data).map_err(|error| error.to_string())?;
                    let stored = if save {
                        Store::open(&db)
                            .and_then(|mut store| store.insert_exchanges(&result.exchanges))
                            .map_err(|error| error.to_string())?
                    } else {
                        0
                    };
                    let mut text = format!(
                        "{} · {} exchanges · {} stored",
                        result.format,
                        result.exchanges.len(),
                        stored
                    );
                    for warning in &result.warnings {
                        text.push('\n');
                        text.push_str(warning);
                    }
                    Ok((text, stored > 0))
                })();
                let _ = tx.send(result);
                ctx.request_repaint();
            });
        match thread {
            Ok(_) => {
                self.archive_pending = Some(rx);
                self.out = Output::Text("Reading archive…".into());
            }
            Err(error) => self.out = Output::Error(error.to_string()),
        }
    }

    fn poll_archive(&mut self) {
        let Some(rx) = self.archive_pending.as_ref() else {
            return;
        };
        let out = match rx.try_recv() {
            Ok(Ok((output, stored))) => {
                if stored {
                    self.workbench.history.invalidate();
                    if matches!(
                        self.surface,
                        Surface::Status | Surface::History | Surface::Query
                    ) {
                        self.enter_workbench(self.surface);
                    }
                }
                Output::Text(output)
            }
            Ok(Err(error)) => Output::Error(error),
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => {
                Output::Error("The archive worker stopped.".into())
            }
        };
        self.archive_pending = None;
        if self.surface == Surface::Import {
            self.out = out;
        } else {
            self.surface_outputs.insert(Surface::Import, out);
        }
    }

    fn resolve_sets(&self) -> Result<Vec<PayloadSet>, String> {
        let mut sets = Vec::new();
        for spec in self
            .payloads
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            if let Some(set) = camio_automate::builtin_pack(spec) {
                sets.push(set);
            } else {
                let p = PathBuf::from(spec);
                if p.exists() {
                    let text =
                        std::fs::read_to_string(&p).map_err(|e| format!("reading {spec}: {e}"))?;
                    sets.push(PayloadSet::from_lines(spec, &text));
                } else {
                    return Err(format!("unknown payload pack / file `{spec}`"));
                }
            }
        }
        if sets.is_empty() {
            return Err("enter at least one payload pack".into());
        }
        Ok(sets)
    }

    fn run_fuzz_plan(&mut self) {
        let res = (|| {
            let base = self.built_request()?;
            let sets = self.resolve_sets()?;
            let budget = self.budget.trim().parse::<u64>().ok();
            camio_automate::plan(&Campaign {
                base,
                attack: self.attack.to_attack(),
                sets,
                budget,
            })
            .map_err(|e| e.to_string())
        })();
        self.out = match res {
            Ok(plan) => Output::Text(format!(
                "attack            : {}\ninsertion points  : {}\nprojected requests: {}\nwithin budget     : {}\npositions         : {}",
                self.attack.label(), plan.num_positions, plan.projected_requests, plan.within_budget,
                plan.positions.iter().map(|p| format!("[{}]={}", p.index, p.baseline)).collect::<Vec<_>>().join("  ")
            )),
            Err(e) => Output::Error(e),
        };
    }

    fn run_fuzz(&mut self) {
        let res = (|| {
            let base = self.built_request()?;
            let sets = self.resolve_sets()?;
            let budget = self.budget.trim().parse::<u64>().unwrap_or(200);
            let campaign = Campaign {
                base: base.clone(),
                attack: self.attack.to_attack(),
                sets,
                budget: Some(budget),
            };
            let plan = camio_automate::plan(&campaign).map_err(|e| e.to_string())?;
            let clean = strip_clean(&base);
            let decision = self
                .cfg
                .scope
                .decide(&HttpExchange::new(clean.clone(), Source::Automate));
            match self
                .cfg
                .policy
                .gate(ActionClass::Active, decision, self.confirm)
            {
                PolicyOutcome::Deny(r) => return Err(format!("refused: {r}")),
                PolicyOutcome::NeedsConfirmation(r) => {
                    return Err(format!(
                        "{r}. Tick 'confirm' to run this active test ({} request(s), scope {}).",
                        plan.projected_requests,
                        decision.as_str()
                    ))
                }
                PolicyOutcome::Allow => {}
            }
            if !plan.within_budget {
                return Err(format!(
                    "projected {} exceeds budget {budget}; raise it",
                    plan.projected_requests
                ));
            }
            let generated = camio_automate::generate(&campaign).map_err(|e| e.to_string())?;
            let baseline = self
                .engine
                .send(clean, Source::Automate)
                .ok()
                .and_then(|ex| {
                    ex.response.as_ref().map(|r| Baseline {
                        status: r.status,
                        body_len: r.body.len(),
                    })
                });
            let mut store = self.open()?;
            let mut results = Vec::new();
            for g in &generated {
                if !self
                    .cfg
                    .scope
                    .decide(&HttpExchange::new(g.request.clone(), Source::Automate))
                    .is_sendable()
                {
                    continue;
                }
                if let Ok(ex) = self.engine.send(g.request.clone(), Source::Automate) {
                    let _ = store.insert(&ex);
                    results.push((g.payloads.clone(), ex));
                }
            }
            Ok::<_, String>(camio_automate::classify(&results, baseline.as_ref(), None))
        })();
        self.out = match res {
            Ok(rows) => Output::Table {
                cols: vec![
                    "Code".into(),
                    "Len".into(),
                    "Flags".into(),
                    "Payload".into(),
                ],
                rows: rows
                    .iter()
                    .map(|r| {
                        vec![
                            r.status
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "-".into()),
                            r.body_len
                                .map(|l| l.to_string())
                                .unwrap_or_else(|| "-".into()),
                            r.flags.join(","),
                            r.payloads.join(" | "),
                        ]
                    })
                    .collect(),
            },
            Err(e) => Output::Error(e),
        };
    }

    fn run_send(&mut self) {
        let res = (|| {
            let req = self.built_request()?;
            let decision = self
                .cfg
                .scope
                .decide(&HttpExchange::new(req.clone(), Source::Replay));
            match self
                .cfg
                .policy
                .gate(ActionClass::Mutating, decision, self.confirm)
            {
                PolicyOutcome::Deny(r) => Err(format!("refused: {r}")),
                PolicyOutcome::NeedsConfirmation(r) => Err(format!(
                    "{r}. Tick 'confirm' to send. (scope: {}, engine: {})",
                    decision.as_str(),
                    self.engine.label()
                )),
                PolicyOutcome::Allow => {
                    let ex = self
                        .engine
                        .send(req, Source::Replay)
                        .map_err(|e| format!("send failed: {e}"))?;
                    let id = self.open()?.insert(&ex).ok().map(|i| i.0);
                    let resp = ex.response.as_ref();
                    Ok(format!(
                        "{} {}  ({} bytes, {} ms, stored #{})\n\n{}\n\n{}",
                        resp.map(|r| r.status.to_string())
                            .unwrap_or_else(|| "-".into()),
                        resp.and_then(|r| r.reason.clone()).unwrap_or_default(),
                        resp.map(|r| r.body.len()).unwrap_or(0),
                        ex.timings.map(|t| t.roundtrip_ms).unwrap_or(0),
                        id.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
                        resp.map(|r| r
                            .headers
                            .iter()
                            .map(|h| format!("{}: {}", h.name, h.value))
                            .collect::<Vec<_>>()
                            .join("\n"))
                            .unwrap_or_default(),
                        resp.map(|r| r.body.as_text().chars().take(20000).collect::<String>())
                            .unwrap_or_default(),
                    ))
                }
            }
        })();
        self.out = match res {
            Ok(t) => Output::Text(t),
            Err(e) => Output::Error(e),
        };
    }

    fn open_in_browser(&mut self, url: String) {
        if url.trim().is_empty() {
            self.out = Output::Error("enter a URL to open".into());
            return;
        }
        match browser::resolve_binary(&self.browser_bin, &self.install_root) {
            Some(bin) => {
                let profile_dir = PathBuf::from("profiles/default");
                match browser::launch(
                    &bin,
                    &self.cfg.profile,
                    &profile_dir,
                    url.trim(),
                    self.marionette,
                ) {
                    Ok(l) => {
                        self.out = Output::Text(format!(
                            "Launched {} (pid {}) at {}\nfingerprint profile: {} ({})\nautomation (marionette): {}\n\nThe browser's about:config fingerprint prefs were written to {}/user.js, so browser and tool traffic share one identity (plan §6.3).",
                            l.binary.display(), l.pid, url.trim(), self.cfg.profile.name, self.cfg.profile.camoufox_build,
                            if l.marionette { "enabled (127.0.0.1:2828) — agent-drivable" } else { "off" },
                            profile_dir.display()
                        ));
                    }
                    Err(e) => self.out = Output::Error(e),
                }
            }
            None => {
                self.out = Output::Error(format!(
                    "No LibreWolf/Camoufox/Firefox binary found.\nInstall LibreWolf (https://librewolf.net) or Camoufox, or set the binary path in Settings.\nSearched PATH for {:?} and the engine install root `{}`.",
                    browser::CANDIDATES, self.install_root
                ));
            }
        }
    }

    fn run_plugin(&mut self) {
        match self.selected_plugin.and_then(|i| self.plugins.get(i)) {
            Some(p) => {
                self.out = match plugins::run(p, &self.plugin_input) {
                    Ok(o) => Output::Text(o),
                    Err(e) => Output::Error(e),
                };
            }
            None => self.out = Output::Error("select a plugin first".into()),
        }
    }

    fn reload_plugins(&mut self) {
        self.plugins = plugins::discover(std::path::Path::new(self.plugins_dir.trim()));
        self.selected_plugin = None;
    }

    // --- UI ----------------------------------------------------------------

    /// The Burp-style horizontal tool tab bar (top of the window). Groups are
    /// laid out left-to-right with a thin separator between them; the active tab
    /// is accent-coloured with an underline, like Burp Suite's tool tabs.
    fn nav_ui(&mut self, ui: &mut egui::Ui) {
        let accent = self.theme.accent_color();
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(3.0, 4.0);
            for (gi, (_group, items)) in workbench::NAV.iter().enumerate() {
                if gi > 0 {
                    ui.add_space(5.0);
                    ui.separator();
                    ui.add_space(5.0);
                }
                for (surface, label) in *items {
                    let active = self.surface == *surface;
                    let color = if active {
                        accent
                    } else {
                        ui.visuals().weak_text_color()
                    };
                    let resp = ui.selectable_label(
                        active,
                        egui::RichText::new(*label).color(color).size(13.5),
                    );
                    if active {
                        // Burp-style active-tab underline.
                        let r = resp.rect;
                        ui.painter().hline(
                            r.x_range(),
                            r.bottom() + 1.0,
                            egui::Stroke::new(2.0_f32, accent),
                        );
                    }
                    if resp.clicked() {
                        self.navigate(*surface);
                    }
                }
            }
        });
    }

    fn central_ui(&mut self, ui: &mut egui::Ui) {
        let surface = self.surface;
        if matches!(
            surface,
            Surface::Status
                | Surface::Workflows
                | Surface::History
                | Surface::Inventory
                | Surface::Query
                | Surface::Scan
                | Surface::Findings
                | Surface::Integrations
                | Surface::Tasks
                | Surface::Library
                | Surface::Settings
        ) {
            egui::ScrollArea::vertical()
                .id_salt(surface)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    match surface {
                        Surface::Status => self.overview_ui(ui),
                        Surface::Workflows => self.workflows_ui(ui),
                        Surface::History | Surface::Query => self.history_ui(ui),
                        Surface::Inventory => self.inventory_ui(ui),
                        Surface::Scan => self.scan_ui(ui),
                        Surface::Findings => self.findings_ui(ui),
                        Surface::Integrations => self.integrations_ui(ui),
                        Surface::Tasks => self.tasks_ui(ui),
                        Surface::Library => self.library_ui(ui),
                        Surface::Settings => self.settings_surface(ui),
                        _ => unreachable!(),
                    }
                    self.workbench_notice(ui);
                });
            return;
        }
        match surface {
            Surface::Fingerprint => self.fingerprint_surface(ui),
            Surface::Sitemap => {
                ui.heading("Site map");
                ui.add(
                    egui::TextEdit::singleline(&mut self.query)
                        .hint_text("filter (CamioQL, optional)")
                        .desired_width(f32::INFINITY),
                );
                if ui.button("Build").clicked() {
                    self.run_sitemap();
                }
            }
            Surface::Replay => {
                ui.heading("Replay / Send");
                ui.label(
                    "Send through the fingerprint-matched engine. In-scope + confirm to send.",
                );
                self.request_builder(ui);
                ui.checkbox(&mut self.confirm, "confirm (actually send)");
                ui.horizontal(|ui| {
                    if ui.button("Send").clicked() {
                        self.run_send();
                    }
                    if ui.button("Open in browser").clicked() {
                        let u = self.url.clone();
                        self.open_in_browser(u);
                    }
                });
            }
            Surface::Discover => {
                ui.heading("Discover inputs");
                self.request_builder(ui);
                if ui.button("Discover").clicked() {
                    self.run_discover();
                }
            }
            Surface::Fuzz => self.fuzz_surface(ui),
            Surface::Convert => {
                ui.heading("Convert");
                ui.label("Pipeline runs left-to-right, e.g. base64,gzip or base64-decode.");
                ui.label("Input");
                ui.add(
                    egui::TextEdit::multiline(&mut self.convert_in).desired_width(f32::INFINITY),
                );
                ui.label("Steps");
                ui.add(
                    egui::TextEdit::singleline(&mut self.convert_steps)
                        .desired_width(f32::INFINITY),
                );
                if ui.button("Apply").clicked() {
                    self.run_convert();
                }
            }
            Surface::Comparer => {
                ui.heading("Comparer");
                ui.label("Byte/line diff between two blobs.");
                ui.label("A");
                ui.add(
                    egui::TextEdit::multiline(&mut self.cmp_a)
                        .desired_width(f32::INFINITY)
                        .desired_rows(5),
                );
                ui.label("B");
                ui.add(
                    egui::TextEdit::multiline(&mut self.cmp_b)
                        .desired_width(f32::INFINITY)
                        .desired_rows(5),
                );
                if ui.button("Diff").clicked() {
                    self.run_compare();
                }
            }
            Surface::Jwt => {
                ui.heading("JWT decode");
                ui.label("Decodes header + payload. The signature is NOT verified.");
                ui.add(egui::TextEdit::multiline(&mut self.jwt_token).desired_width(f32::INFINITY));
                if ui.button("Decode").clicked() {
                    self.run_jwt();
                }
            }
            Surface::Sequencer => {
                ui.heading("Sequencer");
                ui.label("Token randomness estimate (one sample per line). Statistical estimate, not a proof.");
                ui.add(
                    egui::TextEdit::multiline(&mut self.seq_text)
                        .desired_width(f32::INFINITY)
                        .desired_rows(8),
                );
                if ui.button("Analyze").clicked() {
                    self.run_sequencer();
                }
            }
            Surface::MatchReplace => self.matchreplace_surface(ui),
            Surface::Scope => {
                ui.heading("Scope check");
                ui.add(
                    egui::TextEdit::singleline(&mut self.url)
                        .hint_text("http://169.254.169.254/")
                        .desired_width(f32::INFINITY),
                );
                if ui.button("Check").clicked() {
                    self.run_scope();
                }
            }
            Surface::Payloads => {
                ui.heading("Payloads");
                ui.label("Built-in packs — for AUTHORIZED testing only.");
                if ui.button("Load").clicked() {
                    self.run_payloads();
                }
            }
            Surface::Import => {
                ui.heading("Import traffic");
                ui.label("Preview or store a HAR or Burp items XML archive of up to 4 MiB.");
                ui.label("Path");
                ui.add(
                    egui::TextEdit::singleline(&mut self.import_path).desired_width(f32::INFINITY),
                );
                ui.label("…or paste content");
                ui.add(
                    egui::TextEdit::multiline(&mut self.import_content)
                        .desired_width(f32::INFINITY)
                        .desired_rows(6),
                );
                ui.checkbox(&mut self.import_save, "store exchanges");
                if ui
                    .add_enabled(
                        self.archive_pending.is_none(),
                        egui::Button::new(if self.import_save {
                            "Import exchanges"
                        } else {
                            "Preview archive"
                        }),
                    )
                    .clicked()
                {
                    self.run_import(ui.ctx());
                }
            }
            Surface::ActiveScan => self.active_scan_surface(ui),
            Surface::AnalyzeJs => self.analyze_js_surface(ui),
            Surface::Ai => self.ai_surface(ui),
            Surface::Proxy => self.proxy_surface(ui),
            Surface::Browser => self.browser_surface(ui),
            Surface::Plugins => self.plugins_surface(ui),
            _ => unreachable!(),
        }

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);
        self.output_ui(ui);
    }

    fn proxy_surface(&mut self, ui: &mut egui::Ui) {
        ui.heading("Intercepting proxy");
        ui.label(
            "Point your browser's HTTP and HTTPS proxy at the listen address. Every request is \
             scope- and policy-gated (the same path as the rest of Camio) and captured to this \
             workspace tagged source=proxy. HTTPS is blind-relayed (fingerprint-true) unless you \
             enable TLS interception.",
        );
        ui.add_space(8.0);

        let running = self
            .proxy_handle
            .as_ref()
            .map(camio_proxy::ProxyHandle::is_running)
            .unwrap_or(false);

        ui.horizontal(|ui| {
            ui.label("Listen address:");
            ui.add_enabled(
                !running,
                egui::TextEdit::singleline(&mut self.proxy_listen).desired_width(170.0),
            );
        });
        ui.add_enabled(
            !running,
            egui::Checkbox::new(
                &mut self.proxy_tls,
                "Decrypt HTTPS (TLS interception — fingerprint-CHANGING; import the CA first)",
            ),
        );
        ui.add_enabled(
            !running,
            egui::Checkbox::new(
                &mut self.proxy_auto_scan,
                "Auto-scan in-scope traffic (passive checks → Findings; out-of-scope is never tested)",
            ),
        );

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if running {
                if ui.button("⏹ Stop").clicked() {
                    self.stop_proxy();
                }
                if let Some(h) = &self.proxy_handle {
                    ui.label(
                        egui::RichText::new(format!("● running on {}", h.local_addr()))
                            .color(egui::Color32::from_rgb(120, 200, 120)),
                    );
                }
            } else if ui.button("▶ Start").clicked() {
                self.start_proxy();
            }
            if ui.button("Export CA…").clicked() {
                self.export_proxy_ca();
            }
        });

        ui.label(
            egui::RichText::new(format!("CA directory: {}", self.proxy_ca_dir.display()))
                .weak()
                .size(11.0),
        );

        if !self.proxy_status.is_empty() {
            ui.add_space(6.0);
            ui.label(&self.proxy_status);
        }

        self.intercept_ui(ui);

        ui.add_space(8.0);
        ui.separator();
        let captures = self.proxy_sink.snapshot();
        ui.label(format!("Captured this session: {}", captures.len()));
        egui::ScrollArea::vertical()
            .max_height(260.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for ex in captures.iter().rev().take(100) {
                    let status = ex.response.as_ref().map(|r| r.status).unwrap_or(0);
                    let scope = ex.scope.map(|d| d.as_str()).unwrap_or("?");
                    ui.monospace(format!(
                        "[{scope}] {:<6} {} -> {}",
                        ex.request.method,
                        truncate(&ex.request.url, 72),
                        status
                    ));
                }
            });

        // Keep the live count/table refreshing while the proxy runs.
        if running {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(500));
        }
    }

    /// Burp's Proxy ▸ Intercept: hold a request, edit it, then Forward or Drop.
    fn intercept_ui(&mut self, ui: &mut egui::Ui) {
        let running = self
            .proxy_handle
            .as_ref()
            .map(camio_proxy::ProxyHandle::is_running)
            .unwrap_or(false);

        ui.add_space(8.0);
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Intercept").strong());
            let mut on = self.proxy_intercept;
            let label = if on { "on" } else { "off" };
            if ui.toggle_value(&mut on, label).changed() {
                self.proxy_intercept = on;
                if running {
                    self.proxy_queue.set_active(on);
                }
            }
            ui.label(
                egui::RichText::new(format!("{} held", self.proxy_queue.pending_count())).weak(),
            );
        });

        if !running {
            ui.label(
                egui::RichText::new("Start the proxy, then toggle Intercept to hold requests.")
                    .weak()
                    .size(11.0),
            );
            return;
        }
        if !self.proxy_intercept {
            ui.label(
                egui::RichText::new("Intercept is off — requests pass straight through.")
                    .weak()
                    .size(11.0),
            );
            return;
        }

        // Load the next held request into the editor if nothing is loaded.
        if self.icept_id.is_none() {
            if let Some(Pending::Request { id, request }) = self.proxy_queue.next_pending() {
                self.icept_id = Some(id);
                self.icept_method = request.method.clone();
                self.icept_url = request.url.clone();
                self.icept_headers = request
                    .headers
                    .iter()
                    .map(|h| format!("{}: {}", h.name, h.value))
                    .collect::<Vec<_>>()
                    .join("\n");
                self.icept_body = request.body.as_text().to_string();
            }
        }

        match self.icept_id {
            None => {
                ui.label(egui::RichText::new("Waiting for a request…").weak());
            }
            Some(id) => {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("Method");
                    ui.add(egui::TextEdit::singleline(&mut self.icept_method).desired_width(74.0));
                    ui.label("URL");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.icept_url)
                            .desired_width(f32::INFINITY),
                    );
                });
                ui.label(egui::RichText::new("Headers").small().weak());
                ui.add(
                    egui::TextEdit::multiline(&mut self.icept_headers)
                        .code_editor()
                        .desired_rows(5)
                        .desired_width(f32::INFINITY),
                );
                ui.label(egui::RichText::new("Body").small().weak());
                ui.add(
                    egui::TextEdit::multiline(&mut self.icept_body)
                        .code_editor()
                        .desired_rows(4)
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.button("➡ Forward").clicked() {
                        self.resolve_intercept(id, true);
                    }
                    if ui.button("✖ Drop").clicked() {
                        self.resolve_intercept(id, false);
                    }
                });
            }
        }
        // Poll for newly held requests while intercepting.
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(250));
    }

    fn resolve_intercept(&mut self, id: u64, forward: bool) {
        let decision = if forward {
            let mut req = HttpRequest::get(self.icept_url.trim());
            req.method = self.icept_method.trim().to_string();
            for line in self.icept_headers.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Some((n, v)) = line.split_once(':') {
                    req.headers.push(n.trim().to_string(), v.trim().to_string());
                }
            }
            req.body = Body::from_text(self.icept_body.clone());
            RequestDecision::Forward(req)
        } else {
            RequestDecision::Drop
        };
        self.proxy_queue.resolve_request(id, decision);
        self.icept_id = None;
        self.icept_method.clear();
        self.icept_url.clear();
        self.icept_headers.clear();
        self.icept_body.clear();
    }

    fn start_proxy(&mut self) {
        let policy = Policy {
            require_confirmation: false,
            ..self.cfg.policy
        };
        let config = ProxyConfig {
            scope: self.cfg.scope.clone(),
            policy,
            rules: RuleSet::new(),
            tls_intercept: self.proxy_tls,
            ..ProxyConfig::default()
        };

        let forwarder = match EngineForwarder::spawn(self.cfg.profile.clone()) {
            Ok(f) => Arc::new(f),
            Err(e) => {
                self.proxy_status = format!("Could not start the matched engine: {e}");
                return;
            }
        };
        let store = match Store::open(&self.cfg.db) {
            Ok(s) => s,
            Err(e) => {
                self.proxy_status = format!("Could not open the capture store: {e}");
                return;
            }
        };
        let sink: Arc<dyn ExchangeSink> = Arc::new(AppProxySink {
            live: self.proxy_sink.clone(),
            store: Mutex::new(store),
            auto_scan: self.proxy_auto_scan,
        });
        // The intercept queue is always the interceptor; its active flag decides
        // whether requests are held (toggle it live without restarting).
        self.proxy_queue.set_active(self.proxy_intercept);
        let interceptor: Arc<dyn Interceptor> = self.proxy_queue.clone();
        let listener = match TcpListener::bind(&self.proxy_listen) {
            Ok(l) => l,
            Err(e) => {
                self.proxy_status = format!("Could not bind {}: {e}", self.proxy_listen);
                return;
            }
        };

        let mut server = ProxyServer::new(config, forwarder, sink, interceptor);
        if self.proxy_tls {
            match CertAuthority::load_or_create(&self.proxy_ca_dir) {
                Ok(ca) => server = server.with_ca(Arc::new(ca)),
                Err(e) => {
                    self.proxy_status = format!("Could not load the proxy CA: {e}");
                    return;
                }
            }
        }

        match server.spawn(listener) {
            Ok(handle) => {
                self.proxy_status = format!(
                    "Listening on {}{}. Set your browser proxy to it.",
                    handle.local_addr(),
                    if self.proxy_tls {
                        " — TLS interception ON (fingerprint-changing)"
                    } else {
                        " — HTTPS blind-relayed (fingerprint-true)"
                    }
                );
                self.proxy_handle = Some(handle);
            }
            Err(e) => self.proxy_status = format!("Could not serve: {e}"),
        }
    }

    fn stop_proxy(&mut self) {
        // Release any parked request so blocked connection threads can finish.
        self.proxy_queue.set_active(false);
        self.icept_id = None;
        if let Some(handle) = self.proxy_handle.take() {
            handle.stop_and_join();
            self.proxy_status = "Proxy stopped.".to_string();
        }
    }

    fn export_proxy_ca(&mut self) {
        match CertAuthority::load_or_create(&self.proxy_ca_dir) {
            Ok(ca) => {
                let path = self.proxy_ca_dir.join("camio-ca.pem");
                match std::fs::write(&path, ca.ca_cert_pem()) {
                    Ok(()) => {
                        self.proxy_status = format!(
                            "CA written to {}. Import it into your browser/OS trust store to \
                             decrypt HTTPS.",
                            path.display()
                        );
                    }
                    Err(e) => self.proxy_status = format!("Could not write the CA: {e}"),
                }
            }
            Err(e) => self.proxy_status = format!("Could not create the CA: {e}"),
        }
    }

    fn fingerprint_surface(&mut self, ui: &mut egui::Ui) {
        ui.heading("Fingerprint ported to sent requests");
        ui.label("The matched request engine derives this JA3/JA4 · HTTP/2 · header-order profile from the Camoufox build, so tool traffic and the browser share one identity (plan §6.2–6.3). The same profile is written to the browser's about:config on launch.");
        ui.add_space(8.0);
        let spec = FingerprintSpec::from_profile(&self.cfg.profile);
        if ui.button("Copy as JSON to output").clicked() {
            self.out = Output::Text(serde_json::to_string_pretty(&spec).unwrap_or_default());
        }
        ui.add_space(6.0);
        egui::Grid::new("fp")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Family / version");
                ui.monospace(format!("{}/{}", spec.family.as_str(), spec.major_version));
                ui.end_row();
                ui.label("User-Agent");
                ui.monospace(&spec.user_agent);
                ui.end_row();
                ui.label("Accept-Language");
                ui.monospace(&spec.accept_language);
                ui.end_row();
                ui.label("Header order");
                ui.monospace(spec.header_order.join(", "));
                ui.end_row();
                ui.label("H2 pseudo-order");
                ui.monospace(spec.http2.pseudo_header_order.join(" "));
                ui.end_row();
                ui.label("H2 window");
                ui.monospace(spec.http2.initial_window_size.to_string());
                ui.end_row();
            });
    }

    fn fuzz_surface(&mut self, ui: &mut egui::Ui) {
        ui.heading("Automate / Fuzz");
        ui.label("Mark insertion points with §…§ (e.g. id=§1§). Plan shows the projected count; Run sends (in-scope + confirm).");
        self.request_builder(ui);
        ui.horizontal(|ui| {
            ui.label("Attack");
            egui::ComboBox::from_id_salt("attack")
                .selected_text(self.attack.label())
                .show_ui(ui, |ui| {
                    for a in [
                        AttackKind::Sniper,
                        AttackKind::BatteringRam,
                        AttackKind::Pitchfork,
                        AttackKind::ClusterBomb,
                    ] {
                        ui.selectable_value(&mut self.attack, a, a.label());
                    }
                });
            ui.label("Packs");
            ui.add(
                egui::TextEdit::singleline(&mut self.payloads)
                    .hint_text("sqli,xss")
                    .desired_width(150.0),
            );
            ui.label("Budget");
            ui.add(egui::TextEdit::singleline(&mut self.budget).desired_width(70.0));
        });
        ui.checkbox(&mut self.confirm, "confirm (run the active test)");
        ui.horizontal(|ui| {
            if ui.button("Plan").clicked() {
                self.run_fuzz_plan();
            }
            if ui.button("Run").clicked() {
                self.run_fuzz();
            }
        });
    }

    fn matchreplace_surface(&mut self, ui: &mut egui::Ui) {
        ui.heading("Match & Replace");
        ui.label("Rewrite an outgoing request. Build the request below, then a literal find/replace on the chosen part.");
        self.request_builder(ui);
        ui.horizontal(|ui| {
            ui.label("Part");
            egui::ComboBox::from_id_salt("mr_target")
                .selected_text(self.mr_target.label())
                .show_ui(ui, |ui| {
                    for t in [
                        MrTarget::Url,
                        MrTarget::Method,
                        MrTarget::Body,
                        MrTarget::Header,
                    ] {
                        ui.selectable_value(&mut self.mr_target, t, t.label());
                    }
                });
            if self.mr_target == MrTarget::Header {
                ui.add(
                    egui::TextEdit::singleline(&mut self.mr_header)
                        .hint_text("header name")
                        .desired_width(140.0),
                );
            }
        });
        ui.horizontal(|ui| {
            ui.label("Find");
            ui.add(egui::TextEdit::singleline(&mut self.mr_find).desired_width(200.0));
            ui.label("Replace");
            ui.add(egui::TextEdit::singleline(&mut self.mr_replace).desired_width(200.0));
        });
        if ui.button("Preview rewrite").clicked() {
            self.run_matchreplace();
        }
    }

    fn ai_surface(&mut self, ui: &mut egui::Ui) {
        ui.heading("AI assistant");
        let ready = self.ai_config.is_ready();
        ui.horizontal(|ui| {
            ui.label(format!(
                "provider: {}  ·  model: {}",
                self.ai_config.provider, self.ai_config.model
            ));
            if ready {
                ui.colored_label(egui::Color32::from_rgb(63, 185, 80), "ready");
            } else {
                ui.colored_label(
                    egui::Color32::from_rgb(210, 153, 34),
                    "no key — set NVIDIA_API_KEY / OPENAI_API_KEY (Ollama needs none)",
                );
            }
        });
        ui.label("Bring your own key. Nothing is sent to a model unless you ask; no telemetry. Set CAMIO_AI_PROVIDER / CAMIO_AI_MODEL to choose.");
        ui.add(
            egui::TextEdit::multiline(&mut self.ai_prompt)
                .hint_text("Ask about your testing, or describe a query for NL->CamioQL…")
                .desired_width(f32::INFINITY)
                .desired_rows(4),
        );
        let busy = self.ai_pending.is_some();
        ui.horizontal(|ui| {
            if ui.add_enabled(!busy, egui::Button::new("Ask")).clicked() {
                let msgs = vec![
                    Message::system("You are a concise, precise web-security testing assistant. Be specific; avoid filler."),
                    Message::user(self.ai_prompt.clone()),
                ];
                self.start_ai(msgs);
            }
            if ui.add_enabled(!busy, egui::Button::new("NL -> CamioQL")).clicked() {
                self.start_ai(camio_ai::nl_to_camioql(&self.ai_prompt));
            }
            if ui.add_enabled(!busy, egui::Button::new("Explain latest exchange")).clicked() {
                match self.open().and_then(|s| s.recent(1).map_err(|e| e.to_string())) {
                    Ok(v) if !v.is_empty() => self.start_ai(camio_ai::explain_exchange(&v[0])),
                    Ok(_) => self.out = Output::Error("no exchanges in history yet".into()),
                    Err(e) => self.out = Output::Error(e),
                }
            }
            if ui.add_enabled(!busy, egui::Button::new("Suggest tests")).clicked() {
                let context = self.findings_context();
                self.start_ai(camio_ai::suggest_tests(&context));
            }
            if busy {
                ui.spinner();
            }
        });
    }

    fn findings_context(&self) -> String {
        match self
            .open()
            .and_then(|s| s.list_findings().map_err(|e| e.to_string()))
        {
            Ok(fs) if !fs.is_empty() => {
                let mut s = String::from("Findings recorded so far:\n");
                for f in fs.iter().take(50) {
                    s.push_str(&format!(
                        "- [{:?}/{:?}] {}\n",
                        f.severity, f.confidence, f.title
                    ));
                }
                s
            }
            _ => "No findings recorded yet. Suggest an initial web-app testing plan.".into(),
        }
    }

    /// Spawn the AI request on a background thread so the window stays responsive.
    fn start_ai(&mut self, messages: Vec<Message>) {
        if !self.ai_config.is_ready() {
            self.out = Output::Error(format!(
                "AI not configured: provider {} has no API key. Set NVIDIA_API_KEY (NVIDIA NIM) or OPENAI_API_KEY, or run a local Ollama.",
                self.ai_config.provider
            ));
            return;
        }
        if messages.iter().all(|m| m.content.trim().is_empty()) {
            self.out = Output::Error("enter a prompt first".into());
            return;
        }
        let (tx, rx) = mpsc::channel();
        let cfg = self.ai_config.clone();
        std::thread::spawn(move || {
            let result = AiClient::new(cfg)
                .map_err(|e| e.to_string())
                .and_then(|c| c.chat(&messages).map_err(|e| e.to_string()));
            let _ = tx.send(result);
        });
        self.ai_pending = Some(rx);
        self.out = Output::Text("Thinking…".to_string());
    }

    fn active_scan_surface(&mut self, ui: &mut egui::Ui) {
        ui.heading("Active scan");
        ui.colored_label(
            egui::Color32::from_rgb(210, 153, 34),
            "Active testing SENDS probe requests (reflected XSS, error-based SQLi, open redirect). In-scope + confirm required; launch with --allow-active.",
        );
        self.request_builder(ui);
        ui.checkbox(&mut self.confirm, "confirm (run the active test)");
        ui.checkbox(&mut self.active_save, "save findings");
        if ui.button("Run active scan").clicked() {
            self.run_active_scan();
        }
    }

    fn run_active_scan(&mut self) {
        let res = (|| {
            let base = self.built_request()?;
            let decision = self
                .cfg
                .scope
                .decide(&HttpExchange::new(base.clone(), Source::Scanner));
            match self
                .cfg
                .policy
                .gate(ActionClass::Active, decision, self.confirm)
            {
                PolicyOutcome::Deny(r) => return Err(format!("refused: {r}")),
                PolicyOutcome::NeedsConfirmation(r) => {
                    return Err(format!(
                        "{r}. Tick 'confirm' to run (scope {}).",
                        decision.as_str()
                    ))
                }
                PolicyOutcome::Allow => {}
            }
            let store = std::cell::RefCell::new(self.open()?);
            let engine = self.engine.as_ref();
            let scope = &self.cfg.scope;
            let findings = {
                let send = |req: HttpRequest| -> Option<HttpExchange> {
                    if !scope
                        .decide(&HttpExchange::new(req.clone(), Source::Scanner))
                        .is_sendable()
                    {
                        return None; // never send out of scope (plan §16)
                    }
                    match engine.send(req, Source::Scanner) {
                        Ok(ex) => {
                            let _ = store.borrow_mut().insert(&ex);
                            Some(ex)
                        }
                        Err(_) => None,
                    }
                };
                camio_active::run_active(&base, &send)
            };
            if self.active_save {
                for f in &findings {
                    let _ = store.borrow_mut().insert_finding(f);
                }
            }
            Ok::<_, String>(findings)
        })();
        self.out = match res {
            Ok(findings) if findings.is_empty() => {
                Output::Text("active scan complete — no issues confirmed".into())
            }
            Ok(findings) => Output::Table {
                cols: vec!["Severity".into(), "Confidence".into(), "Title".into()],
                rows: findings
                    .iter()
                    .map(|f| {
                        vec![
                            format!("{:?}", f.severity).to_lowercase(),
                            format!("{:?}", f.confidence).to_lowercase(),
                            f.title.clone(),
                        ]
                    })
                    .collect(),
            },
            Err(e) => Output::Error(e),
        };
    }

    fn analyze_js_surface(&mut self, ui: &mut egui::Ui) {
        ui.heading("Analyze JS / secrets");
        ui.label("Passively extract hard-coded secrets and endpoints from a JavaScript (or any) blob — no traffic sent.");
        ui.add(
            egui::TextEdit::multiline(&mut self.js_blob)
                .hint_text("paste JS / a response body…")
                .desired_width(f32::INFINITY)
                .desired_rows(10),
        );
        if ui.button("Analyze").clicked() {
            let a = camio_scan::analyze_js(&self.js_blob);
            self.out = if a.secrets.is_empty() && a.endpoints.is_empty() {
                Output::Text("(nothing found)".into())
            } else {
                Output::Text(format!(
                    "secrets ({}): {}\n\nendpoints ({}):\n{}",
                    a.secrets.len(),
                    if a.secrets.is_empty() {
                        "none".into()
                    } else {
                        a.secrets.join(", ")
                    },
                    a.endpoints.len(),
                    a.endpoints.join("\n")
                ))
            };
        }
    }

    fn poll_ai(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.ai_pending {
            match rx.try_recv() {
                Ok(result) => {
                    self.out = match result {
                        Ok(t) => Output::Text(t),
                        Err(e) => Output::Error(e),
                    };
                    self.ai_pending = None;
                }
                Err(mpsc::TryRecvError::Empty) => ctx.request_repaint(),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.out = Output::Error("AI request failed (worker thread ended)".into());
                    self.ai_pending = None;
                }
            }
        }
    }

    /// Run Nuclei (external) on a background thread against an in-scope target,
    /// saving the normalized findings to the workspace store.
    fn start_nuclei(&mut self, ctx: &egui::Context) {
        let url = self.nuclei_url.trim().to_string();
        if url.is_empty() {
            return;
        }
        let decision = self
            .cfg
            .scope
            .decide(&HttpExchange::new(HttpRequest::get(&url), Source::Scanner));
        if !decision.is_sendable() {
            self.out = Output::Error(format!(
                "target is {} — only in-scope targets may be scanned",
                decision.as_str()
            ));
            return;
        }
        let db = self.cfg.db.clone();
        let (tx, rx) = mpsc::channel();
        self.nuclei_pending = Some(rx);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let opts = camio_integrations::NucleiOptions {
                timeout: std::time::Duration::from_secs(300),
                ..Default::default()
            };
            let res = match camio_integrations::run_nuclei(std::slice::from_ref(&url), &opts) {
                Ok(raw) => {
                    let findings = camio_integrations::nuclei_to_findings(&raw);
                    match Store::open(&db) {
                        Ok(mut store) => store
                            .insert_findings(&findings)
                            .map(|_| findings.len())
                            .map_err(|e| e.to_string()),
                        Err(e) => Err(e.to_string()),
                    }
                }
                Err(camio_integrations::IntegrationError::NotInstalled(_)) => {
                    Err("nuclei is not installed or not on PATH".to_string())
                }
                Err(e) => Err(e.to_string()),
            };
            let _ = tx.send(res);
            ctx.request_repaint();
        });
    }

    fn poll_nuclei(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.nuclei_pending {
            match rx.try_recv() {
                Ok(res) => {
                    self.out = match res {
                        Ok(n) => Output::Text(format!(
                            "Nuclei finished: {n} finding(s) saved to {}",
                            self.cfg.db.display()
                        )),
                        Err(e) => Output::Error(format!("Nuclei: {e}")),
                    };
                    self.nuclei_pending = None;
                }
                Err(mpsc::TryRecvError::Empty) => ctx.request_repaint(),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.out = Output::Error("Nuclei run failed (worker thread ended)".into());
                    self.nuclei_pending = None;
                }
            }
        }
    }

    fn browser_surface(&mut self, ui: &mut egui::Ui) {
        ui.heading("Open in managed browser");
        ui.label("Launches a LibreWolf / Camoufox (Firefox-fork) browser with Camio's fingerprint profile applied, so browsing and tool traffic share one identity. Marionette makes the browser agent-drivable.");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("URL");
            ui.add(
                egui::TextEdit::singleline(&mut self.url)
                    .hint_text("https://example.org/")
                    .desired_width(f32::INFINITY),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Browser binary (blank = auto-detect)");
            ui.add(
                egui::TextEdit::singleline(&mut self.browser_bin)
                    .hint_text("librewolf")
                    .desired_width(260.0),
            );
        });
        ui.checkbox(
            &mut self.marionette,
            "enable automation (marionette, 127.0.0.1:2828)",
        );
        if ui.button("Open in browser").clicked() {
            let u = self.url.clone();
            self.open_in_browser(u);
        }
    }

    fn plugins_surface(&mut self, ui: &mut egui::Ui) {
        ui.heading("Plugins");
        ui.colored_label(egui::Color32::from_rgb(210, 153, 34), "A plugin runs an arbitrary command with your privileges — review the manifest before running.");
        ui.horizontal(|ui| {
            ui.label("Directory");
            ui.add(egui::TextEdit::singleline(&mut self.plugins_dir).desired_width(260.0));
            if ui.button("Reload").clicked() {
                self.reload_plugins();
            }
        });
        ui.add_space(6.0);
        if self.plugins.is_empty() {
            ui.weak(
                "No plugins found. Add a subfolder with a plugin.json (see plugins/README.md).",
            );
        } else {
            for (i, p) in self.plugins.iter().enumerate() {
                let selected = self.selected_plugin == Some(i);
                if ui
                    .selectable_label(
                        selected,
                        format!("{}  —  {}", p.manifest.name, p.manifest.kind),
                    )
                    .clicked()
                {
                    self.selected_plugin = Some(i);
                }
            }
            if let Some(p) = self.selected_plugin.and_then(|i| self.plugins.get(i)) {
                ui.add_space(4.0);
                ui.monospace(format!("$ {}", p.command_display()));
                ui.weak(&p.manifest.description);
            }
        }
        ui.add_space(6.0);
        ui.label("Input (sent to the plugin's stdin)");
        ui.add(
            egui::TextEdit::multiline(&mut self.plugin_input)
                .desired_width(f32::INFINITY)
                .desired_rows(4),
        );
        if ui.button("Run plugin").clicked() {
            self.run_plugin();
        }
    }

    fn settings_surface(&mut self, ui: &mut egui::Ui) {
        ui.heading("Workspace settings");
        self.workspace_settings(ui);
        ui.separator();
        ui.label("Themes apply live. Save theme to keep your preferences.");
        ui.add_space(8.0);
        ui.label(egui::RichText::new("THEME").small().weak());
        ui.horizontal(|ui| {
            ui.label("Preset");
            egui::ComboBox::from_id_salt("preset")
                .selected_text(self.theme.name.clone())
                .show_ui(ui, |ui| {
                    for p in Theme::presets() {
                        if ui
                            .selectable_label(self.theme.name == p.name, &p.name)
                            .clicked()
                        {
                            let motion = self.theme.motion;
                            self.theme = p;
                            self.theme.motion = motion;
                        }
                    }
                });
            ui.checkbox(&mut self.theme.dark, "Dark");
            let mut reduce_motion = !self.theme.motion;
            if ui.checkbox(&mut reduce_motion, "Reduce motion").changed() {
                self.theme.motion = !reduce_motion;
            }
        });
        ui.horizontal(|ui| {
            ui.label("Accent");
            ui.color_edit_button_srgb(&mut self.theme.accent);
            ui.label("Window");
            ui.color_edit_button_srgb(&mut self.theme.window);
            ui.label("Panel");
            ui.color_edit_button_srgb(&mut self.theme.panel);
            ui.label("Text");
            ui.color_edit_button_srgb(&mut self.theme.text);
        });
        ui.add(egui::Slider::new(&mut self.theme.rounding, 0.0..=16.0).text("corner rounding"));
        ui.add_space(6.0);
        ui.label(egui::RichText::new("BACKGROUND IMAGE").small().weak());
        let mut bg = self
            .theme
            .bg_image
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        ui.horizontal(|ui| {
            ui.label("Path");
            if ui
                .add(
                    egui::TextEdit::singleline(&mut bg)
                        .hint_text("/path/to/image.png")
                        .desired_width(320.0),
                )
                .changed()
            {
                self.theme.bg_image = if bg.trim().is_empty() {
                    None
                } else {
                    Some(PathBuf::from(bg.trim()))
                };
            }
            if ui.button("Clear").clicked() {
                self.theme.bg_image = None;
            }
        });
        ui.add(egui::Slider::new(&mut self.theme.bg_opacity, 0.0..=1.0).text("opacity"));
        ui.add_space(6.0);
        ui.label(egui::RichText::new("PLUGINS & BROWSER").small().weak());
        ui.horizontal(|ui| {
            ui.label("Plugins dir");
            ui.add(egui::TextEdit::singleline(&mut self.plugins_dir).desired_width(260.0));
            if ui.button("Reload").clicked() {
                self.reload_plugins();
            }
        });
        ui.horizontal(|ui| {
            ui.label("Browser binary");
            ui.add(
                egui::TextEdit::singleline(&mut self.browser_bin)
                    .hint_text("librewolf")
                    .desired_width(260.0),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Engine install root");
            ui.add(egui::TextEdit::singleline(&mut self.install_root).desired_width(260.0));
        });
        ui.add_space(8.0);
        if ui.button("Save theme").clicked() {
            self.out = match theme::save(&self.theme) {
                Ok(()) => {
                    Output::Text(format!("saved theme to {}", theme::config_path().display()))
                }
                Err(e) => Output::Error(e),
            };
        }
    }

    fn request_builder(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Method");
            ui.add(egui::TextEdit::singleline(&mut self.method).desired_width(80.0));
            ui.label("URL");
            ui.add(egui::TextEdit::singleline(&mut self.url).desired_width(f32::INFINITY));
        });
        ui.label("Headers (one per line: Name: Value)");
        ui.add(
            egui::TextEdit::multiline(&mut self.headers)
                .desired_width(f32::INFINITY)
                .desired_rows(3),
        );
        ui.label("Body");
        ui.add(
            egui::TextEdit::multiline(&mut self.body)
                .desired_width(f32::INFINITY)
                .desired_rows(3),
        );
    }

    fn output_ui(&self, ui: &mut egui::Ui) {
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| match &self.out {
                Output::None => {
                    ui.weak("Results appear here.");
                }
                Output::Error(e) => {
                    ui.colored_label(egui::Color32::from_rgb(248, 81, 73), e);
                }
                Output::Text(t) => {
                    ui.label(egui::RichText::new(t).monospace());
                }
                Output::Table { cols, rows } => {
                    if rows.is_empty() {
                        ui.weak("(no rows)");
                        return;
                    }
                    egui::Grid::new("out_table")
                        .striped(true)
                        .num_columns(cols.len())
                        .show(ui, |ui| {
                            for c in cols {
                                ui.label(egui::RichText::new(c).strong());
                            }
                            ui.end_row();
                            for row in rows {
                                for cell in row {
                                    ui.label(egui::RichText::new(cell).monospace());
                                }
                                ui.end_row();
                            }
                        });
                }
            });
    }

    fn sync_bg(&mut self, ctx: &egui::Context) {
        match &self.theme.bg_image {
            Some(path) => {
                let need = self
                    .bg_texture
                    .as_ref()
                    .map(|(p, _)| p != path)
                    .unwrap_or(true);
                if need {
                    self.bg_texture = Some((path.clone(), theme::load_texture(ctx, path).ok()));
                }
            }
            None => self.bg_texture = None,
        }
    }

    fn paint_bg(&self, ui: &egui::Ui) {
        if let Some((_, Some(tex))) = &self.bg_texture {
            let rect = ui.max_rect();
            let alpha = (self.theme.bg_opacity.clamp(0.0, 1.0) * 255.0) as u8;
            let tint = egui::Color32::from_white_alpha(alpha);
            let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
            ui.painter().image(tex.id(), rect, uv, tint);
        }
    }
}

/// Capture sink for the in-app proxy: records live for the UI table and persists
/// each exchange to the workspace store (WAL + 5s busy-timeout make this safe
/// alongside the UI's reads). Store errors are logged, never fatal to capture.
struct AppProxySink {
    live: Arc<camio_proxy::VecSink>,
    store: Mutex<Store>,
    auto_scan: bool,
}

impl ExchangeSink for AppProxySink {
    fn record(&self, exchange: &HttpExchange) {
        self.live.record(exchange);
        if let Ok(mut store) = self.store.lock() {
            let id = match store.insert(exchange) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("proxy capture store error: {e}");
                    return;
                }
            };
            // Scope-aware automation: passively scan only in-scope traffic.
            if self.auto_scan
                && exchange.scope == Some(camio_core::ScopeDecision::InScope)
                && exchange.response.is_some()
            {
                let mut scanned = exchange.clone();
                scanned.id = id;
                let findings = camio_scan::scan_exchange(&scanned);
                if !findings.is_empty() {
                    if let Err(e) = store.insert_findings(&findings) {
                        eprintln!("proxy finding store error: {e}");
                    }
                }
            }
        }
    }
}

/// Truncate a string to `max` characters (char-safe), appending an ellipsis.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

/// Default directory for the proxy CA (matches the CLI's `camio proxy`).
fn default_proxy_ca_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("camio");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("camio");
    }
    PathBuf::from("camio-ca")
}

impl eframe::App for CamioApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.theme.apply(ctx);
        self.sync_bg(ctx);
        self.poll_ai(ctx);
        self.poll_nuclei(ctx);

        self.poll_archive();

        let panel = self.theme.panel_color();
        let accent = self.theme.accent_color();
        let line = ctx.style().visuals.window_stroke;
        egui::TopBottomPanel::top("status_bar")
            .frame(
                egui::Frame::none()
                    .fill(panel)
                    .stroke(line)
                    .inner_margin(egui::Margin::symmetric(15.0, 8.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (mark, _) =
                        ui.allocate_exact_size(egui::vec2(27.0, 27.0), egui::Sense::hover());
                    ui.painter()
                        .rect_filled(mark, 6.0, accent.gamma_multiply(0.25));
                    ui.painter()
                        .rect_stroke(mark, 6.0, egui::Stroke::new(1.0_f32, accent));
                    ui.painter().circle_stroke(
                        mark.center(),
                        6.0,
                        egui::Stroke::new(1.5_f32, accent),
                    );
                    ui.painter().circle_filled(mark.center(), 2.3, accent);
                    ui.label(egui::RichText::new("CAMIO").size(21.0).strong());
                    ui.separator();
                    ui.label(
                        egui::RichText::new(workbench::title(self.surface))
                            .size(15.0)
                            .color(accent),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Search tools   Ctrl K").clicked() {
                            self.toggle_command();
                        }
                    });
                });
            });
        egui::TopBottomPanel::bottom("bottom_bar")
            .frame(
                egui::Frame::none()
                    .fill(panel)
                    .stroke(line)
                    .inner_margin(egui::Margin::symmetric(15.0, 5.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new("LOCAL STORE").small().monospace());
                    ui.label(egui::RichText::new(self.cfg.db.display().to_string()).small());
                    if self.ai_pending.is_some() {
                        ui.separator();
                        ui.label("AI request running");
                    }
                    if self.archive_pending.is_some() {
                        ui.separator();
                        ui.label("Reading archive");
                    }
                });
            });
        egui::TopBottomPanel::top("toolbar")
            .frame(
                egui::Frame::none()
                    .fill(panel)
                    .stroke(line)
                    .inner_margin(egui::Margin::symmetric(13.0, 6.0)),
            )
            .show(ctx, |ui| self.nav_ui(ui));
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(self.theme.window_color())
                    .inner_margin(egui::Margin::same(19.0)),
            )
            .show(ctx, |ui| {
                self.paint_bg(ui);
                self.central_ui(ui);
            });
        self.inspector_ui(ctx);
        self.command_ui(ctx);
    }
}

/// Map a surface name (used by the `CAMIO_SURFACE` deep-link env var) to a
/// [`Surface`]. Unknown names return `None`.
fn surface_from_name(s: &str) -> Option<Surface> {
    Some(match s.trim().to_ascii_lowercase().as_str() {
        "status" | "overview" => Surface::Status,
        "workflows" | "workflow" => Surface::Workflows,
        "tasks" => Surface::Tasks,
        "library" => Surface::Library,
        "integrations" | "evidence" => Surface::Integrations,
        "fingerprint" => Surface::Fingerprint,
        "history" => Surface::History,
        "query" => Surface::Query,
        "sitemap" | "site map" => Surface::Sitemap,
        "inventory" | "assets" => Surface::Inventory,
        "replay" | "send" => Surface::Replay,
        "discover" => Surface::Discover,
        "fuzz" | "automate" => Surface::Fuzz,
        "scan" | "scanner" => Surface::Scan,
        "findings" => Surface::Findings,
        "convert" => Surface::Convert,
        "comparer" => Surface::Comparer,
        "jwt" => Surface::Jwt,
        "sequencer" => Surface::Sequencer,
        "matchreplace" | "match-replace" => Surface::MatchReplace,
        "scope" => Surface::Scope,
        "payloads" => Surface::Payloads,
        "import" => Surface::Import,
        "activescan" | "active" => Surface::ActiveScan,
        "analyzejs" | "js" => Surface::AnalyzeJs,
        "ai" => Surface::Ai,
        "proxy" => Surface::Proxy,
        "browser" => Surface::Browser,
        "plugins" => Surface::Plugins,
        "settings" => Surface::Settings,
        _ => return None,
    })
}

/// A copy of `req` with every §…§ marker removed (the baseline request).
fn strip_clean(req: &HttpRequest) -> HttpRequest {
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
