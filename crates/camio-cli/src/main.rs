//! `camio` — command-line entry point for the Camio workbench.
//!
//! Implemented surfaces (plan §15 Phase 1 foundations):
//!   * `camio engine info|unpack`     — manage the Camoufox engine
//!   * `camio fingerprint show|spec`  — render the anti-detection policy / matched-engine spec
//!   * `camio launch`                 — launch the managed browser with a policy
//!   * `camio send`                   — send a request via the fingerprint-matched engine
//!   * `camio query` / `history`      — CamioQL over stored history
//!   * `camio scope`                  — the one scope-decision path for a URL
//!   * `camio mcp serve`              — the local MCP server over stdio

mod proxy;
mod workbench;

use anyhow::{bail, Context, Result};
use camio_ai::{AiClient, AiConfig, Message};
use camio_automate::{AttackType, Baseline, Campaign, PayloadSet};
use camio_convert::Transform;
use camio_core::{
    ActionClass, Body, Finding, FindingId, FingerprintPolicy, FingerprintProfile, HttpExchange,
    HttpRequest, MatchReplaceRule, MatchTarget, Policy, PolicyOutcome, Query, RuleSet, Scope,
    ScopeRule, Severity, SiteMap, Source,
};
use camio_engine::{self as engine, Camoufox, LaunchOptions};
use camio_mcp::McpServer;
use camio_request::{matched_engine, FingerprintSpec};
use camio_store::Store;
use clap::{Parser, Subcommand, ValueEnum};
use std::cell::RefCell;
use std::io::Read as _;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "camio",
    version,
    about = "Fingerprint-transparent web security workbench"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage the Camoufox browser engine.
    Engine {
        #[command(subcommand)]
        action: EngineCmd,
    },
    /// Inspect the anti-detection fingerprint policy and matched-engine spec.
    Fingerprint {
        #[command(subcommand)]
        action: FpCmd,
    },
    /// Launch the managed browser with a fingerprint policy applied.
    Launch(LaunchArgs),
    /// Send a request through the fingerprint-matched request engine.
    Send(SendArgs),
    /// Run a CamioQL query over stored history.
    Query(QueryArgs),
    /// Show recent captured exchanges.
    History(HistoryArgs),
    /// Report the scope decision for a URL (the one shared scope path).
    Scope(ScopeArgs),
    /// Encode/decode/hash a value through a Convert pipeline (Convert/Decoder).
    Convert(ConvertArgs),
    /// Decode a JWT (header + payload) WITHOUT verifying its signature.
    Jwt(JwtArgs),
    /// Byte/line diff between two files (Comparer).
    Compare(CompareArgs),
    /// Unified diff between two stored exchanges' responses (or requests) (F09).
    Diff(DiffArgs),
    /// Run passive security checks over stored history (Scanner).
    Scan(ScanArgs),
    /// Triage stored findings: list them, or set a finding's status (F14).
    Findings(FindingsArgs),
    /// Organize exchanges with labels: add/remove/list/show (F18).
    Label(LabelArgs),
    /// Intruder-class fuzzing campaign over §-marked insertion points.
    Fuzz(FuzzArgs),
    /// Enumerate injectable inputs of a request (query/body/cookies/headers/JSON).
    Discover(DiscoverArgs),
    /// Import a Burp items XML export or a HAR archive into history.
    Import(ImportArgs),
    /// Estimate token randomness/entropy (Sequencer).
    Sequencer(SequencerArgs),
    /// Build a site map tree from stored history (Discover).
    Sitemap(SitemapArgs),
    /// List or show the built-in payload packs.
    Payloads(PayloadsArgs),
    /// Combine or chain payloads from multiple DB categories into one set.
    Combo(ComboArgs),
    /// Encode a payload set through one or more encodings (dynamic testing).
    Encode(EncodeArgs),
    /// AI-mediation guard (bind a session, verify a binding, authorize a chain).
    AiGuard {
        #[command(subcommand)]
        action: AiCmd,
    },
    /// Opt-in ACTIVE scan (reflected XSS, error-based SQLi, open redirect) via the matched engine.
    Activescan(ActiveArgs),
    /// Ask the optional AI assistant (NVIDIA NIM / OpenAI / Ollama; BYO key via env).
    Ai(AiArgs),
    /// Launch the native desktop app — every capability in one window.
    App(AppArgs),
    /// Launch the local web workbench and print its session URL.
    Ui(UiArgs),
    /// Run the intercepting HTTP/HTTPS proxy (scope-gated capture + Match & Replace).
    Proxy(proxy::ProxyArgs),
    /// Self-hosted OAST collector (a local Burp-Collaborator analog for blind callbacks).
    Oast(OastArgs),
    /// Run Nuclei (external) against an authorized target and normalize its findings.
    Nuclei(NucleiArgs),
    /// Crawl an authorized target (bounded, same-origin) through the matched engine.
    Crawl(CrawlArgs),
    /// Enumerate subdomains of a domain with subfinder (external, passive OSINT).
    Subfinder(SubfinderArgs),
    /// List external-tool integrations and whether each is installed.
    Integrations,
    /// Review stored traffic, import evidence, and manage the workspace.
    Workbench(workbench::Args),
    /// Verify checksums and evidence references in an exported review bundle.
    VerifyBundle { file: PathBuf },
    /// Write a consistent backup of a workspace database to a new file (F01).
    Backup {
        /// Destination path (must not already exist).
        dest: PathBuf,
        #[arg(long, default_value = "camio.db")]
        db: PathBuf,
    },
    /// Local MCP server.
    Mcp {
        #[command(subcommand)]
        action: McpCmd,
    },
}

#[derive(Subcommand)]
enum EngineCmd {
    /// Show the pinned Camoufox build, download URL and local install status.
    Info {
        #[arg(long, default_value = "vendor/camoufox/dist")]
        install_root: PathBuf,
    },
    /// Unpack a downloaded Camoufox zip.
    Unpack {
        #[arg(long, default_value = "vendor/camoufox/camoufox-lin-x86_64.zip")]
        zip: PathBuf,
        #[arg(long, default_value = "vendor/camoufox/dist")]
        dest: PathBuf,
    },
}

#[derive(Subcommand)]
enum FpCmd {
    /// Render a policy preset to prefs / engine config / full profile JSON.
    Show {
        #[arg(long, value_enum, default_value_t = Preset::Balanced)]
        preset: Preset,
        #[arg(long, value_enum, default_value_t = Format::UserJs)]
        format: Format,
        /// OS persona to present: windows|macos|linux (default windows).
        #[arg(long)]
        os: Option<String>,
    },
    /// Show the matched request engine's fingerprint spec derived from the profile.
    Spec {
        #[arg(long, value_enum, default_value_t = Preset::Balanced)]
        preset: Preset,
    },
}

#[derive(Subcommand)]
enum McpCmd {
    /// Serve the MCP protocol over stdio (loopback-free, no accounts/keys).
    Serve(McpServeArgs),
}

#[derive(Parser)]
struct LaunchArgs {
    #[arg(long, default_value = "vendor/camoufox/dist")]
    install_root: PathBuf,
    #[arg(long, default_value = "profiles/default")]
    profile: PathBuf,
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    /// OS persona to present: windows|macos|linux (default windows).
    #[arg(long)]
    os: Option<String>,
    /// Authorized target URL to open.
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    headless: bool,
    /// Build the command and print it, but do not launch.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Parser)]
struct SendArgs {
    /// Authorized target URL.
    url: String,
    #[arg(long, short = 'X', default_value = "GET")]
    method: String,
    /// Header "Name: Value" (repeatable).
    #[arg(long = "header", short = 'H')]
    headers: Vec<String>,
    /// Request body as a string.
    #[arg(long)]
    body: Option<String>,
    /// Read the request body from a file.
    #[arg(long)]
    body_file: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    /// Scope include rule in CamioQL (repeatable). With none, all non-guarded hosts are in scope.
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    /// Scope exclude rule in CamioQL (repeatable).
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    /// Lab mode: allow private/loopback/metadata destinations.
    #[arg(long)]
    allow_private: bool,
    /// Match & Replace rule applied to the outgoing request (repeatable).
    /// Format: `PART|FIND|REPLACE`, where PART is url|method|body|header=NAME.
    #[arg(long = "rewrite")]
    rewrites: Vec<String>,
    /// Actually send. Without this, prints a preview with the scope decision.
    #[arg(long)]
    confirm: bool,
    /// History database path.
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Print the full stored exchange as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct QueryArgs {
    /// CamioQL query, e.g. 'resp.code.gte:500 AND req.host.cont:"example"'.
    query: Option<String>,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    #[arg(long, default_value_t = 50)]
    limit: usize,
    /// Print full exchanges as JSON instead of a summary table.
    #[arg(long)]
    json: bool,
    /// Save the given query under this name (plan §F07), then run it.
    #[arg(long)]
    save: Option<String>,
    /// Run a previously saved query by name.
    #[arg(long)]
    saved: Option<String>,
    /// List saved searches and exit.
    #[arg(long)]
    list_saved: bool,
    /// Delete a saved search by name and exit.
    #[arg(long)]
    delete_saved: Option<String>,
}

#[derive(Parser)]
struct HistoryArgs {
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    #[arg(long, default_value_t = 50)]
    limit: usize,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct ScopeArgs {
    /// URL to evaluate.
    url: String,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
}

#[derive(Parser)]
struct McpServeArgs {
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Allow active (scan/fuzz) actions via MCP. Off by default.
    #[arg(long)]
    allow_active: bool,
    /// Use the no-network dry-run engine instead of the matched engine.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum Preset {
    Hardened,
    Balanced,
    Off,
}

impl Preset {
    fn policy(self) -> FingerprintPolicy {
        match self {
            Preset::Hardened => FingerprintPolicy::hardened(),
            Preset::Balanced => FingerprintPolicy::balanced(),
            Preset::Off => FingerprintPolicy::off(),
        }
    }
    fn label(self) -> &'static str {
        match self {
            Preset::Hardened => "hardened",
            Preset::Balanced => "balanced",
            Preset::Off => "off",
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum Format {
    /// Firefox `user.js` preferences (the reliable layer).
    UserJs,
    /// Camoufox engine-level fingerprint config (JSON).
    Camoufox,
    /// The full FingerprintProfile as JSON.
    Json,
}

pub(crate) fn profile_for(preset: Preset) -> FingerprintProfile {
    profile_for_os(preset, None)
}

/// Build a profile for a preset, optionally presenting a specific OS persona
/// (Camoufox/camofox-browser's `CAMOFOX_OS`). The persona's UA / platform / WebGL
/// are kept internally consistent for that OS.
pub(crate) fn profile_for_os(
    preset: Preset,
    os: Option<camio_core::BrowserOs>,
) -> FingerprintProfile {
    let os = os.unwrap_or(camio_core::BrowserOs::Windows);
    let mut p = FingerprintProfile::new(
        format!(
            "{}-firefox-{}-{}",
            os.as_str(),
            camio_core::ALIGNED_FIREFOX_MAJOR,
            preset.label()
        ),
        engine::PINNED_VERSION,
    );
    p.policy = preset.policy();
    p.persona = camio_core::Persona::for_os(os);
    p
}

/// Parse an optional `--os` value into a [`BrowserOs`].
pub(crate) fn parse_os(os: &Option<String>) -> Result<Option<camio_core::BrowserOs>> {
    match os {
        None => Ok(None),
        Some(s) => camio_core::BrowserOs::parse(s)
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("unknown --os `{s}` (use windows|macos|linux)")),
    }
}

/// Build a [`Scope`] from CLI include/exclude CamioQL rules.
pub(crate) fn build_scope(
    includes: &[String],
    excludes: &[String],
    allow_private: bool,
) -> Result<Scope> {
    let mut scope = Scope::new();
    if allow_private {
        scope = scope.allowing_private();
    }
    for q in includes {
        scope =
            scope.with_rule(ScopeRule::include(q).with_context(|| format!("include rule `{q}`"))?);
    }
    for q in excludes {
        scope =
            scope.with_rule(ScopeRule::exclude(q).with_context(|| format!("exclude rule `{q}`"))?);
    }
    Ok(scope)
}

fn parse_header(s: &str) -> Result<(String, String)> {
    let (name, value) = s
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("header must be 'Name: Value', got `{s}`"))?;
    Ok((name.trim().to_string(), value.trim().to_string()))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Engine { action } => engine_cmd(action),
        Command::Fingerprint { action } => fingerprint_cmd(action),
        Command::Launch(args) => launch_cmd(args),
        Command::Send(args) => send_cmd(args),
        Command::Query(args) => query_cmd(args),
        Command::History(args) => history_cmd(args),
        Command::Scope(args) => scope_cmd(args),
        Command::Convert(args) => convert_cmd(args),
        Command::Jwt(args) => jwt_cmd(args),
        Command::Compare(args) => compare_cmd(args),
        Command::Diff(args) => diff_cmd(args),
        Command::Scan(args) => scan_cmd(args),
        Command::Findings(args) => findings_cmd(args),
        Command::Label(args) => label_cmd(args),
        Command::Fuzz(args) => fuzz_cmd(args),
        Command::Discover(args) => discover_cmd(args),
        Command::Import(args) => import_cmd(args),
        Command::Sequencer(args) => sequencer_cmd(args),
        Command::Sitemap(args) => sitemap_cmd(args),
        Command::Payloads(args) => payloads_cmd(args),
        Command::Combo(args) => combo_cmd(args),
        Command::Encode(args) => encode_cmd(args),
        Command::AiGuard { action } => ai_guard_cmd(action),
        Command::Activescan(args) => activescan_cmd(args),
        Command::Ai(args) => ai_cmd(args),
        Command::App(args) => app_cmd(args),
        Command::Ui(args) => ui_cmd(args),
        Command::Proxy(args) => proxy::run(args),
        Command::Oast(args) => oast_cmd(args),
        Command::Nuclei(args) => nuclei_cmd(args),
        Command::Crawl(args) => crawl_cmd(args),
        Command::Subfinder(args) => subfinder_cmd(args),
        Command::Integrations => integrations_cmd(),
        Command::Workbench(args) => workbench::run(args),
        Command::VerifyBundle { file } => workbench::verify_bundle(&file),
        Command::Backup { dest, db } => {
            let store = open_store(&db)?;
            store.backup_to(&dest)?;
            println!("backed up {} → {}", db.display(), dest.display());
            Ok(())
        }
        Command::Mcp { action } => match action {
            McpCmd::Serve(args) => mcp_serve_cmd(args),
        },
    }
}

fn engine_cmd(action: EngineCmd) -> Result<()> {
    match action {
        EngineCmd::Info { install_root } => {
            println!("Camio engine");
            println!("  pinned build : {}", engine::PINNED_VERSION);
            match engine::asset_name() {
                Ok(a) => println!("  asset        : {a}"),
                Err(e) => println!("  asset        : (unsupported platform: {e})"),
            }
            if let Ok(url) = engine::download_url() {
                println!("  download url : {url}");
            }
            match engine::locate_binary(&install_root) {
                Some(bin) => println!("  installed    : yes -> {}", bin.display()),
                None => println!(
                    "  installed    : no (searched {}). Run `camio engine unpack`.",
                    install_root.display()
                ),
            }
            Ok(())
        }
        EngineCmd::Unpack { zip, dest } => {
            if !zip.exists() {
                bail!(
                    "zip not found: {}\nDownload it with:\n  curl -L -o {} {}",
                    zip.display(),
                    zip.display(),
                    engine::download_url().unwrap_or_else(|_| "<release-url>".into())
                );
            }
            println!("Unpacking {} -> {} ...", zip.display(), dest.display());
            let bin = engine::unpack(&zip, &dest).context("unpacking Camoufox")?;
            println!("Done. Binary: {}", bin.display());
            Ok(())
        }
    }
}

fn fingerprint_cmd(action: FpCmd) -> Result<()> {
    match action {
        FpCmd::Show { preset, format, os } => {
            let profile = profile_for_os(preset, parse_os(&os)?);
            match format {
                Format::UserJs => print!("{}", profile.to_user_js()),
                Format::Camoufox => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&profile.to_camoufox_config())?
                    )
                }
                Format::Json => println!("{}", serde_json::to_string_pretty(&profile)?),
            }
            Ok(())
        }
        FpCmd::Spec { preset } => {
            let profile = profile_for(preset);
            let spec = FingerprintSpec::from_profile(&profile);
            println!("{}", serde_json::to_string_pretty(&spec)?);
            Ok(())
        }
    }
}

fn launch_cmd(args: LaunchArgs) -> Result<()> {
    let cam = Camoufox::find(&args.install_root)?;
    let profile = profile_for_os(args.preset, parse_os(&args.os)?);
    let opts = LaunchOptions {
        url: args.url.clone(),
        headless: args.headless,
        dry_run: args.dry_run,
    };

    if args.dry_run {
        cam.prepare_profile(&args.profile, &profile)?;
        let cmd = cam.build_command(&args.profile, &profile, &opts);
        println!("Would launch: {:?}", cmd.get_program());
        for a in cmd.get_args() {
            println!("  arg: {}", a.to_string_lossy());
        }
        println!("  (+{} fingerprint env vars)", cmd.get_envs().count());
        println!(
            "  profile prefs written to {}",
            args.profile.join("user.js").display()
        );
        return Ok(());
    }

    println!(
        "Launching Camoufox ({}) with '{}' fingerprint policy...",
        engine::PINNED_VERSION,
        args.preset.label()
    );
    if let Some(mut child) = cam.launch(&args.profile, &profile, &opts)? {
        println!("Browser started (pid {}). Close it to exit.", child.id());
        let status = child.wait().context("waiting for browser")?;
        println!("Browser exited: {status}");
    }
    Ok(())
}

fn send_cmd(args: SendArgs) -> Result<()> {
    let profile = profile_for(args.preset);
    let scope = build_scope(&args.scope_include, &args.scope_exclude, args.allow_private)?;

    let mut req = HttpRequest::get(&args.url);
    req.method = args.method.clone();
    for h in &args.headers {
        let (n, v) = parse_header(h)?;
        req.headers.push(n, v);
    }
    if let Some(file) = &args.body_file {
        req.body = Body::from_bytes(
            std::fs::read(file).with_context(|| format!("reading {}", file.display()))?,
        );
    } else if let Some(body) = &args.body {
        req.body = Body::from_text(body.clone());
    }

    if !args.rewrites.is_empty() {
        let rules = build_ruleset(&args.rewrites)?;
        let n = rules.apply_to_request(&mut req);
        eprintln!(
            "applied {n} of {} match/replace rule(s) to the request",
            rules.len()
        );
    }

    let probe = HttpExchange::new(req.clone(), Source::Replay);
    let decision = scope.decide(&probe);
    let policy = Policy::safe();
    let spec = FingerprintSpec::from_profile(&profile);

    match policy.gate(ActionClass::Mutating, decision, args.confirm) {
        PolicyOutcome::Deny(reason) => {
            // Report the EFFECTIVE destination (after any --rewrite), which is
            // what was scope-decided and would be sent — not the typed URL.
            bail!(
                "refused: {reason} (destination {} is {})",
                req.url,
                decision.as_str()
            );
        }
        PolicyOutcome::NeedsConfirmation(reason) => {
            println!("Preview (not sent) — {reason}");
            println!("  method              : {}", req.method);
            println!("  url                 : {}", req.url);
            if req.url != args.url {
                println!(
                    "  (requested          : {} — changed by --rewrite)",
                    args.url
                );
            }
            println!("  scope decision      : {}", decision.as_str());
            println!("  fingerprint target  : {}", spec.target_label());
            println!("  profile             : {}", profile.name);
            println!("\nRe-run with --confirm to send.");
            Ok(())
        }
        PolicyOutcome::Allow => {
            let eng = matched_engine(&profile).context("building matched request engine")?;
            eprintln!(
                "engine: {} (fingerprint-matched: {})",
                eng.label(),
                eng.is_fingerprint_matched()
            );
            if let Some(note) = eng.parity_note() {
                eprintln!("fingerprint note: {note}");
            }
            let ex = eng.send(req, Source::Replay).context("sending request")?;

            let mut store =
                Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
            let id = store.insert(&ex).context("storing exchange")?;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&ex)?);
            } else {
                print_response(&ex);
                println!("  stored as #{} in {}", id.0, args.db.display());
            }
            Ok(())
        }
    }
}

fn print_response(ex: &HttpExchange) {
    match &ex.response {
        Some(resp) => {
            println!(
                "{} {}{}",
                resp.version.wire_token(),
                resp.status,
                resp.reason
                    .as_deref()
                    .map(|r| format!(" {r}"))
                    .unwrap_or_default()
            );
            for h in resp.headers.iter().take(12) {
                println!("  {}: {}", h.name, h.value);
            }
            if resp.headers.len() > 12 {
                println!("  … (+{} more headers)", resp.headers.len() - 12);
            }
            println!("  [{} body bytes]", resp.body.len());
            if let Some(t) = ex.timings {
                println!("  [{} ms]", t.roundtrip_ms);
            }
        }
        None => println!("(no response captured)"),
    }
}

fn open_store(db: &PathBuf) -> Result<Store> {
    if !db.exists() {
        bail!(
            "no history database at {} — run `camio send` first",
            db.display()
        );
    }
    Store::open(db).with_context(|| format!("opening {}", db.display()))
}

fn query_cmd(args: QueryArgs) -> Result<()> {
    let mut store = open_store(&args.db)?;

    if args.list_saved {
        for (name, q) in store.list_saved_searches()? {
            println!("  {name:<20} {q}");
        }
        return Ok(());
    }
    if let Some(name) = &args.delete_saved {
        let removed = store.delete_saved_search(name)?;
        println!(
            "{}",
            if removed {
                format!("deleted saved search `{name}`")
            } else {
                format!("no saved search named `{name}`")
            }
        );
        return Ok(());
    }

    // Resolve the query text: a saved search, or the positional query.
    let query_text = if let Some(name) = &args.saved {
        store
            .saved_search(name)?
            .ok_or_else(|| anyhow::anyhow!("no saved search named `{name}`"))?
    } else {
        args.query
            .clone()
            .ok_or_else(|| anyhow::anyhow!("provide a CamioQL query, or --saved <name>"))?
    };

    if let Some(name) = &args.save {
        store.save_search(name, &query_text)?;
        eprintln!("saved search `{name}` = {query_text}");
    }

    let query = Query::compile(&query_text).map_err(|e| anyhow::anyhow!("{e}"))?;
    let results = store.query(&query, args.limit)?;
    print_exchange_list(&results, args.json)
}

fn history_cmd(args: HistoryArgs) -> Result<()> {
    let store = open_store(&args.db)?;
    let results = store.recent(args.limit)?;
    print_exchange_list(&results, args.json)
}

fn print_exchange_list(results: &[HttpExchange], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(results)?);
        return Ok(());
    }
    if results.is_empty() {
        println!("(no matching exchanges)");
        return Ok(());
    }
    println!(
        "{:>6}  {:<6} {:>5}  {:<8}  URL",
        "ID", "METHOD", "CODE", "SOURCE"
    );
    for ex in results {
        let code = ex
            .response
            .as_ref()
            .map(|r| r.status.to_string())
            .unwrap_or_else(|| "-".into());
        println!(
            "{:>6}  {:<6} {:>5}  {:<8}  {}",
            ex.id.0,
            ex.request.method,
            code,
            ex.source.as_str(),
            ex.request.url
        );
    }
    println!("\n{} exchange(s).", results.len());
    Ok(())
}

fn scope_cmd(args: ScopeArgs) -> Result<()> {
    let scope = build_scope(&args.scope_include, &args.scope_exclude, args.allow_private)?;
    let ex = HttpExchange::new(HttpRequest::get(&args.url), Source::Replay);
    let decision = scope.decide(&ex);
    println!("{} -> {}", args.url, decision.as_str());
    if decision == camio_core::ScopeDecision::Blocked {
        println!(
            "(blocked by the SSRF/safety guard; pass --allow-private for an authorized lab target)"
        );
    }
    Ok(())
}

fn mcp_serve_cmd(args: McpServeArgs) -> Result<()> {
    let profile = profile_for(args.preset);
    let scope = build_scope(&args.scope_include, &args.scope_exclude, args.allow_private)?;
    let store = Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
    let policy = Policy {
        allow_active: args.allow_active,
        ..Policy::safe()
    };

    let mut server = McpServer::new(profile.clone())
        .with_store(store)
        .with_scope(scope)
        .with_policy(policy);

    if !args.dry_run {
        let eng = matched_engine(&profile).context("building matched request engine")?;
        server = server.with_engine(eng);
    }

    eprintln!("camio mcp: serving on stdio (db {})", args.db.display());
    server.serve_stdio().context("serving MCP")?;
    Ok(())
}

// ===========================================================================
// Convert / Decoder
// ===========================================================================

#[derive(Parser)]
struct ConvertArgs {
    /// Comma-separated pipeline, e.g. `base64,gzip` or `base64-decode`. Omit with --list.
    steps: Option<String>,
    /// Input string (else --input-file, else stdin).
    #[arg(long)]
    input: Option<String>,
    /// Read input bytes from a file.
    #[arg(long)]
    input_file: Option<PathBuf>,
    /// List the available transforms and exit.
    #[arg(long)]
    list: bool,
    /// Write raw output bytes to stdout (for piping) instead of a readable summary.
    #[arg(long)]
    raw_out: bool,
}

fn convert_cmd(args: ConvertArgs) -> Result<()> {
    if args.list {
        println!("Transforms ('*' = reversible, else a one-way hash):");
        for t in Transform::all() {
            println!(
                "  {:<20} {}",
                t.name(),
                if t.is_reversible() { "*" } else { "(hash)" }
            );
        }
        return Ok(());
    }
    let steps_str = args
        .steps
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("give a pipeline (e.g. `base64,gzip`) or use --list"))?;
    let mut steps = Vec::new();
    for name in steps_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        steps.push(
            Transform::from_name(name)
                .ok_or_else(|| anyhow::anyhow!("unknown transform `{name}` (see --list)"))?,
        );
    }
    let input = read_input_bytes(&args.input, &args.input_file)?;
    let out = camio_convert::apply_pipeline(&input, &steps).map_err(|e| anyhow::anyhow!("{e}"))?;
    if args.raw_out {
        use std::io::Write as _;
        std::io::stdout()
            .write_all(&out)
            .context("writing output")?;
        return Ok(());
    }
    match std::str::from_utf8(&out) {
        Ok(s) => println!("{s}"),
        Err(_) => {
            let hex = Transform::HexEncode
                .apply(&out)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default();
            println!("(binary, {} bytes) hex: {hex}", out.len());
        }
    }
    Ok(())
}

fn read_input_bytes(input: &Option<String>, file: &Option<PathBuf>) -> Result<Vec<u8>> {
    if let Some(s) = input {
        return Ok(s.clone().into_bytes());
    }
    if let Some(f) = file {
        return std::fs::read(f).with_context(|| format!("reading {}", f.display()));
    }
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .context("reading stdin")?;
    Ok(buf)
}

#[derive(Parser)]
struct JwtArgs {
    /// The JWT, `header.payload.signature`.
    token: String,
}

fn jwt_cmd(args: JwtArgs) -> Result<()> {
    let parts = camio_convert::decode_jwt(&args.token).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("header : {}", parts.header_json);
    println!("payload: {}", parts.payload_json);
    println!("signature (b64url): {}", parts.signature_b64url);
    println!("\nNote: the signature is NOT verified — treat all claims as untrusted input.");
    Ok(())
}

#[derive(Parser)]
struct CompareArgs {
    /// First file.
    a: PathBuf,
    /// Second file.
    b: PathBuf,
    /// Byte-level summary instead of a unified line diff.
    #[arg(long)]
    bytes: bool,
    /// Context lines for the unified diff.
    #[arg(long, default_value_t = 3)]
    context: usize,
}

fn compare_cmd(args: CompareArgs) -> Result<()> {
    let a = std::fs::read(&args.a).with_context(|| format!("reading {}", args.a.display()))?;
    let b = std::fs::read(&args.b).with_context(|| format!("reading {}", args.b.display()))?;
    if args.bytes {
        let d = camio_convert::diff_bytes(&a, &b);
        println!("equal          : {}", d.equal);
        println!("a_len / b_len  : {} / {}", d.a_len, d.b_len);
        println!("common prefix  : {}", d.common_prefix);
        println!("common suffix  : {}", d.common_suffix);
        println!(
            "first diff at  : {}",
            d.first_diff_offset
                .map(|o| o.to_string())
                .unwrap_or_else(|| "-".into())
        );
        return Ok(());
    }
    let sa = String::from_utf8_lossy(&a);
    let sb = String::from_utf8_lossy(&b);
    let diff = camio_convert::unified_diff(&sa, &sb, args.context);
    if diff.trim().is_empty() {
        println!("(files are identical)");
    } else {
        print!("{diff}");
    }
    Ok(())
}

// ===========================================================================
// Scanner
// ===========================================================================

#[derive(Parser)]
struct ScanArgs {
    /// CamioQL filter over history (default: all captured exchanges).
    query: Option<String>,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    #[arg(long, default_value_t = 1000)]
    limit: usize,
    /// Persist findings to the findings store.
    #[arg(long)]
    save: bool,
    #[arg(long)]
    json: bool,
    /// Run only these check ids (repeatable). Default: every check.
    #[arg(long = "only")]
    only: Vec<String>,
    /// Exclude these check ids (repeatable).
    #[arg(long = "exclude")]
    exclude: Vec<String>,
    /// Drop findings below this severity: info|low|medium|high|critical.
    #[arg(long = "min-severity")]
    min_severity: Option<String>,
    /// List the available check ids and exit.
    #[arg(long = "list-checks")]
    list_checks: bool,
}

#[derive(Parser)]
struct FindingsArgs {
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Set this finding's triage status (requires --status).
    #[arg(long)]
    set: Option<i64>,
    /// Status: open|confirmed|false-positive|fixed|ignored.
    #[arg(long)]
    status: Option<String>,
    /// Attach a triage note (with --set).
    #[arg(long)]
    note: Option<String>,
    #[arg(long)]
    json: bool,
}

fn findings_cmd(args: FindingsArgs) -> Result<()> {
    let mut store =
        Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;

    if let Some(id) = args.set {
        let status = args
            .status
            .as_deref()
            .and_then(camio_store::FindingStatus::parse)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--set requires --status open|confirmed|false-positive|fixed|ignored"
                )
            })?;
        store.set_finding_status(FindingId(id), status, args.note.as_deref())?;
        println!("finding #{id} → {}", status.as_str());
        return Ok(());
    }

    let rows = store.list_findings_with_status()?;
    if args.json {
        let items: Vec<_> = rows
            .iter()
            .map(|(f, s, n)| {
                serde_json::json!({
                    "id": f.id.0, "title": f.title, "severity": f.severity.as_str(),
                    "status": s.as_str(), "note": n,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        for (f, s, note) in &rows {
            let note = note
                .as_deref()
                .map(|n| format!("  — {n}"))
                .unwrap_or_default();
            println!(
                "  #{:<4} {:<8} {:<14} {}{note}",
                f.id.0,
                f.severity.as_str(),
                s.as_str(),
                truncate(&f.title, 60)
            );
        }
        eprintln!("{} finding(s).", rows.len());
    }
    Ok(())
}

#[derive(Parser)]
struct LabelArgs {
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Add the label (--label) to this exchange id.
    #[arg(long)]
    add: Option<i64>,
    /// Remove the label (--label) from this exchange id.
    #[arg(long)]
    remove: Option<i64>,
    /// The label text (with --add/--remove).
    #[arg(long)]
    label: Option<String>,
    /// Show exchange ids carrying this label.
    #[arg(long)]
    show: Option<String>,
    /// List all labels with counts.
    #[arg(long)]
    list: bool,
}

fn label_cmd(args: LabelArgs) -> Result<()> {
    let mut store =
        Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;

    if args.list {
        for (label, count) in store.all_labels()? {
            println!("  {label:<24} {count}");
        }
        return Ok(());
    }
    if let Some(label) = &args.show {
        for id in store.exchanges_with_label(label)? {
            println!("{}", id.0);
        }
        return Ok(());
    }
    let label = || {
        args.label
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--add/--remove require --label <text>"))
    };
    if let Some(id) = args.add {
        let l = label()?;
        store.add_label(camio_core::ExchangeId(id), &l)?;
        println!("labeled #{id} `{l}`");
        return Ok(());
    }
    if let Some(id) = args.remove {
        let l = label()?;
        let removed = store.remove_label(camio_core::ExchangeId(id), &l)?;
        println!(
            "{}",
            if removed {
                format!("removed `{l}` from #{id}")
            } else {
                format!("#{id} had no label `{l}`")
            }
        );
        return Ok(());
    }
    bail!("nothing to do: use --add/--remove/--show/--list")
}

#[derive(Parser)]
struct DiffArgs {
    /// First stored exchange id.
    id1: i64,
    /// Second stored exchange id.
    id2: i64,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Diff the requests instead of the responses.
    #[arg(long)]
    request: bool,
    /// Context lines around each change.
    #[arg(long, default_value_t = 3)]
    context: usize,
}

fn diff_cmd(args: DiffArgs) -> Result<()> {
    let store = open_store(&args.db)?;
    let load = |id: i64| -> Result<HttpExchange> {
        store
            .get(camio_core::ExchangeId(id))?
            .ok_or_else(|| anyhow::anyhow!("no exchange #{id} in {}", args.db.display()))
    };
    let a = load(args.id1)?;
    let b = load(args.id2)?;

    let (ta, tb) = if args.request {
        (a.request.raw(), b.request.raw())
    } else {
        let raw = |ex: &HttpExchange| ex.response.as_ref().map(|r| r.raw()).unwrap_or_default();
        (raw(&a), raw(&b))
    };

    let what = if args.request { "request" } else { "response" };
    eprintln!("diff {} of #{} ↔ #{}", what, args.id1, args.id2);
    let diff = camio_convert::unified_diff(&ta, &tb, args.context);
    if diff.trim().is_empty() {
        println!("(identical)");
    } else {
        print!("{diff}");
    }
    Ok(())
}

fn parse_severity(s: &str) -> Result<camio_core::Severity> {
    camio_core::Severity::parse(s).ok_or_else(|| {
        anyhow::anyhow!("unknown severity `{s}` (use info|low|medium|high|critical)")
    })
}

fn scan_cmd(args: ScanArgs) -> Result<()> {
    if args.list_checks {
        println!("Passive check ids:");
        for c in camio_scan::default_checks() {
            println!("  {:<26} {} ({})", c.id(), c.title(), c.severity().as_str());
        }
        return Ok(());
    }

    let mut profile = if args.only.is_empty() {
        camio_scan::ScanProfile::all()
    } else {
        camio_scan::ScanProfile::only(args.only.clone())
    };
    profile.exclude_ids = args.exclude.clone();
    if let Some(sev) = &args.min_severity {
        profile.min_severity = parse_severity(sev)?;
    }

    let mut store = open_store(&args.db)?;
    let q =
        Query::compile(args.query.as_deref().unwrap_or("")).map_err(|e| anyhow::anyhow!("{e}"))?;
    let exchanges = store.query_with_bodies(&q, args.limit)?;
    let report = camio_scan::scan_all_with_profile(&exchanges, &profile);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_findings(&report.findings);
        println!(
            "\nscanned {} exchange(s) with {} checks; {} finding(s).",
            report.exchanges_scanned,
            report.checks_run,
            report.findings.len()
        );
    }
    if args.save {
        let n = store.insert_findings(&report.findings)?;
        println!("saved {n} finding(s) to {}", args.db.display());
    }
    Ok(())
}

fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("(no findings)");
        return;
    }
    println!(
        "{:<9} {:<11} {:>4}  TITLE",
        "SEVERITY", "CONFIDENCE", "EVID"
    );
    for f in findings {
        println!(
            "{:<9} {:<11} {:>4}  {}",
            severity_label(f.severity),
            format!("{:?}", f.confidence).to_lowercase(),
            f.evidence.len(),
            f.title
        );
    }
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

// ===========================================================================
// Automate / Intruder
// ===========================================================================

#[derive(Copy, Clone, ValueEnum)]
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
}

#[derive(Parser)]
struct FuzzArgs {
    /// Target URL; mark insertion points with §…§ (e.g. '/item?id=§1§').
    url: String,
    #[arg(long, short = 'X', default_value = "GET")]
    method: String,
    /// Header "Name: Value" (repeatable); values may contain §…§ markers.
    #[arg(long = "header", short = 'H')]
    headers: Vec<String>,
    /// Request body; may contain §…§ markers.
    #[arg(long)]
    body: Option<String>,
    #[arg(long, value_enum, default_value_t = AttackKind::Sniper)]
    attack: AttackKind,
    /// Payload set: a built-in pack name (see `camio payloads`) or a file path (repeatable).
    #[arg(long = "payloads")]
    payloads: Vec<String>,
    /// Max requests to generate; the projected count must fit (plan §10).
    #[arg(long, default_value_t = 200)]
    budget: u64,
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Actually run the campaign (an ACTIVE test). Without this, only the plan is shown.
    #[arg(long)]
    confirm: bool,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// How many result rows to print.
    #[arg(long, default_value_t = 30)]
    show: usize,
    #[arg(long)]
    json: bool,
}

fn fuzz_cmd(args: FuzzArgs) -> Result<()> {
    if args.payloads.is_empty() {
        bail!("give at least one --payloads <pack-name|file> (see `camio payloads`)");
    }
    let profile = profile_for(args.preset);
    let scope = build_scope(&args.scope_include, &args.scope_exclude, args.allow_private)?;
    let base = build_request(&args.url, &args.method, &args.headers, &args.body, &None)?;

    let mut sets = Vec::new();
    for p in &args.payloads {
        sets.push(load_payload_set(p)?);
    }
    let attack = args.attack.to_attack();
    let campaign = Campaign {
        base: base.clone(),
        attack,
        sets,
        budget: Some(args.budget),
    };

    let planned = camio_automate::plan(&campaign).map_err(|e| anyhow::anyhow!("{e}"))?;
    let clean = strip_to_clean(&base);
    let decision = scope.decide(&HttpExchange::new(clean.clone(), Source::Automate));

    println!("Campaign plan:");
    println!("  attack             : {}", attack.as_str());
    println!("  insertion points   : {}", planned.num_positions);
    println!(
        "  payload sets       : {}",
        campaign
            .sets
            .iter()
            .map(|s| format!("{}({})", s.name, s.len()))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  projected requests : {}", planned.projected_requests);
    println!("  budget             : {}", args.budget);
    println!("  within budget      : {}", planned.within_budget);
    println!("  scope decision     : {}", decision.as_str());

    // Fuzzing is an ACTIVE action under the shared policy (plan §16).
    let policy = Policy {
        allow_active: true,
        allow_destructive: false,
        require_confirmation: true,
    };
    match policy.gate(ActionClass::Active, decision, args.confirm) {
        PolicyOutcome::Deny(reason) => bail!("refused: {reason}"),
        PolicyOutcome::NeedsConfirmation(reason) => {
            println!("\n{reason}.");
            println!("Re-run with --confirm to execute (authorized targets only).");
            return Ok(());
        }
        PolicyOutcome::Allow => {}
    }
    if !planned.within_budget {
        bail!(
            "projected {} request(s) exceeds budget {}; raise --budget",
            planned.projected_requests,
            args.budget
        );
    }

    let generated = camio_automate::generate(&campaign).map_err(|e| anyhow::anyhow!("{e}"))?;
    let eng = matched_engine(&profile).context("building matched request engine")?;
    eprintln!(
        "engine: {} (fingerprint-matched: {})",
        eng.label(),
        eng.is_fingerprint_matched()
    );
    if let Some(note) = eng.parity_note() {
        eprintln!("fingerprint note: {note}");
    }

    // Baseline (markers stripped) for result classification.
    let baseline = eng.send(clean, Source::Automate).ok().and_then(|ex| {
        ex.response.as_ref().map(|r| Baseline {
            status: r.status,
            body_len: r.body.len(),
        })
    });

    let mut store =
        Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
    let mut results = Vec::new();
    for g in &generated {
        let pr = HttpExchange::new(g.request.clone(), Source::Automate);
        if !scope.decide(&pr).is_sendable() {
            continue; // never send out of scope (plan §16)
        }
        match eng.send(g.request.clone(), Source::Automate) {
            Ok(ex) => {
                let _ = store.insert(&ex);
                results.push((g.payloads.clone(), ex));
            }
            Err(e) => eprintln!("send failed: {e}"),
        }
    }

    let classified = camio_automate::classify(&results, baseline.as_ref(), None);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&classified)?);
    } else {
        print_classified(&classified, args.show);
    }
    println!(
        "\nsent {} request(s); stored in {}.",
        results.len(),
        args.db.display()
    );
    Ok(())
}

fn load_payload_set(spec: &str) -> Result<PayloadSet> {
    // Try the on-disk DB first (`db:<cat>` prefix or plain category name).
    let db = camio_automate::load_payload_db();
    if let Some(set) = resolve_pack(spec, &db) {
        return Ok(set);
    }
    let path = PathBuf::from(spec);
    if path.exists() {
        let text =
            std::fs::read_to_string(&path).with_context(|| format!("reading payloads {spec}"))?;
        return Ok(PayloadSet::from_lines(spec, &text));
    }
    bail!(
        "payloads `{spec}` is not a built-in pack, a DB category (see `camio payloads`), \
         or an existing file"
    );
}

/// A copy of `req` with every §…§ marker removed (baseline request).
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

fn print_classified(rows: &[camio_automate::ClassifiedResult], show: usize) {
    if rows.is_empty() {
        println!("(no results)");
        return;
    }
    println!(
        "{:<4} {:<5} {:>7}  {:<26} PAYLOAD",
        "#", "CODE", "LEN", "FLAGS"
    );
    for (i, r) in rows.iter().take(show).enumerate() {
        println!(
            "{:<4} {:<5} {:>7}  {:<26} {}",
            i,
            r.status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
            r.body_len
                .map(|l| l.to_string())
                .unwrap_or_else(|| "-".into()),
            r.flags.join(","),
            truncate(&r.payloads.join(" | "), 60)
        );
    }
    if rows.len() > show {
        println!("… (+{} more; use --show N or --json)", rows.len() - show);
    }
}

// ===========================================================================
// Discover (inputs) + Sitemap
// ===========================================================================

#[derive(Parser)]
struct DiscoverArgs {
    url: String,
    #[arg(long, short = 'X', default_value = "GET")]
    method: String,
    #[arg(long = "header", short = 'H')]
    headers: Vec<String>,
    #[arg(long)]
    body: Option<String>,
    #[arg(long)]
    json: bool,
}

fn discover_cmd(args: DiscoverArgs) -> Result<()> {
    let req = build_request(&args.url, &args.method, &args.headers, &args.body, &None)?;
    let inputs = camio_automate::discover_inputs(&req);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&inputs)?);
        return Ok(());
    }
    if inputs.is_empty() {
        println!("(no inputs discovered)");
        return Ok(());
    }
    println!("{:<12} {:<24} VALUE", "KIND", "NAME");
    for i in &inputs {
        println!(
            "{:<12} {:<24} {}",
            format!("{:?}", i.kind).to_lowercase(),
            truncate(&i.name, 24),
            truncate(&i.value, 60)
        );
    }
    println!("\n{} input(s).", inputs.len());
    Ok(())
}

#[derive(Parser)]
struct SitemapArgs {
    /// CamioQL filter over history (default: all).
    query: Option<String>,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    #[arg(long, default_value_t = 5000)]
    limit: usize,
    #[arg(long)]
    json: bool,
}

fn sitemap_cmd(args: SitemapArgs) -> Result<()> {
    let store = open_store(&args.db)?;
    let q =
        Query::compile(args.query.as_deref().unwrap_or("")).map_err(|e| anyhow::anyhow!("{e}"))?;
    let exchanges = store.query(&q, args.limit)?;
    let map = SiteMap::build(&exchanges);
    if args.json {
        println!(
            "{}",
            serde_json::json!({ "origin_count": map.origin_count(), "url_count": map.url_count() })
        );
        return Ok(());
    }
    print!("{}", map.render_tree());
    println!(
        "\n{} origin(s), {} URL(s).",
        map.origin_count(),
        map.url_count()
    );
    Ok(())
}

// ===========================================================================
// Import
// ===========================================================================

#[derive(Parser)]
struct ImportArgs {
    /// A Burp items XML export or a HAR archive.
    file: PathBuf,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Parse and report only; do not store.
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    json: bool,
}

fn import_cmd(args: ImportArgs) -> Result<()> {
    let data =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    let result = camio_import::import_bytes(&data).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("format   : {}", result.format);
    println!("exchanges: {}", result.exchanges.len());
    for w in &result.warnings {
        eprintln!("warning: {w}");
    }
    if !args.dry_run {
        let mut store =
            Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
        let n = store.insert_exchanges(&result.exchanges)?;
        println!("stored   : {n} into {}", args.db.display());
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result.exchanges)?);
    }
    Ok(())
}

// ===========================================================================
// Sequencer
// ===========================================================================

#[derive(Parser)]
struct SequencerArgs {
    /// File of samples, one token per line (else read stdin).
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

fn sequencer_cmd(args: SequencerArgs) -> Result<()> {
    let text = match &args.file {
        Some(f) => {
            std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?
        }
        None => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .context("reading stdin")?;
            s
        }
    };
    let tokens: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let report = camio_sequencer::analyze(&tokens);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!(
        "samples              : {} ({} unique, {} duplicate)",
        report.sample_count, report.unique_count, report.duplicate_count
    );
    println!(
        "length (min/mean/max): {}/{:.1}/{}",
        report.min_len, report.mean_len, report.max_len
    );
    println!("charset size         : {}", report.charset_size);
    println!(
        "entropy / symbol     : {:.3} bits",
        report.global_entropy_per_symbol
    );
    println!("effective bits       : {:.1}", report.effective_bits);
    println!("quality              : {:?}", report.quality);
    for n in &report.notes {
        println!("note: {n}");
    }
    Ok(())
}

// ===========================================================================
// Payloads
// ===========================================================================

#[derive(Parser)]
struct PayloadsArgs {
    /// A pack name to print its entries; omit to list all packs.
    name: Option<String>,
}

fn payloads_cmd(args: PayloadsArgs) -> Result<()> {
    let db = camio_automate::load_payload_db();
    match &args.name {
        None => {
            println!("Built-in payload packs (small, hand-curated, for AUTHORIZED testing only):");
            for name in camio_automate::builtin_packs() {
                let n = camio_automate::builtin_pack(name)
                    .map(|s| s.len())
                    .unwrap_or(0);
                println!("  {:<18} {} payload(s)", name, n);
            }
            if !db.categories.is_empty() {
                println!();
                println!(
                    "Camio payload database (payloads/DB/base/*.txt — {} categor{}):",
                    db.categories.len(),
                    if db.categories.len() == 1 { "y" } else { "ies" }
                );
                let total: usize = db.categories.values().map(|s| s.len()).sum();
                for (name, set) in &db.categories {
                    println!("  db:{:<15} {} payload(s)", name, set.len());
                }
                println!("  {:>18}  (total {})", "", total);
                println!();
                println!(
                    "Use `--payloads db:<category>` in fuzz/combo, or `camio payloads db:<category>` to list."
                );
            } else {
                println!();
                println!(
                    "note: payloads/DB/base/ not found — the database isn't shipped with this build."
                );
                println!(
                    "      set CAMIO_PAYLOADS_DIR or run from the workspace root to use it."
                );
            }
        }
        Some(name) => {
            let set = resolve_pack(name, &db)
                .ok_or_else(|| anyhow::anyhow!("unknown pack `{name}` (see `camio payloads`)"))?;
            for p in &set.payloads {
                println!("{p}");
            }
        }
    }
    Ok(())
}

// ===========================================================================
// Combo (payload chaining)
// ===========================================================================

#[derive(Parser)]
struct ComboArgs {
    /// Comma-separated payload categories to combine (e.g. `xss,sqli,traversal`).
    #[arg(long = "categories", required = true)]
    categories: String,
    /// Composition mode: parallel|chain|cross-product.
    #[arg(long = "mode", default_value = "parallel")]
    mode: ComboModeArg,
    /// String inserted between category contributions in each generated payload.
    #[arg(long = "join", default_value = ";")]
    join: String,
    /// Cap the number of generated payloads.
    #[arg(long = "limit", default_value_t = 50)]
    limit: usize,
    /// Write the combo as a one-per-line list to this file instead of stdout.
    #[arg(long = "out")]
    out: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum ComboModeArg {
    Parallel,
    Chain,
    CrossProduct,
}

impl From<ComboModeArg> for camio_automate::ComboMode {
    fn from(m: ComboModeArg) -> Self {
        match m {
            ComboModeArg::Parallel => camio_automate::ComboMode::Parallel,
            ComboModeArg::Chain => camio_automate::ComboMode::Chain,
            ComboModeArg::CrossProduct => camio_automate::ComboMode::CrossProduct,
        }
    }
}

fn combo_cmd(args: ComboArgs) -> Result<()> {
    let db = camio_automate::load_payload_db();
    let names: Vec<&str> = args
        .categories
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if names.len() < 2 {
        bail!(
            "combo needs at least two --categories (got {}): try `camio combo --categories xss,sqli`",
            names.len()
        );
    }
    let mut sets = Vec::with_capacity(names.len());
    for n in &names {
        let set = resolve_pack(n, &db)
            .ok_or_else(|| anyhow::anyhow!("unknown category `{n}` (see `camio payloads`)"))?;
        sets.push(set);
    }
    let out = camio_automate::combo(&sets, args.mode.into(), &args.join, args.limit)
        .ok_or_else(|| anyhow::anyhow!("combo generation yielded no payloads"))?;

    match &args.out {
        Some(path) => {
            let body = out
                .payloads
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(path, format!("{body}\n"))
                .with_context(|| format!("writing {}", path.display()))?;
            eprintln!(
                "wrote {} payload(s) from combo `{}` to {}",
                out.payloads.len(),
                out.name,
                path.display()
            );
        }
        None => {
            eprintln!(
                "combo `{}`: {} payload(s) ({} mode, join={:?})",
                out.name,
                out.payloads.len(),
                match args.mode {
                    ComboModeArg::Parallel => "parallel",
                    ComboModeArg::Chain => "chain",
                    ComboModeArg::CrossProduct => "cross-product",
                },
                args.join
            );
            for p in &out.payloads {
                println!("{p}");
            }
        }
    }
    Ok(())
}

// ===========================================================================
// Encode (dynamic encoded-payload testing)
// ===========================================================================

#[derive(Parser)]
struct EncodeArgs {
    /// A pack name (built-in or `db:<cat>`), a file path, or `-` for stdin.
    /// Required unless one of `--list-encodings` / `--list-contexts` is used.
    #[arg(
        long = "payloads",
        required_unless_present_any = ["list_encodings", "list_contexts"]
    )]
    payloads: Option<String>,
    /// Target context — selects a compatible encoding set automatically.
    /// Use `--encodings` for an explicit list instead.
    #[arg(long = "context", conflicts_with = "encodings")]
    context: Option<String>,
    /// Explicit comma-separated encodings (e.g. `raw,url,url-double,html,b64`).
    /// Run `camio encode --list-encodings` to see every name.
    #[arg(long = "encodings")]
    encodings: Option<String>,
    /// List every encoding name and exit.
    #[arg(long = "list-encodings")]
    list_encodings: bool,
    /// List every context name (and its encoding set) and exit.
    #[arg(long = "list-contexts")]
    list_contexts: bool,
    /// Also print the encoding tag before each line (useful for classifiers).
    #[arg(long = "tagged")]
    tagged: bool,
    /// Cap the number of emitted payloads.
    #[arg(long = "limit", default_value_t = 500)]
    limit: usize,
    /// Write to this file instead of stdout.
    #[arg(long = "out")]
    out: Option<PathBuf>,
}

fn encode_cmd(args: EncodeArgs) -> Result<()> {
    if args.list_encodings {
        println!("Available encodings (apply in the given order; `raw` is always first):");
        for e in camio_automate::Encoding::all() {
            println!("  {}", e.name());
        }
        return Ok(());
    }
    if args.list_contexts {
        println!("Known input contexts and their compatible encodings:");
        let contexts = [
            "url-path", "url-query", "form", "json", "json-number", "xml", "xml-attr",
            "header", "cookie", "html", "html-attr", "html-script", "html-style", "graphql",
            "multipart", "raw",
        ];
        for name in contexts {
            if let Some(ctx) = camio_automate::InputContext::from_name(name) {
                let encs = camio_automate::compatible_encodings(ctx);
                let names: Vec<&str> = encs.iter().map(|e| e.name()).collect();
                println!("  {:<12} {}", name, names.join(", "));
            }
        }
        return Ok(());
    }

    // Resolve the payload set.
    let db = camio_automate::load_payload_db();
    let payloads_spec = args
        .payloads
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--payloads is required"))?;
    let set = if payloads_spec == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading stdin")?;
        camio_automate::PayloadSet::from_lines("stdin", &buf)
    } else if let Some(s) = resolve_pack(payloads_spec, &db) {
        s
    } else {
        let p = PathBuf::from(payloads_spec);
        if p.exists() {
            let text = std::fs::read_to_string(&p)
                .with_context(|| format!("reading {}", p.display()))?;
            camio_automate::PayloadSet::from_lines(payloads_spec, &text)
        } else {
            bail!(
                "payloads `{payloads_spec}` is not a built-in pack, a DB category, stdin (`-`), or a file"
            );
        }
    };

    // Resolve the encoding list.
    let encs: Vec<camio_automate::Encoding> = match (&args.context, &args.encodings) {
        (Some(c), _) => {
            let ctx = camio_automate::InputContext::from_name(c).ok_or_else(|| {
                anyhow::anyhow!("unknown context `{c}` (see `camio encode --list-contexts`)")
            })?;
            camio_automate::compatible_encodings(ctx)
        }
        (None, Some(e)) => {
            let mut out = Vec::new();
            for name in e.split(',') {
                let name = name.trim();
                if name.is_empty() {
                    continue;
                }
                let enc = camio_automate::Encoding::from_name(name).ok_or_else(|| {
                    anyhow::anyhow!(
                        "unknown encoding `{name}` (see `camio encode --list-encodings`)"
                    )
                })?;
                out.push(enc);
            }
            out
        }
        (None, None) => {
            bail!("pass --context <name> or --encodings <list> (see --list-contexts/--list-encodings)");
        }
    };

    let mut expanded = camio_automate::expand_with_encodings(&set, &encs);
    if expanded.len() > args.limit {
        expanded.truncate(args.limit);
    }

    let format_line = |e: &camio_automate::EncodedPayload| {
        if args.tagged {
            format!("{}\t{}", e.encoding.name(), e.body)
        } else {
            e.body.clone()
        }
    };

    match &args.out {
        Some(path) => {
            let mut body = String::new();
            for e in &expanded {
                body.push_str(&format_line(e));
                body.push('\n');
            }
            std::fs::write(path, body)
                .with_context(|| format!("writing {}", path.display()))?;
            eprintln!(
                "wrote {} encoded payload(s) from `{}` to {}",
                expanded.len(),
                set.name,
                path.display()
            );
        }
        None => {
            eprintln!(
                "encode `{}`: {} payload(s), encodings=[{}]",
                set.name,
                expanded.len(),
                encs.iter()
                    .map(|e| e.name())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            for e in &expanded {
                println!("{}", format_line(e));
            }
        }
    }
    Ok(())
}

/// Resolve `spec` to a `PayloadSet`, trying (in order): a `db:<cat>` reference,
/// a plain category name in the DB, and the small built-in packs.
fn resolve_pack(
    spec: &str,
    db: &camio_automate::PayloadDb,
) -> Option<camio_automate::PayloadSet> {
    if let Some(rest) = spec.strip_prefix("db:") {
        return db.categories.get(rest).cloned();
    }
    if let Some(s) = db.categories.get(spec).cloned() {
        return Some(s);
    }
    camio_automate::builtin_pack(spec)
}

// ===========================================================================
// Shared helpers for the new commands
// ===========================================================================

/// Build an [`HttpRequest`] from CLI url/method/header/body args.
fn build_request(
    url: &str,
    method: &str,
    headers: &[String],
    body: &Option<String>,
    body_file: &Option<PathBuf>,
) -> Result<HttpRequest> {
    let mut req = HttpRequest::get(url);
    req.method = method.to_string();
    for h in headers {
        let (n, v) = parse_header(h)?;
        req.headers.push(n, v);
    }
    if let Some(f) = body_file {
        req.body =
            Body::from_bytes(std::fs::read(f).with_context(|| format!("reading {}", f.display()))?);
    } else if let Some(b) = body {
        req.body = Body::from_text(b.clone());
    }
    Ok(req)
}

/// Parse `--rewrite PART|FIND|REPLACE` specs into a [`RuleSet`].
pub(crate) fn build_ruleset(specs: &[String]) -> Result<RuleSet> {
    let mut set = RuleSet::new();
    for (i, spec) in specs.iter().enumerate() {
        let parts: Vec<&str> = spec.splitn(3, '|').collect();
        if parts.len() != 3 {
            bail!(
                "--rewrite `{spec}` must be PART|FIND|REPLACE (PART = url|method|body|header=NAME)"
            );
        }
        let target = parse_rewrite_target(parts[0])?;
        let rule = MatchReplaceRule::literal(format!("cli-{i}"), target, parts[1], parts[2], None)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        set.push(rule);
    }
    Ok(set)
}

fn parse_rewrite_target(s: &str) -> Result<MatchTarget> {
    let s = s.trim();
    if let Some(name) = s.strip_prefix("header=") {
        return Ok(MatchTarget::RequestHeader(name.to_string()));
    }
    if let Some(name) = s.strip_prefix("resp-header=") {
        return Ok(MatchTarget::ResponseHeader(name.to_string()));
    }
    Ok(match s.to_ascii_lowercase().as_str() {
        "url" => MatchTarget::Url,
        "method" => MatchTarget::Method,
        "body" => MatchTarget::RequestBody,
        "resp-body" => MatchTarget::ResponseBody,
        "status-reason" | "reason" => MatchTarget::ResponseReason,
        other => bail!(
            "unknown rewrite part `{other}` (use url|method|body|header=NAME|\
             resp-header=NAME|resp-body|status-reason)"
        ),
    })
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

// ===========================================================================
// OAST collector (self-hosted out-of-band interaction server)
// ===========================================================================

#[derive(Parser)]
struct OastArgs {
    /// Address to listen on for out-of-band callbacks.
    #[arg(long, default_value = "127.0.0.1:8888")]
    listen: String,
    /// Authority (host:port) embedded in callback URLs. Defaults to the listen
    /// address; set this to an address the target can actually reach.
    #[arg(long)]
    base: Option<String>,
    /// Print N sample correlation tokens + callback URLs and exit (no server).
    #[arg(long)]
    tokens: Option<usize>,
}

fn oast_cmd(args: OastArgs) -> Result<()> {
    let base = args.base.clone().unwrap_or_else(|| args.listen.clone());
    let collector = camio_oast::Collector::new(base.clone());

    if let Some(n) = args.tokens {
        for _ in 0..n.max(1) {
            let t = collector.new_token();
            println!(
                "{}    (dns: {})",
                collector.callback_url(&t),
                collector.dns_callback_url(&t)
            );
        }
        return Ok(());
    }

    let listener = std::net::TcpListener::bind(&args.listen)
        .with_context(|| format!("binding {}", args.listen))?;
    let local = listener.local_addr().context("reading local address")?;
    let sample = collector.new_token();

    eprintln!("Camio OAST collector listening on {local}");
    eprintln!("  callback base   : http://{base}/");
    eprintln!("  sample token    : {sample}");
    eprintln!("  sample callback : {}", collector.callback_url(&sample));
    eprintln!(
        "Plant a token-bearing callback URL in a payload (SSRF/XXE/blind injection);\n\
         interactions that reach this address are logged below. Press Ctrl-C to stop."
    );

    let server = camio_oast::OastServer::new(collector).on_interaction(|i| {
        let token = i
            .token
            .as_ref()
            .map(|t| format!("  token={t}"))
            .unwrap_or_default();
        eprintln!(
            "  [#{}] {} {} from {}{token}",
            i.id, i.method, i.target, i.source
        );
    });
    server
        .serve_with_listener(listener)
        .context("serving OAST collector")?;
    Ok(())
}

// ===========================================================================
// Nuclei integration (external tool)
// ===========================================================================

#[derive(Parser)]
struct NucleiArgs {
    /// Authorized target URL to scan.
    url: String,
    /// Limit to these severities (repeatable): info|low|medium|high|critical.
    #[arg(long = "severity")]
    severities: Vec<String>,
    /// Limit to templates with these tags (repeatable).
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Requests-per-second cap passed to Nuclei.
    #[arg(long)]
    rate_limit: Option<u32>,
    /// Overall timeout in seconds; Nuclei is killed if it runs longer.
    #[arg(long, default_value_t = 300)]
    timeout_secs: u64,
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Actually run Nuclei. Without this, prints what would run.
    #[arg(long)]
    confirm: bool,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Persist the normalized findings to the findings store.
    #[arg(long)]
    save: bool,
    #[arg(long)]
    json: bool,
    /// Extra args passed verbatim to nuclei (after `--`), e.g. -t a-template.
    #[arg(last = true)]
    extra: Vec<String>,
}

fn nuclei_cmd(args: NucleiArgs) -> Result<()> {
    let scope = build_scope(&args.scope_include, &args.scope_exclude, args.allow_private)?;
    let base = HttpRequest::get(&args.url);
    let decision = scope.decide(&HttpExchange::new(base.clone(), Source::Scanner));

    // Nuclei actively probes: in scope + explicit confirmation (plan §16).
    let policy = Policy {
        allow_active: true,
        allow_destructive: false,
        require_confirmation: true,
    };
    match policy.gate(ActionClass::Active, decision, args.confirm) {
        PolicyOutcome::Deny(reason) => bail!("refused: {reason}"),
        PolicyOutcome::NeedsConfirmation(reason) => {
            println!("{reason}.");
            println!(
                "Would run Nuclei against {} (scope {}). Re-run with --confirm (authorized targets only).",
                args.url,
                decision.as_str()
            );
            return Ok(());
        }
        PolicyOutcome::Allow => {}
    }

    let opts = camio_integrations::NucleiOptions {
        severities: args.severities.clone(),
        tags: args.tags.clone(),
        rate_limit: args.rate_limit,
        timeout: std::time::Duration::from_secs(args.timeout_secs),
        extra_args: args.extra.clone(),
    };
    eprintln!(
        "running nuclei against {} (timeout {}s)…",
        args.url, args.timeout_secs
    );
    let raw = match camio_integrations::run_nuclei(std::slice::from_ref(&args.url), &opts) {
        Ok(r) => r,
        Err(camio_integrations::IntegrationError::NotInstalled(_)) => {
            bail!("nuclei is not installed or not on PATH; install it from https://github.com/projectdiscovery/nuclei")
        }
        Err(e) => bail!("nuclei run failed: {e}"),
    };
    let findings = camio_integrations::nuclei_to_findings(&raw);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else {
        print_findings(&findings);
        println!("\n{} finding(s) from nuclei.", findings.len());
    }
    if args.save {
        let mut store =
            Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
        let n = store.insert_findings(&findings).unwrap_or(0);
        eprintln!("saved {n} finding(s) to {}", args.db.display());
    }
    Ok(())
}

// ===========================================================================
// Subfinder integration (external, passive OSINT)
// ===========================================================================

#[derive(Parser)]
struct SubfinderArgs {
    /// Root domain to enumerate (e.g. example.com).
    domain: String,
    /// Use every passive source (subfinder -all).
    #[arg(long)]
    all: bool,
    /// Restrict to these passive sources (repeatable).
    #[arg(long = "source")]
    sources: Vec<String>,
    /// Overall timeout in seconds; subfinder is killed if it runs longer.
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,
    /// Emit the unique host list as JSON.
    #[arg(long)]
    json: bool,
    /// Extra args passed verbatim to subfinder (after `--`).
    #[arg(last = true)]
    extra: Vec<String>,
}

fn subfinder_cmd(args: SubfinderArgs) -> Result<()> {
    let opts = camio_integrations::SubfinderOptions {
        sources: args.sources.clone(),
        all_sources: args.all,
        timeout: std::time::Duration::from_secs(args.timeout_secs),
        extra_args: args.extra.clone(),
    };
    eprintln!(
        "running subfinder on {} (timeout {}s)…",
        args.domain, args.timeout_secs
    );
    let subs = match camio_integrations::run_subfinder(std::slice::from_ref(&args.domain), &opts) {
        Ok(s) => s,
        Err(camio_integrations::IntegrationError::NotInstalled(_)) => {
            bail!("subfinder is not installed or not on PATH; install it from https://github.com/projectdiscovery/subfinder")
        }
        Err(e) => bail!("subfinder run failed: {e}"),
    };
    let hosts = camio_integrations::unique_hosts(&subs);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&hosts)?);
    } else {
        for h in &hosts {
            println!("{h}");
        }
        eprintln!("{} unique subdomain(s).", hosts.len());
    }
    Ok(())
}

#[derive(Parser)]
struct CrawlArgs {
    /// Seed URL to crawl.
    url: String,
    /// Maximum pages to fetch.
    #[arg(long, default_value_t = 50)]
    max_pages: usize,
    /// Follow links off the seed's host too (default: same-origin only).
    #[arg(long)]
    cross_origin: bool,
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Actually crawl. Without this, prints what would run.
    #[arg(long)]
    confirm: bool,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    #[arg(long)]
    json: bool,
}

fn crawl_cmd(args: CrawlArgs) -> Result<()> {
    let profile = profile_for(args.preset);
    let scope = build_scope(&args.scope_include, &args.scope_exclude, args.allow_private)?;
    let decision = scope.decide(&HttpExchange::new(
        HttpRequest::get(&args.url),
        Source::Crawler,
    ));

    // Crawling sends many requests: in scope + explicit confirmation (plan §16).
    let policy = Policy::safe();
    match policy.gate(ActionClass::Mutating, decision, args.confirm) {
        PolicyOutcome::Deny(reason) => bail!("refused: {reason}"),
        PolicyOutcome::NeedsConfirmation(reason) => {
            println!("{reason}.");
            println!(
                "Would crawl up to {} page(s) from {} (scope {}{}). Re-run with --confirm.",
                args.max_pages,
                args.url,
                decision.as_str(),
                if args.cross_origin {
                    ", cross-origin"
                } else {
                    ", same-origin"
                }
            );
            return Ok(());
        }
        PolicyOutcome::Allow => {}
    }

    let eng = matched_engine(&profile).context("building matched request engine")?;
    let store = RefCell::new(
        Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?,
    );
    eprintln!("crawling {} (max {} pages)…", args.url, args.max_pages);

    let send = |req: HttpRequest| -> Option<HttpExchange> {
        if !scope
            .decide(&HttpExchange::new(req.clone(), Source::Crawler))
            .is_sendable()
        {
            return None;
        }
        match eng.send(req, Source::Crawler) {
            Ok(mut ex) => {
                if let Ok(id) = store.borrow_mut().insert(&ex) {
                    ex.id = id;
                }
                Some(ex)
            }
            Err(e) => {
                eprintln!("fetch failed: {e}");
                None
            }
        }
    };
    let opts = camio_active::CrawlOptions {
        max_pages: args.max_pages,
        same_origin_only: !args.cross_origin,
    };
    let result = camio_active::crawl(&args.url, &send, &opts);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "fetched": result.fetched.iter().map(|e| e.0).collect::<Vec<_>>(),
                "discovered": result.discovered,
                "skipped": result.skipped,
            }))?
        );
    } else {
        for u in &result.discovered {
            println!("{u}");
        }
        eprintln!(
            "crawled {} page(s); {} URL(s) discovered; {} refused/out-of-scope.",
            result.fetched.len(),
            result.discovered.len(),
            result.skipped
        );
    }
    Ok(())
}

fn integrations_cmd() -> Result<()> {
    println!("External-tool integrations:");
    for st in camio_integrations::registry() {
        let status = if st.installed {
            st.version
                .as_deref()
                .map(|v| format!("installed ({v})"))
                .unwrap_or_else(|| "installed".to_string())
        } else {
            "not installed".to_string()
        };
        println!("  {:<12} {:<34} {status}", st.name, st.purpose);
    }
    Ok(())
}

// ===========================================================================
// Active scan (opt-in)
// ===========================================================================

#[derive(Parser)]
struct ActiveArgs {
    /// Authorized target URL (the scanner derives injectable inputs from it).
    url: String,
    #[arg(long, short = 'X', default_value = "GET")]
    method: String,
    #[arg(long = "header", short = 'H')]
    headers: Vec<String>,
    #[arg(long)]
    body: Option<String>,
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Actually run the active probes. Without this, prints what would run.
    #[arg(long)]
    confirm: bool,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Persist findings to the findings store.
    #[arg(long)]
    save: bool,
    #[arg(long)]
    json: bool,
    /// Also run OAST-driven blind-SSRF detection: start a collector listening on
    /// this address and inject correlated callback URLs into each input.
    #[arg(long)]
    oast_listen: Option<String>,
    /// Authority (host:port) embedded in OAST callback URLs. Defaults to the
    /// --oast-listen address; set this to an address the target can reach.
    #[arg(long)]
    oast_base: Option<String>,
    /// Milliseconds to wait after each SSRF probe for the out-of-band callback.
    #[arg(long, default_value_t = 1500)]
    oast_settle_ms: u64,
}

fn activescan_cmd(args: ActiveArgs) -> Result<()> {
    let profile = profile_for(args.preset);
    let scope = build_scope(&args.scope_include, &args.scope_exclude, args.allow_private)?;
    let base = build_request(&args.url, &args.method, &args.headers, &args.body, &None)?;
    let decision = scope.decide(&HttpExchange::new(base.clone(), Source::Scanner));

    // Active testing (plan §16): must be in scope and explicitly confirmed.
    let policy = Policy {
        allow_active: true,
        allow_destructive: false,
        require_confirmation: true,
    };
    match policy.gate(ActionClass::Active, decision, args.confirm) {
        PolicyOutcome::Deny(reason) => bail!("refused: {reason}"),
        PolicyOutcome::NeedsConfirmation(reason) => {
            println!("{reason}.");
            println!(
                "Would actively probe {} (scope {}) for reflected XSS, error-based SQLi and open redirect{}.",
                args.url,
                decision.as_str(),
                if args.oast_listen.is_some() {
                    ", plus OAST-driven blind SSRF"
                } else {
                    ""
                }
            );
            println!("Re-run with --confirm to execute (authorized targets only).");
            return Ok(());
        }
        PolicyOutcome::Allow => {}
    }

    let eng = matched_engine(&profile).context("building matched request engine")?;
    eprintln!(
        "engine: {} (fingerprint-matched: {})",
        eng.label(),
        eng.is_fingerprint_matched()
    );
    let store = RefCell::new(
        Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?,
    );

    // The sender is the one place scope is re-enforced on every probe (plan §16).
    let send = |req: HttpRequest| -> Option<HttpExchange> {
        if !scope
            .decide(&HttpExchange::new(req.clone(), Source::Scanner))
            .is_sendable()
        {
            return None;
        }
        match eng.send(req, Source::Scanner) {
            Ok(ex) => {
                let _ = store.borrow_mut().insert(&ex);
                Some(ex)
            }
            Err(e) => {
                eprintln!("probe send failed: {e}");
                None
            }
        }
    };
    let mut findings = camio_active::run_active(&base, &send);

    // Optional OAST-driven blind-SSRF detection with a live collector.
    if let Some(oast_listen) = &args.oast_listen {
        let listener = std::net::TcpListener::bind(oast_listen)
            .with_context(|| format!("binding OAST collector on {oast_listen}"))?;
        let local = listener.local_addr().context("reading OAST address")?;
        let base_auth = args.oast_base.clone().unwrap_or_else(|| local.to_string());
        let collector = camio_oast::Collector::new(base_auth.clone());
        let handle = camio_oast::OastServer::new(collector.clone())
            .on_interaction(|i| {
                eprintln!(
                    "  OAST callback: {} {} from {}",
                    i.method, i.target, i.source
                );
            })
            .spawn(listener)
            .context("starting OAST collector")?;
        eprintln!(
            "OAST collector on {local} (callback base http://{base_auth}/) — probing inputs for blind SSRF…"
        );
        let ssrf = camio_active::run_oast_ssrf(
            &base,
            &send,
            &collector,
            std::time::Duration::from_millis(args.oast_settle_ms),
        );
        findings.extend(ssrf);
        handle.stop_and_join();
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else {
        print_findings(&findings);
        println!("\n{} finding(s) from the active scan.", findings.len());
    }
    if args.save {
        let mut n = 0;
        for f in &findings {
            if store.borrow_mut().insert_finding(f).is_ok() {
                n += 1;
            }
        }
        println!("saved {n} finding(s) to {}", args.db.display());
    }
    Ok(())
}

// ===========================================================================
// AI assistant (optional, BYO key)
// ===========================================================================

#[derive(Copy, Clone, ValueEnum)]
enum AiProviderArg {
    NvidiaNim,
    Openai,
    Ollama,
}

#[derive(Parser)]
struct AiArgs {
    /// The prompt (free text; multiple words are joined).
    prompt: Vec<String>,
    /// Provider; default auto-detects from env (CAMIO_AI_PROVIDER / available key, else Ollama).
    #[arg(long, value_enum)]
    provider: Option<AiProviderArg>,
    /// Model id (else the provider default or CAMIO_AI_MODEL).
    #[arg(long)]
    model: Option<String>,
    /// Optional system prompt.
    #[arg(long)]
    system: Option<String>,
    /// Translate the prompt into a CamioQL query instead of a chat answer.
    #[arg(long)]
    camioql: bool,
}

fn ai_cmd(args: AiArgs) -> Result<()> {
    let prompt = args.prompt.join(" ");
    if prompt.trim().is_empty() {
        bail!("give a prompt, e.g.  camio ai \"explain this CSRF defence\"");
    }
    let default_model = |p: AiProviderArg| match p {
        AiProviderArg::NvidiaNim => "meta/llama-3.1-70b-instruct",
        AiProviderArg::Openai => "gpt-4o-mini",
        AiProviderArg::Ollama => "llama3.1",
    };
    let cfg = match args.provider {
        Some(p) => {
            let model = args
                .model
                .clone()
                .unwrap_or_else(|| default_model(p).to_string());
            match p {
                AiProviderArg::NvidiaNim => AiConfig::nvidia_nim(model),
                AiProviderArg::Openai => AiConfig::openai(model),
                AiProviderArg::Ollama => AiConfig::ollama(model),
            }
        }
        None => {
            let mut c = AiConfig::from_env();
            if let Some(m) = args.model.clone() {
                c.model = m;
            }
            c
        }
    };
    if !cfg.is_ready() {
        bail!(
            "AI not configured: provider {} has no API key. Set NVIDIA_API_KEY (NVIDIA NIM) or OPENAI_API_KEY, or use --provider ollama with a local Ollama.",
            cfg.provider
        );
    }
    let client = AiClient::new(cfg).map_err(|e| anyhow::anyhow!("{e}"))?;
    let messages = if args.camioql {
        camio_ai::nl_to_camioql(&prompt)
    } else {
        let mut m = Vec::new();
        if let Some(s) = &args.system {
            m.push(Message::system(s.clone()));
        }
        m.push(Message::user(prompt));
        m
    };
    let response = client.chat(&messages).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{response}");
    Ok(())
}

// ===========================================================================
// Native desktop app
// ===========================================================================

#[derive(Parser)]
struct AppArgs {
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Allow active (fuzz) actions from the app. Off by default.
    #[arg(long)]
    allow_active: bool,
}

fn app_cmd(args: AppArgs) -> Result<()> {
    let profile = profile_for(args.preset);
    let scope = build_scope(&args.scope_include, &args.scope_exclude, args.allow_private)?;
    let policy = Policy {
        allow_active: args.allow_active,
        ..Policy::safe()
    };
    let cfg = camio_app::AppConfig {
        db: args.db,
        profile,
        scope,
        policy,
    };
    camio_app::run(cfg).map_err(|e| anyhow::anyhow!("{e}"))
}

// ===========================================================================
// Web UI
// ===========================================================================

#[derive(Parser)]
struct UiArgs {
    /// Address to bind (loopback by default, plan §16).
    #[arg(long, default_value = "127.0.0.1:8787")]
    addr: String,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Allow active (fuzz) actions from the UI. Off by default.
    #[arg(long)]
    allow_active: bool,
}

fn ui_cmd(args: UiArgs) -> Result<()> {
    let profile = profile_for(args.preset);
    let scope = build_scope(&args.scope_include, &args.scope_exclude, args.allow_private)?;
    let policy = Policy {
        allow_active: args.allow_active,
        ..Policy::safe()
    };
    let cfg = camio_web::WebConfig {
        addr: args.addr.clone(),
        db: args.db.clone(),
        profile,
        scope,
        policy,
    };
    camio_web::serve(cfg).context("serving the web UI")
}

// ===========================================================================
// AI guard
// ===========================================================================

#[derive(Subcommand)]
enum AiCmd {
    /// Bind a session — commit scope + targets + allowed action classes to a
    /// signed capability, keep the key in `~/.config/camio/ai-keys/`, print the
    /// binding JSON for the AI to carry.
    Bind(AiBindArgs),
    /// Verify a binding against its on-disk key. Prints OK or the error.
    Verify(AiVerifyArgs),
    /// Authorize a chain file (JSON) — materialize it, re-check every URL
    /// against the binding, print the ready-to-send request plan.
    AuthorizeChain(AiAuthorizeChainArgs),
    /// Re-check the integrity-locked paths against the binding's pinned
    /// hash. Refuses with `IntegrityBreach` if a file/dir has changed.
    CheckIntegrity(AiCheckIntegrityArgs),
}

#[derive(Parser)]
struct AiCheckIntegrityArgs {
    /// Path to a binding JSON file.
    binding: String,
    /// Extra paths to re-check in addition to the defaults. The set must
    /// match what the binding was issued with — any mismatch is a breach.
    #[arg(long = "lock-path")]
    lock_paths: Vec<PathBuf>,
    #[arg(long = "key-dir")]
    key_dir: Option<PathBuf>,
}

#[derive(Parser)]
struct AiBindArgs {
    /// Optional session id. Defaults to a random one derived from the time.
    #[arg(long = "session-id")]
    session_id: Option<String>,
    /// Scope include rule (CamioQL), repeatable.
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    /// Scope exclude rule (CamioQL), repeatable.
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    /// Authorized target URL — at least one is required. Hashed at host level
    /// (scheme://host[:port]); the AI may hit any path on these hosts.
    #[arg(long = "target", required = true)]
    targets: Vec<String>,
    /// Allowed action classes (repeatable). Choose from: read, mutating,
    /// active, destructive. Defaults to read-only.
    #[arg(long = "allow")]
    allow: Vec<String>,
    /// Optional binding lifetime in seconds (0 or unset = no expiry).
    #[arg(long = "ttl-secs", default_value_t = 0)]
    ttl_secs: u64,
    /// Directory to persist the per-session key. Default
    /// `$XDG_CONFIG_HOME/camio/ai-keys` (or `~/.config/camio/ai-keys`).
    #[arg(long = "key-dir")]
    key_dir: Option<PathBuf>,
    /// Pretty-print the binding JSON.
    #[arg(long = "pretty")]
    pretty: bool,
    /// Pin on-disk integrity — snapshot the Camio binary, `~/.config/camio`,
    /// and `plugins/` at bind time and fold their SHA-256 into the signed
    /// binding. Any subsequent change (new plugin dropped, binary swapped,
    /// key file replaced) causes the next guard check to refuse.
    #[arg(long = "lock")]
    lock: bool,
    /// Extra paths to add to the integrity lock (repeatable). Implies `--lock`.
    #[arg(long = "lock-path")]
    lock_paths: Vec<PathBuf>,
}

#[derive(Parser)]
struct AiVerifyArgs {
    /// Path to a binding JSON file. Use `-` for stdin.
    binding: String,
    /// Key directory (same default as `camio ai bind`).
    #[arg(long = "key-dir")]
    key_dir: Option<PathBuf>,
}

#[derive(Parser)]
struct AiAuthorizeChainArgs {
    /// Path to a binding JSON file.
    #[arg(long = "binding", required = true)]
    binding: PathBuf,
    /// Path to a chain JSON file with the shape documented in
    /// `docs/AI-SAFETY.md`.
    #[arg(long = "chain", required = true)]
    chain: PathBuf,
    /// Key directory.
    #[arg(long = "key-dir")]
    key_dir: Option<PathBuf>,
}

fn ai_guard_cmd(action: AiCmd) -> Result<()> {
    match action {
        AiCmd::Bind(a) => ai_bind(a),
        AiCmd::Verify(a) => ai_verify(a),
        AiCmd::AuthorizeChain(a) => ai_authorize_chain(a),
        AiCmd::CheckIntegrity(a) => ai_check_integrity(a),
    }
}

fn default_key_dir(override_: Option<PathBuf>) -> PathBuf {
    if let Some(p) = override_ {
        return p;
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("camio").join("ai-keys")
}

fn save_key(dir: &std::path::Path, session_id: &str, key_bytes: &[u8; 32]) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(format!("{session_id}.key"));
    std::fs::write(&path, hex_encode(key_bytes))
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(&path, perms);
    }
    Ok(path)
}

fn load_key(dir: &std::path::Path, session_id: &str) -> Result<camio_core::SessionKey> {
    let path = dir.join(format!("{session_id}.key"));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {} (did you `camio ai bind` first?)", path.display()))?;
    let bytes = hex_decode(text.trim())
        .map_err(|_| anyhow::anyhow!("invalid hex in {}", path.display()))?;
    if bytes.len() != 32 {
        bail!("key file {} is not 32 bytes", path.display());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(camio_core::SessionKey::from_bytes(arr))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(s: &str) -> std::result::Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let from_hex = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    };
    let mut i = 0;
    while i < b.len() {
        out.push((from_hex(b[i])? << 4) | from_hex(b[i + 1])?);
        i += 2;
    }
    Ok(out)
}

fn parse_action(s: &str) -> Result<camio_core::ActionClass> {
    use camio_core::ActionClass;
    match s.trim().to_ascii_lowercase().as_str() {
        "read" => Ok(ActionClass::Read),
        "mutating" | "mutate" | "send" => Ok(ActionClass::Mutating),
        "active" => Ok(ActionClass::Active),
        "destructive" | "destroy" => Ok(ActionClass::Destructive),
        other => bail!("unknown action class `{other}` (want: read|mutating|active|destructive)"),
    }
}

fn ai_bind(args: AiBindArgs) -> Result<()> {
    // Build scope rules from CamioQL strings.
    let mut rules: Vec<camio_core::ScopeRule> = Vec::new();
    for r in &args.scope_include {
        rules.push(camio_core::ScopeRule::include(r).with_context(|| format!("scope rule `{r}`"))?);
    }
    for r in &args.scope_exclude {
        rules.push(camio_core::ScopeRule::exclude(r).with_context(|| format!("scope rule `{r}`"))?);
    }

    // Parse allowed actions (default to read).
    let allowed = if args.allow.is_empty() {
        vec![camio_core::ActionClass::Read]
    } else {
        args.allow
            .iter()
            .map(|s| parse_action(s))
            .collect::<Result<Vec<_>>>()?
    };

    let session_id = args.session_id.unwrap_or_else(|| {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("ai-{t:x}")
    });

    let key = camio_core::SessionKey::generate();
    let key_dir = default_key_dir(args.key_dir);
    let raw = key.expose_for_persist();
    let key_path = save_key(&key_dir, &session_id, &raw)?;

    let expires = if args.ttl_secs == 0 {
        0
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        now.saturating_add(args.ttl_secs.saturating_mul(1000))
    };
    let want_lock = args.lock || !args.lock_paths.is_empty();
    let binding = if want_lock {
        let mut paths = camio_core::default_integrity_paths();
        paths.extend(args.lock_paths.iter().cloned());
        camio_core::bind_session_with_integrity(
            &session_id,
            &rules,
            &args.targets,
            &allowed,
            &paths,
            expires,
            &key,
        )
        .with_context(|| "bind_session_with_integrity failed (malformed target or unreadable lock path?)")?
    } else {
        camio_core::bind_session(&session_id, &rules, &args.targets, &allowed, expires, &key)
            .with_context(|| "bind_session failed (malformed target?)")?
    };
    eprintln!("stored key at {}", key_path.display());
    eprintln!("session_id = {session_id}");
    if want_lock {
        eprintln!("integrity-locked ({} paths)", {
            let mut paths = camio_core::default_integrity_paths();
            paths.extend(args.lock_paths.iter().cloned());
            paths.len()
        });
    }
    let json = if args.pretty {
        serde_json::to_string_pretty(&binding)?
    } else {
        serde_json::to_string(&binding)?
    };
    println!("{json}");
    Ok(())
}

fn ai_check_integrity(args: AiCheckIntegrityArgs) -> Result<()> {
    let text = if args.binding == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else {
        std::fs::read_to_string(&args.binding)
            .with_context(|| format!("reading {}", args.binding))?
    };
    let binding: camio_core::SessionBinding =
        serde_json::from_str(&text).context("parsing binding JSON")?;
    let dir = default_key_dir(args.key_dir);
    let _key = load_key(&dir, &binding.session_id)?;
    let mut paths = camio_core::default_integrity_paths();
    paths.extend(args.lock_paths);
    match camio_core::verify_integrity(&binding, &paths) {
        Ok(()) if binding.integrity_hash.is_empty() => {
            println!("ok  no integrity lock on this binding");
            Ok(())
        }
        Ok(()) => {
            println!("ok  integrity matches ({} paths)", paths.len());
            Ok(())
        }
        Err(e) => bail!("{e}"),
    }
}

fn ai_verify(args: AiVerifyArgs) -> Result<()> {
    let text = if args.binding == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else {
        std::fs::read_to_string(&args.binding)
            .with_context(|| format!("reading {}", args.binding))?
    };
    let binding: camio_core::SessionBinding =
        serde_json::from_str(&text).context("parsing binding JSON")?;
    let dir = default_key_dir(args.key_dir);
    let key = load_key(&dir, &binding.session_id)?;
    match camio_core::verify_binding(&binding, &key) {
        Ok(()) => {
            println!(
                "ok  session={}  targets={}  actions=[{}]",
                binding.session_id,
                binding.target_hashes.len(),
                binding.allowed_actions.join(",")
            );
            Ok(())
        }
        Err(e) => bail!("{e}"),
    }
}

fn ai_authorize_chain(args: AiAuthorizeChainArgs) -> Result<()> {
    use camio_automate::{authorize_chain_steps, Chain, ChainState, ChainStep};

    let binding_text = std::fs::read_to_string(&args.binding)
        .with_context(|| format!("reading {}", args.binding.display()))?;
    let binding: camio_core::SessionBinding = serde_json::from_str(&binding_text)?;
    let key = load_key(&default_key_dir(args.key_dir), &binding.session_id)?;

    // Load the chain spec as untyped JSON — avoids bringing `serde` into
    // scope just for a transient reader struct.
    let chain_text = std::fs::read_to_string(&args.chain)
        .with_context(|| format!("reading {}", args.chain.display()))?;
    let json: serde_json::Value = serde_json::from_str(&chain_text)?;

    let mut chain = Chain::new();
    let steps_json = json
        .get("steps")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("chain spec needs a `steps` array"))?;
    for s in steps_json {
        let label = s
            .get("label")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("every step needs a `label`"))?;
        let url = s
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("every step needs a `url`"))?;
        let method = s.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
        let mut req = camio_core::HttpRequest::get(url);
        req.method = method.to_string();
        if let Some(hs) = s.get("headers").and_then(|v| v.as_array()) {
            for h in hs {
                if let Some(pair) = h.as_array() {
                    if pair.len() == 2 {
                        if let (Some(n), Some(v)) = (pair[0].as_str(), pair[1].as_str()) {
                            req.headers.push(n.to_string(), v.to_string());
                        }
                    }
                }
            }
        }
        if let Some(body) = s.get("body").and_then(|v| v.as_str()) {
            if !body.is_empty() {
                req.body = camio_core::Body::from_text(body.to_string());
            }
        }
        chain = chain.push(ChainStep::new(label, req));
    }
    let mut state = ChainState::new();
    if let Some(obj) = json.get("state").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                state.insert(k.clone(), s.to_string());
            }
        }
    }
    match authorize_chain_steps(&chain, &state, &binding, &key) {
        Ok(steps) => {
            println!(
                "authorized: {} step(s) — ready to send through the scope-gated engine",
                steps.len()
            );
            for s in &steps {
                println!("  [{}] {} {}", s.step_label, s.request.method, s.request.url);
            }
            Ok(())
        }
        Err(e) => bail!("refused: {e}"),
    }
}
