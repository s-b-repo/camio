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

use anyhow::{bail, Context, Result};
use camio_ai::{AiClient, AiConfig, Message};
use camio_automate::{AttackType, Baseline, Campaign, PayloadSet};
use camio_convert::Transform;
use camio_core::{
    ActionClass, Body, Finding, FingerprintPolicy, FingerprintProfile, HttpExchange, HttpRequest,
    MatchReplaceRule, MatchTarget, Policy, PolicyOutcome, Query, RuleSet, Scope, ScopeRule,
    Severity, SiteMap, Source,
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
    /// Run passive security checks over stored history (Scanner).
    Scan(ScanArgs),
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
    /// Opt-in ACTIVE scan (reflected XSS, error-based SQLi, open redirect) via the matched engine.
    Activescan(ActiveArgs),
    /// Ask the optional AI assistant (NVIDIA NIM / OpenAI / Ollama; BYO key via env).
    Ai(AiArgs),
    /// Launch the native desktop app — every capability in one window.
    App(AppArgs),
    /// Launch the local web UI — every capability in your browser (loopback-only).
    Ui(UiArgs),
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
    query: String,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    #[arg(long, default_value_t = 50)]
    limit: usize,
    /// Print full exchanges as JSON instead of a summary table.
    #[arg(long)]
    json: bool,
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

fn profile_for(preset: Preset) -> FingerprintProfile {
    let mut p = FingerprintProfile::new(
        format!(
            "win-firefox-{}-{}",
            camio_core::ALIGNED_FIREFOX_MAJOR,
            preset.label()
        ),
        engine::PINNED_VERSION,
    );
    p.policy = preset.policy();
    p
}

/// Build a [`Scope`] from CLI include/exclude CamioQL rules.
fn build_scope(includes: &[String], excludes: &[String], allow_private: bool) -> Result<Scope> {
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
        Command::Scan(args) => scan_cmd(args),
        Command::Fuzz(args) => fuzz_cmd(args),
        Command::Discover(args) => discover_cmd(args),
        Command::Import(args) => import_cmd(args),
        Command::Sequencer(args) => sequencer_cmd(args),
        Command::Sitemap(args) => sitemap_cmd(args),
        Command::Payloads(args) => payloads_cmd(args),
        Command::Activescan(args) => activescan_cmd(args),
        Command::Ai(args) => ai_cmd(args),
        Command::App(args) => app_cmd(args),
        Command::Ui(args) => ui_cmd(args),
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
        FpCmd::Show { preset, format } => {
            let profile = profile_for(preset);
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
    let profile = profile_for(args.preset);
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
    let store = open_store(&args.db)?;
    let query = Query::compile(&args.query).map_err(|e| anyhow::anyhow!("{e}"))?;
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
}

fn scan_cmd(args: ScanArgs) -> Result<()> {
    let mut store = open_store(&args.db)?;
    let q =
        Query::compile(args.query.as_deref().unwrap_or("")).map_err(|e| anyhow::anyhow!("{e}"))?;
    let exchanges = store.query(&q, args.limit)?;
    let report = camio_scan::scan_all(&exchanges);
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
        let mut n = 0;
        for f in &report.findings {
            if store.insert_finding(f).is_ok() {
                n += 1;
            }
        }
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
    if let Some(set) = camio_automate::builtin_pack(spec) {
        return Ok(set);
    }
    let path = PathBuf::from(spec);
    if path.exists() {
        let text =
            std::fs::read_to_string(&path).with_context(|| format!("reading payloads {spec}"))?;
        return Ok(PayloadSet::from_lines(spec, &text));
    }
    bail!("payloads `{spec}` is not a built-in pack (see `camio payloads`) or an existing file");
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
        let mut n = 0;
        for ex in &result.exchanges {
            if store.insert(ex).is_ok() {
                n += 1;
            }
        }
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
    match &args.name {
        None => {
            println!("Built-in payload packs (for AUTHORIZED testing only):");
            for name in camio_automate::builtin_packs() {
                let n = camio_automate::builtin_pack(name)
                    .map(|s| s.len())
                    .unwrap_or(0);
                println!("  {:<14} {} payload(s)", name, n);
            }
        }
        Some(name) => {
            let set = camio_automate::builtin_pack(name)
                .ok_or_else(|| anyhow::anyhow!("unknown pack `{name}` (see `camio payloads`)"))?;
            for p in &set.payloads {
                println!("{p}");
            }
        }
    }
    Ok(())
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
fn build_ruleset(specs: &[String]) -> Result<RuleSet> {
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
    Ok(match s.to_ascii_lowercase().as_str() {
        "url" => MatchTarget::Url,
        "method" => MatchTarget::Method,
        "body" => MatchTarget::RequestBody,
        other => bail!("unknown rewrite part `{other}` (use url|method|body|header=NAME)"),
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
                "Would actively probe {} (scope {}) for reflected XSS, error-based SQLi and open redirect.",
                args.url,
                decision.as_str()
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
    let findings = {
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
        camio_active::run_active(&base, &send)
    };

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
    println!(
        "Camio web UI → open http://{} in your browser (Ctrl-C to stop).",
        args.addr
    );
    camio_web::serve(cfg).context("serving the web UI")
}
