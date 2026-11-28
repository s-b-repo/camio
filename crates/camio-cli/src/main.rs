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

use anyhow::{anyhow, bail, Context, Result};
use camio_ai::{AiClient, AiConfig, Message};
use camio_automate::{AttackType, Baseline, Campaign, PayloadSet};
use camio_convert::Transform;
use camio_core::{
    ActionClass, Approval, Body, Finding, FindingId, FingerprintPolicy, FingerprintProfile,
    HttpExchange, HttpRequest, MatchReplaceRule, MatchTarget, PlanSummary, Policy, PolicyOutcome,
    Query, RuleSet, Scope, ScopeDecision, ScopeRule, Severity, SiteMap, Source,
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
    /// Capture the managed browser's traffic over WebDriver BiDi (F05). Launch
    /// first with `--remote-debugging-port`, then point `capture` at that port.
    Capture(CaptureArgs),
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
    /// Decode a JWT, and with --analyze audit it for weaknesses (jwt_tool-style).
    Jwt(JwtArgs),
    /// Compute a file's Shodan favicon hash (http.favicon.hash) for asset
    /// correlation — pivot in Shodan/Censys/FOFA to find related hosts.
    FaviconHash(FaviconHashArgs),
    /// Byte/line diff between two files (Comparer).
    Compare(CompareArgs),
    /// Unified diff between two stored exchanges' responses (or requests) (F09).
    Diff(DiffArgs),
    /// Run passive security checks over stored history (Scanner).
    Scan(ScanArgs),
    /// Synthesize an attack surface for a stored exchange: detect stack + WAF,
    /// then recommend payload-DB categories, evasion encodings, and a scope rule.
    AttackSurface(AttackSurfaceArgs),
    /// Triage stored findings: list them, or set a finding's status (F14).
    Findings(FindingsArgs),
    /// Retest a stored finding (F14): re-send its evidence request through the
    /// matched engine, re-run the checks, and report whether it still fires.
    Retest(RetestArgs),
    /// Suggest multi-step attack chains composed from the stored findings —
    /// which vulnerabilities combine into a higher-impact exploitation path.
    Chains(ChainsArgs),
    /// Export stored findings as a redacted report (Markdown/JSON/HTML/SARIF).
    Report(ReportArgs),
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
    /// One-shot automated recon + active sweep: fingerprint the stack, run every
    /// active check (incl. the HTTP method audit), and bucket responses by status.
    Autopilot(AutopilotArgs),
    /// Headless DAST run for CI (F25): baseline + active + passive scan over the
    /// matched engine, emitting a machine-readable result contract and a stable
    /// exit code (0 clean, 3 findings at/above --fail-on). Non-interactive.
    Dast(DastArgs),
    /// Run a typed workflow document (F12): a validated, forward-only pipeline of
    /// request/scan/transform steps. Validate-only without --confirm when it sends.
    Workflow(WorkflowCmdArgs),
    /// Ask the optional AI assistant (NVIDIA NIM / OpenAI / Ollama; BYO key via env).
    Ai(AiArgs),
    /// CAPTCHA tools: detect widgets in a captured response, or solve a
    /// simple image CAPTCHA with the local OCR backend.
    Captcha {
        #[command(subcommand)]
        action: CaptchaCmd,
    },
    /// Proof-of-work tools: detect an anti-bot PoW wall (Anubis/mCaptcha/
    /// hashcash) in a response, or solve a SHA-256 PoW challenge locally.
    Pow {
        #[command(subcommand)]
        action: PowCmd,
    },
    /// Print realistic, blend-in random User-Agent string(s), weighted by
    /// real-world market share and deterministic from --seed.
    Useragent(UseragentArgs),
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
    /// Probe authorized targets with ProjectDiscovery httpx (reachability +
    /// technology metadata), or import an existing httpx JSONL export.
    Probe(ProbeArgs),
    /// List durable background-task records, optionally reconciling
    /// interrupted ones (F03 restart recovery).
    Tasks(TasksArgs),
    /// Read the durable audit log of gated actions — who did what, to what, and
    /// whether it was allowed, confirmed or refused (F02).
    Audit(AuditArgs),
    /// Group exchanges, findings, and tasks into named collections (F18).
    Collection {
        #[command(subcommand)]
        action: CollectionCmd,
    },
    /// Named response baselines: pin a stored exchange, then diff later ones
    /// against it to see what changed (F09 compare-to-baseline).
    Baseline {
        #[command(subcommand)]
        action: BaselineCmd,
    },
    /// Emit a CycloneDX SBOM of the build's dependency graph (F26 supply chain).
    Sbom(SbomArgs),
    /// Review stored traffic, import evidence, and manage the workspace.
    Workbench(workbench::Args),
    /// Verify checksums and evidence references in an exported review bundle.
    VerifyBundle { file: PathBuf },
    /// Write a consistent backup of a workspace database to a new file (F01),
    /// optionally encrypted with a passphrase (F04).
    Backup {
        /// Destination path (must not already exist).
        dest: PathBuf,
        #[arg(long, default_value = "camio.db")]
        db: PathBuf,
        /// Encrypt the backup with the passphrase in $CAMIO_BACKUP_PASSPHRASE
        /// (XChaCha20-Poly1305 + PBKDF2; plan §F04).
        #[arg(long)]
        encrypt: bool,
        /// Decrypt a previously `--encrypt`ed backup at this path into `dest`
        /// (passphrase from $CAMIO_BACKUP_PASSPHRASE); `db` is ignored.
        #[arg(long, value_name = "FILE")]
        decrypt: Option<PathBuf>,
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
    /// Generate a realistic, blend-in random persona (coherent OS/GPU/hardware/
    /// screen from real-world distributions), deterministic from --seed.
    Random {
        /// Seed for reproducibility. Omit for a one-off (time+pid) identity.
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long, value_enum, default_value_t = Preset::Balanced)]
        preset: Preset,
        #[arg(long, value_enum, default_value_t = Format::Json)]
        format: Format,
        /// Emit N personas (a rotation pool) instead of one.
        #[arg(long, default_value_t = 1)]
        count: usize,
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
    /// Use a named, isolated, persistent profile under --profiles-root instead
    /// of --profile (F04). Cookies/storage/IndexedDB stay separate per name; the
    /// name is sanitised to a single safe path segment.
    #[arg(long)]
    profile_name: Option<String>,
    /// Root directory that holds named profiles (with --profile-name).
    #[arg(long, default_value = "profiles")]
    profiles_root: PathBuf,
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    /// OS persona to present: windows|macos|linux (default windows).
    #[arg(long)]
    os: Option<String>,
    /// Launch with a realistic, blend-in random persona from this seed (same
    /// seed ⇒ same identity). Overrides --os. See `fingerprint random`.
    #[arg(long)]
    persona_seed: Option<u64>,
    /// Authorized target URL to open.
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    headless: bool,
    /// Build the command and print it, but do not launch.
    #[arg(long)]
    dry_run: bool,
    /// Enable the WebDriver BiDi remote agent on this loopback port so Camio can
    /// capture/intercept the managed browser's traffic (plan §5, F05).
    #[arg(long)]
    remote_debugging_port: Option<u16>,
    /// Lab profile: allow private/loopback destinations for the opened URL.
    #[arg(long)]
    allow_private: bool,
    /// Also permit link-local / cloud-metadata destinations. Lab mode alone
    /// never un-blocks 169.254.169.254 or fe80::/10.
    #[arg(long)]
    allow_metadata: bool,
    /// Include rule(s) the opened URL must match.
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
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
    /// Send with a realistic, blend-in random persona generated from this seed
    /// (same seed ⇒ same identity). Overrides the fixed default persona so real
    /// traffic carries a generated UA/platform/locale. See `fingerprint random`.
    #[arg(long)]
    persona_seed: Option<u64>,
    /// Scope include rule in CamioQL (repeatable). With none, all non-guarded hosts are in scope.
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    /// Scope exclude rule in CamioQL (repeatable).
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    /// Lab mode: allow private/loopback/metadata destinations.
    #[arg(long)]
    allow_private: bool,
    /// Also permit link-local / cloud-metadata destinations. Lab mode alone
    /// never un-blocks 169.254.169.254 or fe80::/10.
    #[arg(long)]
    allow_metadata: bool,
    /// Match & Replace rule applied to the outgoing request (repeatable).
    /// Format: `PART|FIND|REPLACE`, where PART is url|method|body|header=NAME.
    #[arg(long = "rewrite")]
    rewrites: Vec<String>,
    /// Follow 3xx redirects (Repeater control, F09). Each hop is re-checked
    /// against scope before it is sent; the chain is bounded by --max-redirects.
    #[arg(long)]
    follow_redirects: bool,
    /// Maximum redirect hops to follow with --follow-redirects.
    #[arg(long, default_value_t = 5)]
    max_redirects: u32,
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
    /// Also permit link-local / cloud-metadata destinations. Lab mode alone
    /// never un-blocks 169.254.169.254 or fe80::/10.
    #[arg(long)]
    allow_metadata: bool,
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
    /// Also permit link-local / cloud-metadata destinations. Lab mode alone
    /// never un-blocks 169.254.169.254 or fe80::/10.
    #[arg(long)]
    allow_metadata: bool,
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

/// Build a profile for a preset, choosing the persona from a persona `seed`
/// when one is given: a seed yields a **realistic, blend-in random persona**
/// ([`camio_core::Persona::random`]) so real traffic carries a generated
/// identity, not the fixed default. Without a seed, falls back to the `os`
/// persona (or the Windows default). This is the one place the CLI turns the
/// `--persona-seed` flag into an actual identity, so every send path (send,
/// launch, crawl, activescan) stays consistent.
pub(crate) fn profile_for_persona(
    preset: Preset,
    os: Option<camio_core::BrowserOs>,
    persona_seed: Option<u64>,
) -> FingerprintProfile {
    match persona_seed {
        Some(seed) => {
            let mut p = FingerprintProfile::new(
                format!("random-{seed}-{}", preset.label()),
                engine::PINNED_VERSION,
            );
            p.policy = preset.policy();
            p.persona = camio_core::Persona::random(seed);
            p
        }
        None => profile_for_os(preset, os),
    }
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
    build_scope_full(includes, excludes, allow_private, false)
}

/// [`build_scope`] plus the separate link-local/metadata opt-in. Lab mode
/// (`allow_private`) alone never un-blocks 169.254.169.254 or fe80::/10 — the
/// operator must opt in explicitly (plan §16).
pub(crate) fn build_scope_full(
    includes: &[String],
    excludes: &[String],
    allow_private: bool,
    allow_metadata: bool,
) -> Result<Scope> {
    let mut scope = Scope::new();
    if allow_private {
        scope = scope.allowing_private();
    }
    if allow_metadata {
        scope = scope.allowing_metadata();
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
        Command::Capture(args) => capture_cmd(args),
        Command::Send(args) => send_cmd(args),
        Command::Query(args) => query_cmd(args),
        Command::History(args) => history_cmd(args),
        Command::Scope(args) => scope_cmd(args),
        Command::Convert(args) => convert_cmd(args),
        Command::Jwt(args) => jwt_cmd(args),
        Command::FaviconHash(args) => favicon_hash_cmd(args),
        Command::Compare(args) => compare_cmd(args),
        Command::Diff(args) => diff_cmd(args),
        Command::Scan(args) => scan_cmd(args),
        Command::AttackSurface(args) => attack_surface_cmd(args),
        Command::Findings(args) => findings_cmd(args),
        Command::Retest(args) => retest_cmd(args),
        Command::Chains(args) => chains_cmd(args),
        Command::Report(args) => report_cmd(args),
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
        Command::Autopilot(args) => autopilot_cmd(args),
        Command::Dast(args) => dast_cmd(args),
        Command::Workflow(args) => workflow_cmd(args),
        Command::Ai(args) => ai_cmd(args),
        Command::Captcha { action } => captcha_cmd(action),
        Command::Pow { action } => pow_cmd(action),
        Command::Useragent(args) => useragent_cmd(args),
        Command::App(args) => app_cmd(args),
        Command::Ui(args) => ui_cmd(args),
        Command::Proxy(args) => proxy::run(args),
        Command::Oast(args) => oast_cmd(args),
        Command::Nuclei(args) => nuclei_cmd(args),
        Command::Crawl(args) => crawl_cmd(args),
        Command::Subfinder(args) => subfinder_cmd(args),
        Command::Integrations => integrations_cmd(),
        Command::Probe(args) => probe_cmd(args),
        Command::Tasks(args) => tasks_cmd(args),
        Command::Audit(args) => audit_cmd(args),
        Command::Collection { action } => collection_cmd(action),
        Command::Baseline { action } => baseline_cmd(action),
        Command::Sbom(args) => sbom_cmd(args),
        Command::Workbench(args) => workbench::run(args),
        Command::VerifyBundle { file } => workbench::verify_bundle(&file),
        Command::Backup { dest, db, encrypt, decrypt } => backup_cmd(dest, db, encrypt, decrypt),
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
        FpCmd::Random {
            seed,
            preset,
            format,
            count,
        } => {
            if count == 0 {
                bail!("--count must be at least 1");
            }
            // A fixed seed is reproducible; no seed means a one-off identity.
            let base_seed = seed.unwrap_or_else(|| {
                use camio_core::SplitMix64;
                SplitMix64::from_entropy().next_u64()
            });
            let personas = camio_core::Persona::random_pool(base_seed, count);
            for (i, persona) in personas.into_iter().enumerate() {
                let mut profile = FingerprintProfile::new(
                    format!("random-{base_seed}-{i}"),
                    engine::PINNED_VERSION,
                );
                profile.policy = preset.policy();
                profile.persona = persona;
                match format {
                    Format::UserJs => print!("{}", profile.to_user_js()),
                    Format::Camoufox => println!(
                        "{}",
                        serde_json::to_string_pretty(&profile.to_camoufox_config())?
                    ),
                    Format::Json => println!("{}", serde_json::to_string_pretty(&profile)?),
                }
            }
            Ok(())
        }
    }
}

#[derive(Parser)]
struct CaptureArgs {
    /// The browser's remote-agent port (the --remote-debugging-port passed to
    /// `camio launch`).
    #[arg(long, default_value_t = 9222)]
    port: u16,
    /// Capture for this many seconds, then stop and store what was seen.
    #[arg(long, default_value_t = 30)]
    duration: u64,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    #[arg(long)]
    json: bool,
}

/// Capture the managed browser's traffic over WebDriver BiDi (plan §5, F05).
///
/// This is pure observation of the operator's own authorized browser — nothing is
/// sent by Camio — so it is not scope-gated the way sends are; it records what the
/// browser fetched. It orchestrates the tested BiDi pieces: connect the WebSocket
/// transport, open a session, subscribe to network events, and accumulate the
/// completed responses until the duration elapses.
fn capture_cmd(args: CaptureArgs) -> Result<()> {
    use camio_engine::bidi::{
        session_new_command, subscribe_network_command, BiDiCapture, BiDiTransport,
    };
    use camio_engine::ws::WebSocketBiDiTransport;

    let addr = format!("127.0.0.1:{}", args.port);
    eprintln!("connecting to the browser's BiDi agent at ws://{addr}/session …");
    let mut transport = WebSocketBiDiTransport::connect(&addr, &addr, "/session")
        .with_context(|| format!("connecting to the BiDi agent on {addr} (launch with --remote-debugging-port {}?)", args.port))?;

    // Standard BiDi start-up: open a session, then subscribe to network events.
    transport
        .send(&session_new_command(1))
        .context("sending session.new")?;
    transport
        .send(&subscribe_network_command(2))
        .context("subscribing to network events")?;
    // Wake periodically so the deadline is honoured even without traffic.
    transport
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .ok();

    let mut capture = BiDiCapture::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(args.duration);
    eprintln!("capturing for {}s …", args.duration);
    while std::time::Instant::now() < deadline {
        match transport.recv() {
            Ok(Some(message)) => capture.ingest(&message),
            Ok(None) => {
                eprintln!("the browser closed the BiDi connection");
                break;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue; // no message this interval; re-check the deadline
            }
            Err(e) => return Err(anyhow::anyhow!("BiDi receive failed: {e}")),
        }
    }

    let exchanges = capture.into_exchanges();
    let mut store =
        Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
    let stored = store
        .insert_exchanges(&exchanges)
        .with_context(|| format!("storing captured exchanges in {}", args.db.display()))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&exchanges)?);
    }
    println!(
        "captured {} exchange(s); stored {stored} in {}.",
        exchanges.len(),
        args.db.display()
    );
    Ok(())
}

/// Resolve a named browser profile to an isolated directory under `root` (F04).
/// The name is reduced to a single path segment of `[A-Za-z0-9._-]` (every other
/// character becomes `-`); an empty result or a bare `.`/`..` is rejected
/// (`None`), so a profile name can never traverse out of the profiles root.
fn named_profile_dir(root: &std::path::Path, name: &str) -> Option<PathBuf> {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = safe.trim_matches('-');
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return None;
    }
    Some(root.join(trimmed))
}

fn launch_cmd(args: LaunchArgs) -> Result<()> {
    // Opening a URL in the managed browser sends traffic, so it runs the same
    // SSRF/scope guard as `camio send` (plan §16) instead of bypassing it.
    if let Some(url) = args.url.as_deref() {
        let scope = build_scope_full(
            &args.scope_include,
            &[],
            args.allow_private,
            args.allow_metadata,
        )?;
        let decision = scope.decide(&HttpExchange::new(HttpRequest::get(url), Source::Browser));
        match decision {
            ScopeDecision::Blocked => bail!(
                "refused: {url} is blocked by the SSRF/safety guard (link-local/metadata \
                 need an explicit --allow-metadata)"
            ),
            ScopeDecision::OutOfScope => {
                bail!("refused: {url} is out of scope for this launch (add --scope-include)")
            }
            ScopeDecision::InScope => {}
        }
    }
    let cam = Camoufox::find(&args.install_root)?;
    let profile = profile_for_persona(args.preset, parse_os(&args.os)?, args.persona_seed);
    // A named profile resolves to an isolated, persistent directory; otherwise
    // the explicit --profile path is used (F04 named isolated profiles).
    let profile_dir = match &args.profile_name {
        Some(name) => named_profile_dir(&args.profiles_root, name).ok_or_else(|| {
            anyhow::anyhow!("invalid --profile-name `{name}` (use letters, digits, . _ -)")
        })?,
        None => args.profile.clone(),
    };
    let opts = LaunchOptions {
        url: args.url.clone(),
        headless: args.headless,
        dry_run: args.dry_run,
        remote_debugging_port: args.remote_debugging_port,
    };

    if args.dry_run {
        cam.prepare_profile(&profile_dir, &profile)?;
        let cmd = cam.build_command(&profile_dir, &profile, &opts);
        println!("Would launch: {:?}", cmd.get_program());
        for a in cmd.get_args() {
            println!("  arg: {}", a.to_string_lossy());
        }
        println!("  (+{} fingerprint env vars)", cmd.get_envs().count());
        println!(
            "  profile prefs written to {}",
            profile_dir.join("user.js").display()
        );
        return Ok(());
    }

    println!(
        "Launching Camoufox ({}) with '{}' fingerprint policy...",
        engine::PINNED_VERSION,
        args.preset.label()
    );
    if let Some(mut child) = cam.launch(&profile_dir, &profile, &opts)? {
        println!("Browser started (pid {}). Close it to exit.", child.id());
        let status = child.wait().context("waiting for browser")?;
        println!("Browser exited: {status}");
    }
    Ok(())
}

/// Record one durable audit entry (plan §F02), best-effort: an audit-write
/// failure is reported but never masks or aborts the action being audited. The
/// store is opened for just this write so callers that hold no store (a refused
/// send) can still leave a trail.
fn best_effort_audit(db: &std::path::Path, entry: &camio_store::NewAudit) {
    let recorded = Store::open(db).and_then(|s| s.record_audit(entry));
    if let Err(e) = recorded {
        eprintln!("warning: could not write audit log to {}: {e}", db.display());
    }
}

/// Compact detail string for a send audit entry: method + scope decision, never
/// the body.
fn send_audit_detail(method: &str, decision: ScopeDecision) -> String {
    format!("{method} scope={}", decision.as_str())
}

fn send_cmd(args: SendArgs) -> Result<()> {
    let profile = profile_for_persona(args.preset, None, args.persona_seed);
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;

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
            // A refused send is a security-relevant event: record it before
            // bailing so the audit trail shows what was attempted and blocked.
            best_effort_audit(
                &args.db,
                &camio_store::NewAudit::new("cli", "ACTIVE", "send", "denied")
                    .target(req.url.clone())
                    .detail(send_audit_detail(&req.method, decision)),
            );
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
            let mut ex = eng.send(req, Source::Replay).context("sending request")?;

            let mut store =
                Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
            let mut id = store.insert(&ex).context("storing exchange")?;

            // Durable audit (plan §F02): the send was allowed and performed.
            if let Err(e) = store.record_audit(
                &camio_store::NewAudit::new("cli", "ACTIVE", "send", "allowed")
                    .target(ex.request.url.clone())
                    .detail(send_audit_detail(&ex.request.method, decision)),
            ) {
                eprintln!("warning: could not write audit log: {e}");
            }

            // Follow redirects (F09): each hop is re-decided against scope (so the
            // SSRF guard and include rules still apply) before it is sent.
            let mut hops = 0u32;
            if args.follow_redirects {
                while hops < args.max_redirects {
                    let Some(resp) = ex.response.as_ref() else { break };
                    if !(300..=399).contains(&resp.status) {
                        break;
                    }
                    let Some(location) = resp.headers.get("Location") else { break };
                    let status = resp.status;
                    let Some(next_url) = resolve_url(&ex.request.url, location) else {
                        eprintln!("redirect: could not resolve Location `{location}`; stopping");
                        break;
                    };
                    let mut next = HttpRequest::get(&next_url);
                    // 307/308 preserve the method and body; 301/302/303 go to GET
                    // (the common browser/relayed behaviour).
                    let keeps_body = status == 307 || status == 308;
                    if keeps_body {
                        next.method = ex.request.method.clone();
                        next.body = ex.request.body.clone();
                    }
                    // Carry the request headers to the next hop, following the same
                    // rules a browser/curl use:
                    //  - drop `Host` (recomputed from the new URL);
                    //  - drop `Authorization`/`Cookie` when the host changes, so
                    //    credentials never leak to a different origin;
                    //  - drop body/content headers when the method falls back to
                    //    GET (there is no body on those hops).
                    // Without this the preserved 307/308 body went out with no
                    // Content-Type, and auth/session context was lost on same-host
                    // hops.
                    let cross_host = next.host() != ex.request.host();
                    next.headers =
                        forward_redirect_headers(&ex.request, cross_host, keeps_body);
                    let hop_decision =
                        scope.decide(&HttpExchange::new(next.clone(), Source::Replay));
                    if !hop_decision.is_sendable() {
                        eprintln!(
                            "redirect: next hop {next_url} is {} — not followed",
                            hop_decision.as_str()
                        );
                        break;
                    }
                    hops += 1;
                    eprintln!("redirect {hops}: {status} → {next_url}");
                    ex = eng.send(next, Source::Replay).context("sending redirect")?;
                    id = store.insert(&ex).context("storing redirect exchange")?;
                }
            }

            if args.json {
                println!("{}", serde_json::to_string_pretty(&ex)?);
            } else {
                print_response(&ex);
                if hops > 0 {
                    println!("  followed {hops} redirect(s)");
                }
                println!("  stored as #{} in {}", id.0, args.db.display());
            }
            Ok(())
        }
    }
}

/// Resolve a redirect `Location` (absolute, scheme-relative, origin-relative, or
/// path-relative) against the request URL it came from. Returns `None` if either
/// cannot be parsed, so an unresolvable redirect simply stops the chain.
fn resolve_url(base: &str, location: &str) -> Option<String> {
    camio_core::resolve_redirect(base, location)
}

/// Build the header list for a redirect hop, following browser/curl rules:
/// drop `Host` (it is recomputed from the new URL), drop `Authorization`/`Cookie`
/// across a host change so credentials never leak to another origin, and drop the
/// body/content headers when the hop falls back to GET (there is no body then).
/// `keeps_body` is true only for 307/308, which preserve the method and body.
fn forward_redirect_headers(
    from: &HttpRequest,
    cross_host: bool,
    keeps_body: bool,
) -> camio_core::HeaderList {
    let mut out = camio_core::HeaderList::new();
    for h in from.headers.iter() {
        let name = h.name.as_str();
        let is_cred = name.eq_ignore_ascii_case("authorization")
            || name.eq_ignore_ascii_case("cookie");
        let is_content = name.eq_ignore_ascii_case("content-type")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("content-encoding")
            || name.eq_ignore_ascii_case("transfer-encoding");
        if name.eq_ignore_ascii_case("host")
            || (cross_host && is_cred)
            || (!keeps_body && is_content)
        {
            continue;
        }
        out.push(h.name.clone(), h.value.clone());
    }
    out
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
    // Body filters must read real bodies; the summary path does not, and the
    // old length-sized placeholder bodies made it allocate Σ(body lengths)
    // per row for a table that only shows method/status/URL (plan §5).
    let results = if query.needs_body() || args.json {
        store.query(&query, args.limit)?
    } else {
        store.query_metadata(&query, args.limit)?
    };
    print_exchange_list(&results, args.json)
}

fn history_cmd(args: HistoryArgs) -> Result<()> {
    let store = open_store(&args.db)?;
    let results = if args.json {
        store.recent(args.limit)?
    } else {
        // No bodies needed for the summary table: metadata only.
        let empty = Query::compile("").map_err(|e| anyhow::anyhow!("{e}"))?;
        store.query_metadata(&empty, args.limit)?
    };
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
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
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
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
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
            // A payload that transforms to hex but not to UTF-8 should not
            // print as "hex: " with nothing after it.
            let hex = Transform::HexEncode
                .apply(&out)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_else(|| {
                    eprintln!(
                        "camio: could not hex-encode {} bytes of binary output",
                        out.len()
                    );
                    String::new()
                });
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
    /// Analyze for weaknesses: alg:none, a guessable HMAC secret, and claim
    /// hygiene (missing/expired exp, future nbf) — inspired by jwt_tool.
    #[arg(long)]
    analyze: bool,
    /// Wordlist file (one secret per line) for the HMAC crack. Without it, a
    /// built-in list of common secrets is used. Implies --analyze.
    #[arg(long)]
    wordlist: Option<PathBuf>,
}

#[derive(Parser)]
struct FaviconHashArgs {
    /// Path to the favicon file (`.ico`/`.png`/…). Use `-` to read stdin.
    file: PathBuf,
}

fn favicon_hash_cmd(args: FaviconHashArgs) -> Result<()> {
    let bytes = if args.file.as_os_str() == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?
    };
    let hash = camio_convert::favicon_hash(&bytes);
    println!("{hash}");
    eprintln!("Pivot: shodan `http.favicon.hash:{hash}` · censys/fofa equivalents.");
    Ok(())
}

fn jwt_cmd(args: JwtArgs) -> Result<()> {
    let parts = camio_convert::decode_jwt(&args.token).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("header : {}", parts.header_json);
    println!("payload: {}", parts.payload_json);
    println!("signature (b64url): {}", parts.signature_b64url);

    if args.analyze || args.wordlist.is_some() {
        let wordlist: Vec<String> = match &args.wordlist {
            Some(p) => std::fs::read_to_string(p)
                .with_context(|| format!("reading wordlist {}", p.display()))?
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
            None => Vec::new(),
        };
        let a = camio_convert::analyze_jwt(&args.token, &wordlist, None)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("\nAnalysis (alg: {}):", a.alg);
        if let Some(secret) = &a.cracked_secret {
            println!("  !! HMAC secret cracked: `{secret}`");
        }
        if a.issues.is_empty() {
            println!("  (no weaknesses found)");
        }
        for issue in &a.issues {
            println!("  [{:?}] {} — {}", issue.severity, issue.title, issue.detail);
        }
    } else {
        println!(
            "\nNote: the signature is NOT verified — treat all claims as untrusted input. \
             Pass --analyze to audit for weaknesses."
        );
    }
    Ok(())
}

// ===========================================================================
// CAPTCHA (detect + solve)
// ===========================================================================

#[derive(Subcommand)]
enum CaptchaCmd {
    /// Detect CAPTCHA widgets (reCAPTCHA, hCaptcha, Turnstile, image CAPTCHAs)
    /// in an HTML file or stdin.
    Detect {
        /// Path to an HTML file. If omitted or `-`, read from stdin.
        #[arg(default_value = "-")]
        html: PathBuf,
    },
    /// Solve a local image-CAPTCHA with the OCR backend.
    Solve {
        /// Path to the image file (PNG, or any format tesseract can read).
        image: PathBuf,
        /// `digits` restricts the alphabet to 0-9; `alphanum` adds letters.
        #[arg(long, value_enum, default_value_t = OcrAlphabet::Digits)]
        alphabet: OcrAlphabet,
        /// Force a specific backend.
        #[arg(long, value_enum, default_value_t = OcrBackendArg::Auto)]
        backend: OcrBackendArg,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum OcrAlphabet {
    Digits,
    Alphanum,
    Any,
}

#[derive(Copy, Clone, ValueEnum)]
enum OcrBackendArg {
    Auto,
    Tesseract,
    Builtin,
}

fn captcha_cmd(cmd: CaptchaCmd) -> Result<()> {
    match cmd {
        CaptchaCmd::Detect { html } => {
            let body = if html.as_os_str() == "-" {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                std::fs::read_to_string(&html)
                    .with_context(|| format!("reading {}", html.display()))?
            };
            let hits = camio_scan::detect_captcha_in_html(&body);
            if hits.is_empty() {
                println!("(no CAPTCHA widgets detected)");
                return Ok(());
            }
            println!("Detected CAPTCHA widgets:");
            for kind in hits {
                println!("  - {}: {}", kind.as_str(), kind.solver_hint());
            }
            Ok(())
        }
        CaptchaCmd::Solve {
            image,
            alphabet,
            backend,
        } => {
            let bytes = std::fs::read(&image)
                .with_context(|| format!("reading {}", image.display()))?;
            let mut cfg = match alphabet {
                OcrAlphabet::Digits => camio_ai::OcrConfig::digits(),
                OcrAlphabet::Alphanum => camio_ai::OcrConfig::alphanum(),
                OcrAlphabet::Any => camio_ai::OcrConfig::default(),
            };
            cfg.backend = match backend {
                OcrBackendArg::Auto => camio_ai::OcrBackend::Auto,
                OcrBackendArg::Tesseract => camio_ai::OcrBackend::Tesseract,
                OcrBackendArg::Builtin => camio_ai::OcrBackend::Builtin,
            };
            match camio_ai::solve_captcha(&bytes, &cfg) {
                Ok(r) => {
                    println!("text      : {}", r.text);
                    println!("backend   : {:?}", r.backend);
                    println!("confidence: {}%", r.confidence);
                    Ok(())
                }
                Err(e) => bail!("OCR failed: {e}"),
            }
        }
    }
}

// ===========================================================================
// Proof-of-work (detect + solve)
// ===========================================================================

#[derive(Subcommand)]
enum PowCmd {
    /// Detect a proof-of-work anti-bot wall (Anubis/mCaptcha/hashcash) in an
    /// HTML file or stdin.
    Detect {
        /// Path to an HTML file. If omitted or `-`, read from stdin.
        #[arg(default_value = "-")]
        html: PathBuf,
    },
    /// Solve a SHA-256 proof-of-work challenge locally.
    Solve {
        /// The challenge string the nonce is appended to.
        challenge: String,
        /// Difficulty: leading zero hex chars (hex mode) or bits (--bits).
        #[arg(long, default_value_t = 4)]
        difficulty: u32,
        /// Interpret --difficulty as leading zero BITS (hashcash/mCaptcha)
        /// instead of leading zero hex characters (Anubis).
        #[arg(long)]
        bits: bool,
        /// Parse `challenge` as an Anubis challenge JSON blob instead of a raw
        /// string (reads the challenge + difficulty from the JSON).
        #[arg(long)]
        anubis: bool,
    },
}

fn pow_cmd(cmd: PowCmd) -> Result<()> {
    use camio_automate::pow;
    match cmd {
        PowCmd::Detect { html } => {
            let body = if html.as_os_str() == "-" {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                std::fs::read_to_string(&html)
                    .with_context(|| format!("reading {}", html.display()))?
            };
            let hits = camio_scan::detect_pow_in_response(&body, None, None);
            if hits.is_empty() {
                println!("(no proof-of-work wall detected)");
                return Ok(());
            }
            println!("Detected proof-of-work wall(s):");
            for system in hits {
                println!("  - {}: {}", system.as_str(), system.solver_hint());
            }
            Ok(())
        }
        PowCmd::Solve {
            challenge,
            difficulty,
            bits,
            anubis,
        } => {
            let ch = if anubis {
                pow::parse_anubis(&challenge)
                    .ok_or_else(|| anyhow!("could not parse an Anubis challenge from the input"))?
            } else if bits {
                pow::PowChallenge::hashcash(challenge, difficulty)
            } else {
                pow::PowChallenge::anubis(challenge, difficulty)
            };
            match pow::solve(&ch) {
                Ok(sol) => {
                    println!("nonce      : {}", sol.nonce);
                    println!("nonce_str  : {}", sol.nonce_string);
                    println!("hash       : {}", sol.hash_hex);
                    println!("iterations : {}", sol.iterations);
                    Ok(())
                }
                Err(e) => bail!("proof-of-work solve failed: {e}"),
            }
        }
    }
}

// ===========================================================================
// Random User-Agents
// ===========================================================================

#[derive(Parser)]
struct UseragentArgs {
    /// Seed for reproducibility. Omit for a one-off (time+pid) pick.
    #[arg(long)]
    seed: Option<u64>,
    /// Restrict to one family: firefox|chrome|safari|edge.
    #[arg(long)]
    family: Option<String>,
    /// Print N user-agents.
    #[arg(long, default_value_t = 1)]
    count: usize,
    /// Print the family/OS/version alongside each UA string.
    #[arg(long)]
    verbose: bool,
}

fn useragent_cmd(args: UseragentArgs) -> Result<()> {
    use camio_core::{BrowserFamily, SplitMix64};
    if args.count == 0 {
        bail!("--count must be at least 1");
    }
    let family = match args.family.as_deref() {
        None => None,
        Some(f) => Some(match f.to_ascii_lowercase().as_str() {
            "firefox" => BrowserFamily::Firefox,
            "chrome" => BrowserFamily::Chrome,
            "safari" => BrowserFamily::Safari,
            "edge" => BrowserFamily::Edge,
            other => bail!("unknown --family `{other}` (use firefox|chrome|safari|edge)"),
        }),
    };
    let base = args
        .seed
        .unwrap_or_else(|| SplitMix64::from_entropy().next_u64());
    for i in 0..args.count as u64 {
        let seed = base ^ i.wrapping_mul(0x9E37_79B9);
        let ua = match family {
            Some(f) => camio_core::random_user_agent_for(seed, f),
            None => camio_core::random_user_agent(seed),
        };
        if args.verbose {
            println!(
                "[{} {} v{}] {}",
                ua.family.as_str(),
                ua.os.as_str(),
                ua.major_version,
                ua.string
            );
        } else {
            println!("{}", ua.string);
        }
    }
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
                    "rule": f.rule, "status": s.as_str(), "note": n,
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
                "  #{:<4} {:<8} {:<14} {:<20} {}{note}",
                f.id.0,
                f.severity.as_str(),
                s.as_str(),
                truncate(f.rule.as_deref().unwrap_or("—"), 20),
                truncate(&f.title, 50)
            );
        }
        eprintln!("{} finding(s).", rows.len());
    }
    Ok(())
}

#[derive(Parser)]
struct ChainsArgs {
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    #[arg(long)]
    json: bool,
}

/// Suggest composed attack chains from the stored findings (vector chaining).
fn chains_cmd(args: ChainsArgs) -> Result<()> {
    let store = Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
    let findings = store.list_findings()?;
    let chains = camio_automate::suggest_attack_chains(&findings);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&chains)?);
        return Ok(());
    }
    if chains.is_empty() {
        println!(
            "no multi-step attack chains suggested from {} stored finding(s)",
            findings.len()
        );
        return Ok(());
    }
    println!(
        "{} attack chain(s) composed from {} finding(s):",
        chains.len(),
        findings.len()
    );
    for c in &chains {
        println!("\n▶ {} [{}]", c.name, c.severity);
        for (i, step) in c.steps.iter().enumerate() {
            println!("  {}. {step}", i + 1);
        }
        println!("  rationale: {}", c.rationale);
    }
    Ok(())
}

#[derive(Parser)]
struct RetestArgs {
    /// The stored finding to retest.
    finding_id: i64,
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    #[arg(long)]
    allow_metadata: bool,
    /// Update the finding's status from the result: `confirmed` if it still
    /// fires, `fixed` if it no longer does. Off by default (report only).
    #[arg(long)]
    mark: bool,
    /// Actually re-send (traffic). Without it, prints the plan and exits 0.
    #[arg(long)]
    confirm: bool,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
}

/// Retest a stored finding (F14): replay its evidence request and re-run the
/// checks to see whether the issue is still present or appears fixed. Sending is
/// fully gated — ACTIVE class, scope re-checked on the replay, `--confirm`
/// required — and the attempt is recorded in the audit log (F02).
fn retest_cmd(args: RetestArgs) -> Result<()> {
    let store = Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
    let finding = store
        .list_findings()?
        .into_iter()
        .find(|f| f.id.0 == args.finding_id)
        .ok_or_else(|| anyhow::anyhow!("no finding #{} in {}", args.finding_id, args.db.display()))?;
    let origin_id = *finding.evidence.first().ok_or_else(|| {
        anyhow::anyhow!("finding #{} has no evidence exchange to replay", args.finding_id)
    })?;
    let origin = store
        .get(origin_id)?
        .ok_or_else(|| anyhow::anyhow!("evidence exchange #{} is no longer stored", origin_id.0))?;
    let base = origin.request.clone();

    let profile = profile_for_persona(args.preset, None, None);
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
    let decision = scope.decide(&HttpExchange::new(base.clone(), Source::Scanner));
    let policy = Policy {
        allow_active: true,
        allow_destructive: false,
        require_confirmation: true,
    };
    match policy.gate_action_with(ActionClass::Active, &scope, decision, args.confirm) {
        PolicyOutcome::Deny(reason) => {
            best_effort_audit(
                &args.db,
                &camio_store::NewAudit::new("cli", "ACTIVE", "retest", "denied")
                    .target(base.url.clone())
                    .detail(format!("finding #{}: {reason}", args.finding_id)),
            );
            bail!("refused: {reason}");
        }
        PolicyOutcome::NeedsConfirmation(reason) => {
            eprintln!("{reason}.");
            eprintln!(
                "Retest would, in scope {}: re-send {} {} and re-run the checks that could \
                 reproduce finding #{} ({}). Re-run with --confirm (authorized targets only).",
                decision.as_str(),
                base.method,
                base.url,
                args.finding_id,
                finding.rule.as_deref().unwrap_or(&finding.title),
            );
            return Ok(());
        }
        PolicyOutcome::Allow => {}
    }

    let eng = matched_engine(&profile).context("building matched request engine")?;
    let store = RefCell::new(store);
    let send = |req: HttpRequest| -> Option<HttpExchange> {
        if !scope
            .decide(&HttpExchange::new(req.clone(), Source::Scanner))
            .is_sendable()
        {
            return None;
        }
        match eng.send(req, Source::Scanner) {
            Ok(mut ex) => match store.borrow_mut().insert(&ex) {
                Ok(id) => {
                    ex.id = id;
                    Some(ex)
                }
                Err(e) => {
                    camio_core::note_failure("storing a retest exchange", e);
                    Some(ex)
                }
            },
            Err(e) => {
                eprintln!("retest send failed: {e}");
                None
            }
        }
    };

    // Re-run both the active checks (which send their own probes) and the passive
    // checks over a fresh fetch — the producing check is among them regardless of
    // the finding's class.
    let mut reproduced = camio_active::run_active(&base, &send);
    if let Some(ex) = send(base.clone()) {
        reproduced.extend(camio_scan::scan_exchange(&ex));
    }

    // Does the same issue reappear? Prefer the stable rule id; fall back to the
    // title for older findings that predate rule provenance.
    let still_present = reproduced.iter().any(|f| match (&finding.rule, &f.rule) {
        (Some(orig), Some(now)) => orig == now,
        _ => f.title == finding.title,
    });

    let label = finding.rule.as_deref().unwrap_or(&finding.title);
    if still_present {
        println!("finding #{} ({label}) is STILL PRESENT on retest.", args.finding_id);
    } else {
        println!(
            "finding #{} ({label}) was NOT reproduced — it appears fixed (verify manually).",
            args.finding_id
        );
    }

    if args.mark {
        let status = if still_present {
            camio_store::FindingStatus::Confirmed
        } else {
            camio_store::FindingStatus::Fixed
        };
        store
            .borrow_mut()
            .set_finding_status(FindingId(args.finding_id), status, Some("set by retest"))?;
        println!("  status → {}", status.as_str());
    }

    if let Err(e) = store.borrow().record_audit(
        &camio_store::NewAudit::new("cli", "ACTIVE", "retest", "allowed")
            .target(base.url.clone())
            .detail(format!(
                "finding #{} {}",
                args.finding_id,
                if still_present { "still-present" } else { "not-reproduced" }
            )),
    ) {
        eprintln!("warning: could not write audit log: {e}");
    }
    Ok(())
}

#[derive(Copy, Clone, ValueEnum)]
enum ReportFmt {
    Markdown,
    Json,
    Html,
    Sarif,
}

impl ReportFmt {
    fn to_store(self) -> camio_store::ReportFormat {
        match self {
            ReportFmt::Markdown => camio_store::ReportFormat::Markdown,
            ReportFmt::Json => camio_store::ReportFormat::Json,
            ReportFmt::Html => camio_store::ReportFormat::Html,
            ReportFmt::Sarif => camio_store::ReportFormat::Sarif,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum ReportStatus {
    All,
    Open,
    Confirmed,
    Resolved,
    Dismissed,
}

impl ReportStatus {
    fn to_state(self) -> Option<camio_store::ReviewState> {
        match self {
            ReportStatus::All => None,
            ReportStatus::Open => Some(camio_store::ReviewState::Open),
            ReportStatus::Confirmed => Some(camio_store::ReviewState::Confirmed),
            ReportStatus::Resolved => Some(camio_store::ReviewState::Resolved),
            ReportStatus::Dismissed => Some(camio_store::ReviewState::Dismissed),
        }
    }
}

#[derive(Parser)]
struct ReportArgs {
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = ReportFmt::Markdown)]
    format: ReportFmt,
    /// Only include findings in this review state (default: all).
    #[arg(long, value_enum, default_value_t = ReportStatus::All)]
    status: ReportStatus,
    /// Write the report to this file instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,
    /// CI gate: exit non-zero if any reported finding is at least this severity
    /// (info|low|medium|high|critical). The report is still written first.
    #[arg(long)]
    fail_on: Option<String>,
}

fn report_cmd(args: ReportArgs) -> Result<()> {
    let store = open_store(&args.db)?;
    let report = store
        .finding_report(args.status.to_state())
        .context("building findings report")?;
    let rendered = report
        .render(args.format.to_store())
        .context("rendering report")?;
    match &args.out {
        Some(path) => {
            std::fs::write(path, &rendered)
                .with_context(|| format!("writing report to {}", path.display()))?;
            eprintln!(
                "wrote {} report ({} finding(s)) to {}",
                args.format.to_store().label(),
                report.findings.len(),
                path.display()
            );
        }
        None => print!("{rendered}"),
    }

    // CI gate (plan §F25 headless/CI): the report is emitted first, then the
    // process fails if anything meets the threshold, so a pipeline can both keep
    // the artifact and block the merge.
    if let Some(sev) = &args.fail_on {
        let threshold = parse_severity(sev)?;
        let over: usize = report
            .findings
            .iter()
            .filter(|e| e.severity >= threshold)
            .count();
        if over > 0 {
            bail!(
                "report gate: {over} finding(s) at or above {} severity",
                threshold.as_str()
            );
        }
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

#[derive(Parser)]
struct AttackSurfaceArgs {
    /// CamioQL filter; the most recent matching exchange is analyzed. Omit to
    /// analyze the most recent exchange in history.
    query: Option<String>,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Print the full attack surface as JSON.
    #[arg(long)]
    json: bool,
}

fn attack_surface_cmd(args: AttackSurfaceArgs) -> Result<()> {
    let store = open_store(&args.db)?;
    let q =
        Query::compile(args.query.as_deref().unwrap_or("")).map_err(|e| anyhow::anyhow!("{e}"))?;
    let exchanges = store.query_with_bodies(&q, 1)?;
    let ex = exchanges
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no stored exchange matched (capture traffic first, or widen the query)"))?;
    let s = camio_scan::analyze_attack_surface(&ex);
    if args.json {
        // Render via a plain serializable view (AttackSurface isn't Serialize;
        // build the JSON explicitly).
        let techs: Vec<_> = s
            .technologies
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name, "version": t.version, "categories": t.categories,
                    "confidence": t.confidence, "implied": t.implied,
                })
            })
            .collect();
        let v = serde_json::json!({
            "host": s.host,
            "technologies": techs,
            "wafs": s.wafs,
            "takeover_candidate": s.takeover,
            "suggested_payload_categories": s.suggested_payload_categories,
            "suggested_evasion_encodings": s.suggested_encodings.iter().map(|e| format!("{e:?}")).collect::<Vec<_>>(),
            "suggested_scope_rule": s.suggested_scope_rule,
            "notes": s.notes,
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    println!("host: {}", s.host.as_deref().unwrap_or("-"));
    print!("technologies:");
    if s.technologies.is_empty() {
        println!(" (none detected)");
    } else {
        println!();
        for t in &s.technologies {
            let ver = t.version.as_deref().map(|v| format!(" {v}")).unwrap_or_default();
            let cat = t.categories.first().cloned().unwrap_or_default();
            let imp = if t.implied { " [implied]" } else { "" };
            println!("  - {}{ver} ({cat}){imp}", t.name);
        }
    }
    if !s.wafs.is_empty() {
        println!("waf/cdn: {}", s.wafs.join(", "));
    }
    if let Some(service) = &s.takeover {
        println!("takeover candidate: {service}");
    }
    println!("payload categories: {}", s.suggested_payload_categories.join(", "));
    if !s.suggested_encodings.is_empty() {
        let encs: Vec<String> = s.suggested_encodings.iter().map(|e| format!("{e:?}")).collect();
        println!("evasion encodings: {}", encs.join(", "));
    }
    if let Some(rule) = &s.suggested_scope_rule {
        println!("scope rule: {rule}");
    }
    println!();
    for note in &s.notes {
        println!("note: {note}");
    }
    Ok(())
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
    /// Also permit link-local / cloud-metadata destinations. Lab mode alone
    /// never un-blocks 169.254.169.254 or fe80::/10.
    #[arg(long)]
    allow_metadata: bool,
    /// Throttle to at most this many requests/second (F11). Unlimited when unset.
    #[arg(long)]
    rate: Option<f64>,
    /// Actually run the campaign (an ACTIVE test). Without this, only the plan is shown.
    #[arg(long)]
    confirm: bool,
    /// Bind the run to the plan hash printed by the preview (plan §4.3). The
    /// run is refused if the plan drifted since that hash was approved.
    #[arg(long)]
    approve: Option<String>,
    /// Resume an interrupted campaign: skip the first N generated requests
    /// (already-sent work is never replayed, plan §4.2).
    #[arg(long, default_value_t = 0)]
    resume_from: u64,
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
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
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

    // The exact plan an approval is bound to (plan §4.3): the normalized
    // target, the action class, the request budget, and the policy revision.
    let plan_summary = PlanSummary::new(ActionClass::Active, vec![args.url.trim().to_string()])
        .with_max_requests(args.budget)
        .with_policy(&policy);
    let plan_hash = plan_summary.plan_hash();
    println!("  plan hash          : {plan_hash}");
    if args.approve.is_none() {
        println!("\nApprove this exact plan with --approve {plan_hash} (and --confirm).");
    }
    match policy.gate_action_with(ActionClass::Active, &scope, decision, args.confirm) {
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

    // Approval binding (plan §4.3): the operator must approve the *printed*
    // plan; any drift (different target, budget, or policy) changes the hash
    // and is refused rather than silently executed under a stale approval.
    if let Some(approved) = args.approve.as_deref() {
        let approval = Approval::bind(plan_summary.clone(), camio_core::approval::now_ms())
            .granted_by("camio fuzz --approve");
        if approved.trim() != approval.plan_hash {
            bail!(
                "this approval does not cover the current plan (approved {approved}, plan is {plan_hash}); \
                 re-run the preview and approve the printed hash"
            );
        }
        if let Err(reason) = approval.allows(&plan_summary, camio_core::approval::now_ms()) {
            bail!("refused: approval does not cover this plan: {reason}");
        }
        println!("approval bound to plan {plan_hash}");
    } else {
        bail!(
            "an approved plan hash is required before an ACTIVE campaign (plan §4.3): \
             re-run the preview and pass --approve {plan_hash}"
        );
    }

    // Resume: only the unexecuted remainder of an approved plan runs (plan
    // §4.2). The approval hash above still binds the plan, so a drifted plan is
    // refused rather than silently replayed under a stale approval.
    let resume_from = usize::try_from(args.resume_from).unwrap_or(usize::MAX);
    let generated = camio_automate::generate_from(&campaign, resume_from)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if resume_from > 0 {
        eprintln!(
            "resuming after {resume_from} request(s) — executing the remaining {}",
            generated.len()
        );
    }
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
    let limiter = camio_core::RateLimiter::new(None, args.rate.filter(|r| *r > 0.0));
    let mut results = Vec::new();
    let mut skipped = 0usize;
    for g in &generated {
        let pr = HttpExchange::new(g.request.clone(), Source::Automate);
        if !scope.decide(&pr).is_sendable() {
            continue; // never send out of scope (plan §16)
        }
        limiter.acquire(&g.request.host().unwrap_or_default());
        match eng.send(g.request.clone(), Source::Automate) {
            Ok(ex) => {
                store.insert(&ex).with_context(|| {
                    format!("storing campaign exchange in {}", args.db.display())
                })?;
                results.push((g.payloads.clone(), ex));
            }
            Err(e) => {
                skipped += 1;
                eprintln!("send failed: {e}");
            }
        }
    }

    let classified = camio_automate::classify(&results, baseline.as_ref(), None);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&classified)?);
    } else {
        print_classified(&classified, args.show);
    }
    if skipped > 0 {
        // A partially-failed campaign is not a clean run (plan §4.2).
        println!("\n{skipped} request(s) could not be sent (see errors above).");
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
    // a non-UTF-8 body is skipped on purpose: it is not editable as text.
    // audit-allow: B4
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
    // Body filters real bytes; otherwise metadata only (no padded placeholders).
    let exchanges = if q.needs_body() || args.json {
        store.query(&q, args.limit)?
    } else {
        store.query_metadata(&q, args.limit)?
    };
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
    /// A Burp items XML export, a HAR archive, or (with --openapi) an
    /// OpenAPI 3.x / Swagger 2.0 JSON document.
    file: PathBuf,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Treat the file as an OpenAPI/Swagger spec: generate one request per
    /// path+method operation (request-only; nothing is sent).
    #[arg(long)]
    openapi: bool,
    /// Treat the file as a GraphQL introspection result: generate one POST per
    /// root Query/Mutation field. Requires --base as the GraphQL endpoint.
    #[arg(long)]
    graphql: bool,
    /// For --openapi: origin to build requests against (overrides the spec's
    /// server/host). For --graphql: the GraphQL endpoint URL to POST to.
    #[arg(long)]
    base: Option<String>,
    /// Parse and report only; do not store.
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    json: bool,
}

fn import_cmd(args: ImportArgs) -> Result<()> {
    let data =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    let result = if args.openapi {
        let text = String::from_utf8(data)
            .map_err(|_| anyhow::anyhow!("OpenAPI spec must be UTF-8 JSON"))?;
        camio_import::import_openapi(&text, args.base.as_deref())
            .map_err(|e| anyhow::anyhow!("{e}"))?
    } else if args.graphql {
        let text = String::from_utf8(data)
            .map_err(|_| anyhow::anyhow!("GraphQL introspection must be UTF-8 JSON"))?;
        let endpoint = args
            .base
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--graphql requires --base <graphql endpoint URL>"))?;
        camio_import::import_graphql(&text, endpoint).map_err(|e| anyhow::anyhow!("{e}"))?
    } else {
        camio_import::import_bytes(&data).map_err(|e| anyhow::anyhow!("{e}"))?
    };
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
    /// Emit JSON instead of plain text: the catalog (with per-pack counts) when
    /// listing, or `{pack, count, payloads}` for a named pack.
    #[arg(long)]
    json: bool,
}

fn payloads_cmd(args: PayloadsArgs) -> Result<()> {
    let db = camio_automate::load_payload_db();
    if args.json {
        let value = match &args.name {
            None => {
                let builtin: Vec<_> = camio_automate::builtin_packs()
                    .iter()
                    .map(|name| {
                        serde_json::json!({
                            "pack": name,
                            "count": camio_automate::builtin_pack(name).map(|s| s.len()).unwrap_or(0),
                        })
                    })
                    .collect();
                let database: Vec<_> = db
                    .categories
                    .iter()
                    .map(|(name, set)| {
                        serde_json::json!({ "pack": format!("db:{name}"), "count": set.len() })
                    })
                    .collect();
                serde_json::json!({ "builtin": builtin, "database": database })
            }
            Some(name) => {
                let set = resolve_pack(name, &db)
                    .ok_or_else(|| anyhow::anyhow!("unknown pack `{name}` (see `camio payloads`)"))?;
                serde_json::json!({
                    "pack": name,
                    "count": set.payloads.len(),
                    "payloads": set.payloads,
                })
            }
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
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
                println!("      set CAMIO_PAYLOADS_DIR or run from the workspace root to use it.");
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
    /// Chain encodings *in sequence* for WAF evasion (e.g. `url>url` double-URL-
    /// encodes, `html>url` HTML- then URL-encodes). One line per payload. Takes
    /// precedence over --encodings/--context.
    #[arg(long = "chain", conflicts_with_all = ["encodings", "context"])]
    chain: Option<String>,
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
            "url-path",
            "url-query",
            "form",
            "json",
            "json-number",
            "xml",
            "xml-attr",
            "header",
            "cookie",
            "html",
            "html-attr",
            "html-script",
            "html-style",
            "graphql",
            "multipart",
            "raw",
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
            let text =
                std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
            camio_automate::PayloadSet::from_lines(payloads_spec, &text)
        } else {
            bail!(
                "payloads `{payloads_spec}` is not a built-in pack, a DB category, stdin (`-`), or a file"
            );
        }
    };

    // Sequential encoding chain (WAF evasion): compose encodings left-to-right.
    if let Some(spec) = &args.chain {
        let chain = camio_automate::parse_encoding_chain(spec).map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut chained = camio_automate::chain_payload_set(&set, &chain);
        if chained.len() > args.limit {
            chained.truncate(args.limit);
        }
        let label = chain.iter().map(|e| e.name()).collect::<Vec<_>>().join(">");
        match &args.out {
            Some(path) => {
                let body = chained.join("\n") + "\n";
                std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))?;
                eprintln!("wrote {} chained payload(s) [{label}] to {}", chained.len(), path.display());
            }
            None => {
                eprintln!("encode chain `{}`: {} payload(s), chain=[{label}]", set.name, chained.len());
                for p in &chained {
                    println!("{p}");
                }
            }
        }
        return Ok(());
    }

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
            std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))?;
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
                encs.iter().map(|e| e.name()).collect::<Vec<_>>().join(",")
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
fn resolve_pack(spec: &str, db: &camio_automate::PayloadDb) -> Option<camio_automate::PayloadSet> {
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
        // Destructured, so the three-way split is verified by the pattern rather
        // than by a length check the reader has to trust.
        let [part, find, replace] = parts.as_slice() else {
            bail!(
                "--rewrite `{spec}` must be PART|FIND|REPLACE (PART = url|method|body|header=NAME)"
            );
        };
        let target = parse_rewrite_target(part)?;
        let rule = MatchReplaceRule::literal(
            format!("cli-{i}"),
            target,
            find.to_string(),
            replace.to_string(),
            None,
        )
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
    /// Persist interactions into this workspace database (with a retention
    /// policy) so callbacks survive a restart (plan §F15).
    #[arg(long)]
    db: Option<PathBuf>,
    /// Also answer DNS A queries on this address so pure-DNS exfiltration
    /// (blind SSRF by hostname, XXE with an external DTD) correlates (plan §F15).
    #[arg(long)]
    dns_listen: Option<String>,
    /// How many interactions to retain (oldest pruned first).
    #[arg(long, default_value_t = 10_000)]
    retain: usize,
    /// How long to retain interactions (e.g. `7d`, `24h`).
    #[arg(long, default_value = "7d")]
    retain_for: String,
}

/// Parse a simple duration (`7d`, `24h`, `30m`, `3600s`) into seconds.
fn parse_duration_secs(text: &str) -> u64 {
    let text = text.trim();
    let (num, unit) = text.split_at(
        text.find(|c: char| c.is_ascii_alphabetic())
            .unwrap_or(text.len()),
    );
    let n: u64 = num.trim().parse().unwrap_or(0);
    match unit.trim().to_ascii_lowercase().as_str() {
        "d" => n * 24 * 3600,
        "h" => n * 3600,
        "m" => n * 60,
        "s" | "" => n,
        _ => n,
    }
}

fn oast_cmd(args: OastArgs) -> Result<()> {
    let base = args.base.clone().unwrap_or_else(|| args.listen.clone());
    let collector = camio_oast::Collector::new(base.clone());

    if let Some(n) = args.tokens {
        for _ in 0..n.max(1) {
            let t = collector
                .new_token()
                .map_err(|e| anyhow::anyhow!("minting a token: {e}"))?;
            println!(
                "{}    (dns: {})",
                collector.callback_url(&t),
                collector.dns_callback_url(&t)
            );
        }
        return Ok(());
    }

    // Optional durable persistence with a retention policy (plan §F15).
    let durable = match args.db.as_ref() {
        Some(db) => {
            let retention = camio_oast::durable::RetentionPolicy {
                max_interactions: args.retain,
                max_age: std::time::Duration::from_secs(parse_duration_secs(&args.retain_for)),
            };
            let store = Store::open(db).with_context(|| format!("opening {}", db.display()))?;
            Some(camio_oast::durable::DurableCollector::new(
                collector.clone(),
                store,
                retention,
            ))
        }
        None => None,
    };

    let listener = std::net::TcpListener::bind(&args.listen)
        .with_context(|| format!("binding {}", args.listen))?;
    let local = listener.local_addr().context("reading local address")?;
    let sample = collector
        .new_token()
        .map_err(|e| anyhow::anyhow!("minting a sample token: {e}"))?;

    eprintln!("Camio OAST collector listening on {local}");
    eprintln!("  callback base   : http://{base}/");
    eprintln!("  sample token    : {sample}");
    eprintln!("  sample callback : {}", collector.callback_url(&sample));
    if let Some(d) = durable.as_ref() {
        eprintln!(
            "  persistence     : {} (retain {} interaction(s) for {})",
            args.db
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            d.retention().max_interactions,
            args.retain_for,
        );
    }

    // Optional DNS responder for pure-DNS exfiltration correlation.
    let dns_handle = match args.dns_listen.as_ref() {
        Some(addr) => {
            let socket = std::net::UdpSocket::bind(addr)
                .with_context(|| format!("binding DNS on {addr}"))?;
            // The DNS answer points at the collector's own address (IPv4
            // only; an IPv6 bind gets the all-hosts answer, which stays local).
            let answer_ip = match local.ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                std::net::IpAddr::V6(_) => [127, 0, 0, 1],
            };
            // A durable collector gets the DNS lookups too; without a store the
            // in-memory collector records them.
            let sink: std::sync::Arc<dyn camio_oast::dns::DnsSink> = match durable.clone() {
                Some(d) => std::sync::Arc::new(d),
                None => collector.clone(),
            };
            let responder = camio_oast::dns::DnsResponder::new(sink, answer_ip);
            let handle = responder.spawn(socket).context("starting DNS responder")?;
            eprintln!(
                "  DNS responder   : {addr} (A queries answered with {})",
                local.ip()
            );
            Some(handle)
        }
        None => None,
    };

    eprintln!(
        "Plant a token-bearing callback URL in a payload (SSRF/XXE/blind injection);\n\
         interactions that reach this address are logged below. Press Ctrl-C to stop."
    );

    // The hook owns its durable collector (a `'static` closure cannot borrow).
    let durable_hook = durable.clone().map(std::sync::Arc::new);
    let server = camio_oast::OastServer::new(collector).on_interaction(move |i| {
        if let Some(d) = durable_hook.as_ref() {
            if let Err(e) = d.record(i) {
                eprintln!("  (could not persist the interaction: {e})");
            }
        }
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
    let result = server
        .serve_with_listener(listener)
        .context("serving OAST collector");
    if let Some(handle) = dns_handle {
        handle.stop_and_join();
    }
    result
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
    /// Also permit link-local / cloud-metadata destinations. Lab mode alone
    /// never un-blocks 169.254.169.254 or fe80::/10.
    #[arg(long)]
    allow_metadata: bool,
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
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
    let base = HttpRequest::get(&args.url);
    let decision = scope.decide(&HttpExchange::new(base.clone(), Source::Scanner));

    // Nuclei actively probes: in scope + explicit confirmation (plan §16).
    let policy = Policy {
        allow_active: true,
        allow_destructive: false,
        require_confirmation: true,
    };
    match policy.gate_action_with(ActionClass::Active, &scope, decision, args.confirm) {
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
    // A template can match a redirect target or a host the operator never
    // approved; re-decide each matched location and report what was dropped
    // rather than storing it as if in scope.
    let mut findings = findings;
    let mut out_of_scope = Vec::new();
    findings.retain(|f| {
        let matched = f
            .detail
            .lines()
            .find_map(|l| {
                l.strip_prefix("- Matched at: `")
                    .and_then(|v| v.strip_suffix('`'))
            })
            .map(str::to_string);
        match matched {
            Some(location) => {
                let decision = scope.decide(&HttpExchange::new(
                    HttpRequest::get(&location),
                    Source::Scanner,
                ));
                if decision.is_sendable() {
                    true
                } else {
                    out_of_scope.push(location);
                    false
                }
            }
            None => true,
        }
    });
    for dropped in &out_of_scope {
        eprintln!("skipped out-of-scope finding location: {dropped}");
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else {
        print_findings(&findings);
        println!("\n{} finding(s) from nuclei.", findings.len());
    }
    if args.save {
        let mut store =
            Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
        let n = store
            .insert_findings(&findings)
            .with_context(|| format!("saving findings to {}", args.db.display()))?;
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
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Also permit link-local / cloud-metadata destinations. Lab mode alone
    /// never un-blocks 169.254.169.254 or fe80::/10.
    #[arg(long)]
    allow_metadata: bool,
    /// Actually enumerate (an ACTIVE action). Without this, the plan is shown.
    #[arg(long)]
    confirm: bool,
}

fn subfinder_cmd(args: SubfinderArgs) -> Result<()> {
    // Enumeration sends traffic about a domain (to passive sources and, for
    // some sources, to the domain itself), so it goes through the same
    // authorization path as the other external tools (plan §16).
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
    let ex = HttpExchange::new(
        HttpRequest::get(format!("https://{}/", args.domain.trim())),
        Source::Crawler,
    );
    let decision = scope.decide(&ex);
    let policy = Policy {
        allow_active: true,
        allow_destructive: false,
        require_confirmation: true,
    };
    match policy.gate_action_with(ActionClass::Active, &scope, decision, args.confirm) {
        PolicyOutcome::Deny(reason) => bail!("refused: {reason}"),
        PolicyOutcome::NeedsConfirmation(reason) => {
            println!("needs confirmation: {reason}.");
            println!(
                "Would enumerate {} (scope {}). Re-run with --confirm and an explicit \
                 --scope-include rule (authorized targets only).",
                args.domain,
                decision.as_str()
            );
            return Ok(());
        }
        PolicyOutcome::Allow => {}
    }

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
    /// Crawl with a realistic blend-in random persona from this seed. See
    /// `fingerprint random`.
    #[arg(long)]
    persona_seed: Option<u64>,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Also permit link-local / cloud-metadata destinations. Lab mode alone
    /// never un-blocks 169.254.169.254 or fe80::/10.
    #[arg(long)]
    allow_metadata: bool,
    /// Actually crawl. Without this, prints what would run.
    #[arg(long)]
    confirm: bool,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    #[arg(long)]
    json: bool,
}

fn crawl_cmd(args: CrawlArgs) -> Result<()> {
    let profile = profile_for_persona(args.preset, None, args.persona_seed);
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
    let decision = scope.decide(&HttpExchange::new(
        HttpRequest::get(&args.url),
        Source::Crawler,
    ));

    // Crawling sends many requests automatically: in scope + explicit targets +
    // explicit confirmation (plan §16). It is an ACTIVE action like the scanner
    // and the campaign runner, not a one-shot manual send.
    let policy = Policy {
        allow_active: true,
        allow_destructive: false,
        require_confirmation: true,
    };
    match policy.gate_action_with(ActionClass::Active, &scope, decision, args.confirm) {
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
                // A crawl result that is not stored never reaches history or
                // any later query, so a failed insert is not a no-op.
                match store.borrow_mut().insert(&ex) {
                    Ok(id) => {
                        ex.id = id;
                        Some(ex)
                    }
                    Err(e) => {
                        eprintln!("camio: crawled exchange not stored: {e}");
                        None
                    }
                }
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
// httpx integration (external HTTP prober, plan §6)
// ===========================================================================

#[derive(Parser)]
struct ProbeArgs {
    /// Target URLs to probe (explicit project targets, one or more).
    #[arg(required_unless_present = "import")]
    targets: Vec<String>,
    /// Import an existing httpx JSONL export instead of running the tool
    /// (import-only path for hosts where execution is unavailable, plan §6).
    #[arg(long)]
    import: Option<PathBuf>,
    /// Seed targets from the site map of an existing history database
    /// (explicit project inventory, plan §6) instead of listing URLs.
    #[arg(long)]
    from_sitemap: Option<PathBuf>,
    /// Seed targets from a saved CamioQL search, re-run against the same
    /// database (plan §6).
    #[arg(long = "from-saved")]
    from_saved: Option<String>,
    /// Maximum targets to probe in one run (a bound on the whole run).
    #[arg(long)]
    max_probes: Option<usize>,
    /// Skip responses larger than this many bytes (an httpx output bound).
    #[arg(long)]
    max_response_bytes: Option<usize>,
    /// Requests-per-second cap.
    #[arg(long)]
    rate_limit: Option<u32>,
    /// Concurrent probes.
    #[arg(long)]
    concurrency: Option<u32>,
    /// Per-probe timeout in seconds.
    #[arg(long)]
    timeout_secs: Option<u64>,
    /// Follow redirects (off by default; each hop must be in scope).
    #[arg(long)]
    follow_redirects: bool,
    /// Extra args passed verbatim to httpx (after `--`).
    #[arg(last = true)]
    extra: Vec<String>,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Also permit link-local / cloud-metadata destinations. Lab mode alone
    /// never un-blocks 169.254.169.254 or fe80::/10.
    #[arg(long)]
    allow_metadata: bool,
    /// Actually probe (an ACTIVE action). Without this, the plan is shown.
    #[arg(long)]
    confirm: bool,
    /// Persist the raw JSONL as a stored artifact (searchable inventory).
    #[arg(long)]
    db: Option<PathBuf>,
    /// Emit normalized probe results as JSON.
    #[arg(long)]
    json: bool,
}

fn probe_cmd(args: ProbeArgs) -> Result<()> {
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;

    // Import-only path: no execution, no network, parse what's already on disk.
    if let Some(path) = args.import.as_ref() {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let results = camio_integrations::parse_httpx_jsonl(&raw);
        print_probes(&results, args.json)?;
        if let Some(db) = args.db.as_ref() {
            let mut store = Store::open(db).with_context(|| format!("opening {}", db.display()))?;
            let saved = store.import_artifact(
                camio_store::ArtifactFormat::Httpx,
                &raw,
                Some("imported"),
                true,
            )?;
            eprintln!(
                "stored {} observation(s) from {} ({} skipped) in {}",
                saved.records,
                path.display(),
                saved.skipped,
                db.display()
            );
        }
        return Ok(());
    }

    // Seed targets from the project's own inventory when asked: the site map of
    // a history DB, or a saved CamioQL search re-run against it.
    let mut targets = args.targets.clone();
    if args.targets.is_empty() {
        if let Some(db) = args.from_sitemap.as_ref() {
            let store = open_store(db)?;
            let compiled = Query::compile("").map_err(|e| anyhow::anyhow!("{e}"))?;
            let rows = store.query_metadata(&compiled, 5_000)?;
            let map = SiteMap::build(&rows);
            targets.extend(map.origins.keys().cloned());
        } else if let Some(name) = args.from_saved.as_ref() {
            let db = args.db.as_ref().ok_or_else(|| {
                anyhow!("--from-saved re-runs a saved search against a database; pass --db")
            })?;
            let store = open_store(db)?;
            let saved = store
                .list_saved_searches()?
                .into_iter()
                .find(|(n, _)| n == name)
                .map(|(_, q)| q)
                .ok_or_else(|| anyhow!("no saved search named `{name}`"))?;
            let compiled = Query::compile(&saved).map_err(|e| anyhow::anyhow!("{e}"))?;
            let rows = store.query_metadata(&compiled, 5_000)?;
            for ex in &rows {
                targets.push(ex.request.url.clone());
            }
        }
    }
    if targets.is_empty() {
        bail!(
            "no targets: pass URLs, or seed them with --from-sitemap <db> / --from-saved <name> --db <db>"
        );
    }
    if let Some(max) = args.max_probes {
        if targets.len() > max {
            targets.truncate(max);
            eprintln!("capped the probe list at {max} target(s)");
        }
    }

    // Probing is an ACTIVE action under the shared policy (plan §16): each
    // destination must be in scope and approved before it receives traffic.
    let policy = Policy {
        allow_active: true,
        allow_destructive: false,
        require_confirmation: true,
    };
    let mut denied = Vec::new();
    let mut unconfirmed = Vec::new();
    for target in &args.targets {
        let ex = HttpExchange::new(HttpRequest::get(target), Source::Crawler);
        let decision = scope.decide(&ex);
        match policy.gate_action_with(ActionClass::Active, &scope, decision, args.confirm) {
            PolicyOutcome::Deny(reason) => denied.push(format!("{target}: {reason}")),
            PolicyOutcome::NeedsConfirmation(reason) => {
                unconfirmed.push(format!("{target}: {reason}"))
            }
            PolicyOutcome::Allow => {}
        }
    }
    if !denied.is_empty() {
        for d in &denied {
            println!("refused: {d}");
        }
        // A refusal is not a clean run: exit non-zero like every other gate.
        bail!("no target approved for probing");
    }
    if !unconfirmed.is_empty() {
        for u in &unconfirmed {
            println!("needs confirmation: {u}");
        }
        println!(
            "\nWould probe {} target(s) with httpx. Re-run with --confirm and an explicit \
             --scope-include rule (authorized targets only).",
            args.targets.len()
        );
        return Ok(());
    }

    let opts = camio_integrations::HttpxOptions {
        rate_limit: args.rate_limit,
        concurrency: args.concurrency,
        timeout_secs: args.timeout_secs,
        follow_redirects: args.follow_redirects,
        extra_args: args.extra.clone(),
        max_targets: args.max_probes,
        max_response_bytes: args.max_response_bytes,
        ..Default::default()
    };
    eprintln!(
        "probing {} target(s) with httpx (rate {:?}, concurrency {:?}, timeout {}s)…",
        args.targets.len(),
        opts.rate_limit,
        opts.concurrency,
        opts.timeout_secs.unwrap_or(10)
    );
    let raw = match camio_integrations::run_httpx_raw(&args.targets, &opts, || false) {
        Ok(r) => r,
        Err(camio_integrations::IntegrationError::NotInstalled(t)) => {
            bail!(
                "{t} is not installed or not on PATH; install ProjectDiscovery's Go tool from \
                 https://github.com/projectdiscovery/httpx (or import an existing export with \
                 --import <file.jsonl>)"
            )
        }
        Err(e @ camio_integrations::IntegrationError::Incompatible { .. }) => bail!("{e}"),
        Err(e) => bail!("httpx run failed: {e}"),
    };
    let results = camio_integrations::parse_httpx_jsonl(&raw);
    print_probes(&results, args.json)?;
    if let Some(db) = args.db.as_ref() {
        let mut store = Store::open(db).with_context(|| format!("opening {}", db.display()))?;
        let saved = store.import_artifact(camio_store::ArtifactFormat::Httpx, &raw, None, true)?;
        eprintln!(
            "stored {} observation(s) ({} skipped) in {}",
            saved.records,
            saved.skipped,
            db.display()
        );
    }
    Ok(())
}

fn print_probes(results: &[camio_integrations::ProbeResult], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(results)?);
        return Ok(());
    }
    if results.is_empty() {
        println!("no probe results (no target answered, or the run was cancelled)");
        return Ok(());
    }
    for p in results {
        println!(
            "{:<44} {}",
            if p.url.is_empty() { &p.input } else { &p.url },
            camio_integrations::summarize_probe(p)
        );
    }
    println!("\n{} target(s) probed.", results.len());
    Ok(())
}

#[derive(Parser)]
struct TasksArgs {
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Mark records still non-terminal after the last exit as interrupted
    /// (restart recovery, plan §4.2). Read-only unless given.
    #[arg(long)]
    reconcile: bool,
    /// How many records to show (newest first).
    #[arg(long, default_value = "50")]
    limit: i64,
}

fn tasks_cmd(args: TasksArgs) -> Result<()> {
    let store = Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
    if args.reconcile {
        let n = store.reconcile_interrupted_tasks()?;
        println!("reconciled {n} interrupted background task(s)");
    }
    let rows = store.tasks(args.limit)?;
    if rows.is_empty() {
        println!("no background task records in {}", args.db.display());
        return Ok(());
    }
    println!("Background tasks in {}:", args.db.display());
    for row in &rows {
        let outcome = row
            .outcome
            .as_deref()
            .map(|o| format!(" [{o}]"))
            .unwrap_or_default();
        let detail = row
            .result
            .as_deref()
            .or(row.error.as_deref())
            .unwrap_or(&row.message)
            .lines()
            .next()
            .unwrap_or_default();
        let progress = match row.progress_total {
            Some(total) => format!(" {}/{}", row.progress_done, total),
            None if row.progress_done > 0 => format!(" {}", row.progress_done),
            None => String::new(),
        };
        println!(
            "  #{:<4} {:<22} {:<18}{progress}{outcome} {detail}",
            row.id, row.kind, row.state,
        );
    }
    Ok(())
}

#[derive(Parser)]
struct AuditArgs {
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Only show entries of this policy class (PASSIVE / ACTIVE / DESTRUCTIVE).
    #[arg(long)]
    class: Option<String>,
    /// How many entries to show (newest first).
    #[arg(long, default_value = "50")]
    limit: i64,
    /// Emit the entries as JSON instead of a table.
    #[arg(long)]
    json: bool,
    /// Prune the log to at most this many newest entries (explicit retention;
    /// never automatic). Prints how many were removed, then lists the rest.
    #[arg(long)]
    prune_to: Option<usize>,
}

/// Read (and optionally prune) the durable audit log (F02).
fn audit_cmd(args: AuditArgs) -> Result<()> {
    let store = Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
    if let Some(max) = args.prune_to {
        let removed = store.prune_audit_log(max, i64::MAX)?;
        println!("pruned {removed} audit entr{} (kept newest {max})", if removed == 1 { "y" } else { "ies" });
    }
    let rows = match &args.class {
        Some(class) => store.audit_log_by_class(&class.to_uppercase(), args.limit)?,
        None => store.audit_log(args.limit)?,
    };
    if args.json {
        let items: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "at_ms": r.at_ms,
                    "actor": r.actor,
                    "class": r.action_class,
                    "action": r.action,
                    "target": r.target,
                    "decision": r.decision,
                    "detail": r.detail,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    if rows.is_empty() {
        println!("no audit entries in {}", args.db.display());
        return Ok(());
    }
    println!("Audit log in {} ({} total):", args.db.display(), store.audit_log_count()?);
    for r in &rows {
        let target = r.target.as_deref().unwrap_or("-");
        let detail = r.detail.as_deref().unwrap_or("");
        println!(
            "  #{:<5} {:<5} {:<11} {:<13} {:<12} {target}  {detail}",
            r.id, r.actor, r.action_class, r.action, r.decision,
        );
    }
    Ok(())
}

#[derive(clap::Subcommand)]
enum CollectionCmd {
    /// Create a collection (idempotent by name).
    New {
        name: String,
        #[arg(long, default_value = "camio.db")]
        db: PathBuf,
    },
    /// Add an item to a collection (kind: exchange | finding | task).
    Add {
        name: String,
        kind: String,
        id: i64,
        #[arg(long, default_value = "camio.db")]
        db: PathBuf,
    },
    /// Remove an item from a collection.
    Rm {
        name: String,
        kind: String,
        id: i64,
        #[arg(long, default_value = "camio.db")]
        db: PathBuf,
    },
    /// List collections with their member counts.
    List {
        #[arg(long, default_value = "camio.db")]
        db: PathBuf,
    },
    /// Show a collection's members.
    Show {
        name: String,
        #[arg(long, default_value = "camio.db")]
        db: PathBuf,
    },
    /// Delete a collection (its referenced rows are left intact).
    Delete {
        name: String,
        #[arg(long, default_value = "camio.db")]
        db: PathBuf,
    },
}

fn parse_item_kind(s: &str) -> Result<camio_store::ItemKind> {
    camio_store::ItemKind::parse(s)
        .ok_or_else(|| anyhow::anyhow!("unknown item kind `{s}` (expected exchange|finding|task)"))
}

fn resolve_collection(store: &Store, name: &str) -> Result<i64> {
    store
        .collection_id(name)?
        .ok_or_else(|| anyhow::anyhow!("no collection named `{name}` (create it with `collection new`)"))
}

/// Manage collections (F18): named groups spanning exchanges/findings/tasks.
fn collection_cmd(action: CollectionCmd) -> Result<()> {
    match action {
        CollectionCmd::New { name, db } => {
            let store = Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
            let id = store.collection_create(&name)?;
            println!("collection `{name}` (#{id})");
        }
        CollectionCmd::Add { name, kind, id, db } => {
            let kind = parse_item_kind(&kind)?;
            let store = Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
            let cid = store.collection_create(&name)?; // create-if-absent, then add
            let added = store.collection_add(cid, kind, id)?;
            println!(
                "{} {} #{id} {} collection `{name}`",
                if added { "added" } else { "already in" },
                kind.as_str(),
                if added { "to" } else { "—" },
            );
        }
        CollectionCmd::Rm { name, kind, id, db } => {
            let kind = parse_item_kind(&kind)?;
            let store = Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
            let cid = resolve_collection(&store, &name)?;
            let removed = store.collection_remove(cid, kind, id)?;
            println!(
                "{} {} #{id} {} `{name}`",
                if removed { "removed" } else { "no such member" },
                kind.as_str(),
                if removed { "from" } else { "in" },
            );
        }
        CollectionCmd::List { db } => {
            let store = Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
            let cols = store.collections()?;
            if cols.is_empty() {
                println!("no collections in {}", db.display());
                return Ok(());
            }
            for c in &cols {
                let note = c.note.as_deref().map(|n| format!(" — {n}")).unwrap_or_default();
                println!("  #{:<4} {:<24} {} item(s){note}", c.id, c.name, c.item_count);
            }
        }
        CollectionCmd::Show { name, db } => {
            let store = Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
            let cid = resolve_collection(&store, &name)?;
            let items = store.collection_items(cid)?;
            if items.is_empty() {
                println!("collection `{name}` is empty");
                return Ok(());
            }
            println!("collection `{name}` (#{cid}):");
            for it in &items {
                println!("  {:<9} #{}", it.kind.as_str(), it.ref_id);
            }
        }
        CollectionCmd::Delete { name, db } => {
            let store = Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
            let cid = resolve_collection(&store, &name)?;
            store.collection_delete(cid)?;
            println!("deleted collection `{name}` (referenced rows left intact)");
        }
    }
    Ok(())
}

#[derive(Parser)]
struct SbomArgs {
    /// A Cargo.lock to describe instead of the one this binary was built from.
    #[arg(long)]
    lock: Option<PathBuf>,
    /// Write the SBOM here instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

/// Emit a CycloneDX SBOM (F26). Defaults to the lockfile embedded at build time.
fn sbom_cmd(args: SbomArgs) -> Result<()> {
    let lock = match &args.lock {
        Some(path) => {
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
        }
        None => camio_core::sbom::EMBEDDED_LOCK.to_string(),
    };
    let doc = camio_core::sbom::generate(&lock, "camio-cli", env!("CARGO_PKG_VERSION"));
    let json = serde_json::to_string_pretty(&doc)?;
    let n = doc["components"].as_array().map(|a| a.len()).unwrap_or(0);
    match &args.out {
        Some(path) => {
            std::fs::write(path, &json)
                .with_context(|| format!("writing SBOM to {}", path.display()))?;
            eprintln!("wrote CycloneDX SBOM ({n} components) to {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

#[derive(clap::Subcommand)]
enum BaselineCmd {
    /// Pin a stored exchange as the baseline under `name` (re-points if it
    /// already exists).
    Set {
        name: String,
        exchange_id: i64,
        #[arg(long, default_value = "camio.db")]
        db: PathBuf,
    },
    /// List named baselines and the exchange each points at.
    List {
        #[arg(long, default_value = "camio.db")]
        db: PathBuf,
    },
    /// Diff a stored exchange against the named baseline's exchange.
    Diff {
        name: String,
        exchange_id: i64,
        /// Diff the requests instead of the responses.
        #[arg(long)]
        request: bool,
        /// Context lines around each change.
        #[arg(long, default_value = "3")]
        context: usize,
        #[arg(long, default_value = "camio.db")]
        db: PathBuf,
    },
    /// Remove a named baseline (the referenced exchange is left intact).
    Rm {
        name: String,
        #[arg(long, default_value = "camio.db")]
        db: PathBuf,
    },
}

/// Manage response baselines and diff against them (F09 compare-to-baseline).
fn baseline_cmd(action: BaselineCmd) -> Result<()> {
    match action {
        BaselineCmd::Set { name, exchange_id, db } => {
            let store = open_store(&db)?;
            let eid = camio_core::ExchangeId(exchange_id);
            if store.get(eid)?.is_none() {
                bail!("no exchange #{exchange_id} in {}", db.display());
            }
            store.set_baseline(&name, eid)?;
            println!("baseline `{name}` → exchange #{exchange_id}");
        }
        BaselineCmd::List { db } => {
            let store = open_store(&db)?;
            let rows = store.baselines()?;
            if rows.is_empty() {
                println!("no baselines in {}", db.display());
                return Ok(());
            }
            for (name, id) in &rows {
                println!("  {:<24} → exchange #{}", name, id.0);
            }
        }
        BaselineCmd::Diff { name, exchange_id, request, context, db } => {
            let store = open_store(&db)?;
            let base_id = store
                .baseline(&name)?
                .ok_or_else(|| anyhow::anyhow!("no baseline named `{name}`"))?;
            let load = |id: camio_core::ExchangeId| -> Result<HttpExchange> {
                store
                    .get(id)?
                    .ok_or_else(|| anyhow::anyhow!("no exchange #{} in {}", id.0, db.display()))
            };
            let base = load(base_id)?;
            let other = load(camio_core::ExchangeId(exchange_id))?;
            let raw = |ex: &HttpExchange| {
                if request {
                    ex.request.raw()
                } else {
                    ex.response.as_ref().map(|r| r.raw()).unwrap_or_default()
                }
            };
            let what = if request { "request" } else { "response" };
            eprintln!(
                "diff {what} of baseline `{name}` (#{}) ↔ #{exchange_id}",
                base_id.0
            );
            let diff = camio_convert::unified_diff(&raw(&base), &raw(&other), context);
            if diff.trim().is_empty() {
                println!("(identical to baseline)");
            } else {
                print!("{diff}");
            }
        }
        BaselineCmd::Rm { name, db } => {
            let store = open_store(&db)?;
            if store.delete_baseline(&name)? {
                println!("removed baseline `{name}`");
            } else {
                println!("no baseline named `{name}`");
            }
        }
    }
    Ok(())
}

/// Env var carrying the backup passphrase. Read from the environment, never a CLI
/// flag, so it stays out of the process list and shell history.
const BACKUP_PASSPHRASE_ENV: &str = "CAMIO_BACKUP_PASSPHRASE";

fn backup_passphrase() -> Result<String> {
    match std::env::var(BACKUP_PASSPHRASE_ENV) {
        Ok(p) if !p.is_empty() => Ok(p),
        _ => bail!(
            "set the passphrase in ${BACKUP_PASSPHRASE_ENV} \
             (read from the environment so it stays out of argv and shell history)"
        ),
    }
}

/// Back up a workspace DB (F01), optionally sealing it with a passphrase, or
/// decrypt a sealed backup (F04).
fn backup_cmd(dest: PathBuf, db: PathBuf, encrypt: bool, decrypt: Option<PathBuf>) -> Result<()> {
    // Decrypt path: no DB is read; the encrypted file is opened into `dest`.
    if let Some(enc_path) = decrypt {
        if dest.exists() {
            bail!("{} already exists", dest.display());
        }
        let pass = backup_passphrase()?;
        let data = std::fs::read(&enc_path)
            .with_context(|| format!("reading {}", enc_path.display()))?;
        let plain = camio_core::secretbox::open(&data, &pass).map_err(|e| anyhow::anyhow!("{e}"))?;
        std::fs::write(&dest, &plain)
            .with_context(|| format!("writing {}", dest.display()))?;
        println!("decrypted {} → {}", enc_path.display(), dest.display());
        return Ok(());
    }

    let store = open_store(&db)?;
    if !encrypt {
        store.backup_to(&dest)?;
        println!("backed up {} → {}", db.display(), dest.display());
        return Ok(());
    }

    // Encrypted export: make a consistent plaintext backup to a short-lived temp
    // beside `dest`, seal it, and remove the temp — so the plaintext is never the
    // delivered artifact.
    if dest.exists() {
        bail!("{} already exists", dest.display());
    }
    let pass = backup_passphrase()?;
    let tmp = PathBuf::from(format!("{}.plain.tmp", dest.display()));
    let _ = std::fs::remove_file(&tmp); // clear any stale temp first
    store.backup_to(&tmp)?;
    restrict_permissions(&tmp);
    let plain = std::fs::read(&tmp);
    let _ = std::fs::remove_file(&tmp); // remove the plaintext temp no matter what
    let plain = plain.with_context(|| format!("reading temp backup {}", tmp.display()))?;
    let sealed = camio_core::secretbox::seal(&plain, &pass, camio_core::DEFAULT_PBKDF2_ITERS)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::write(&dest, &sealed).with_context(|| format!("writing {}", dest.display()))?;
    restrict_permissions(&dest);
    println!(
        "backed up {} → {} (encrypted, {} bytes; decrypt with `camio backup --decrypt {} <out>`)",
        db.display(),
        dest.display(),
        sealed.len(),
        dest.display()
    );
    Ok(())
}

/// Best-effort tighten a file to owner-only (0600) on Unix. A failure is not
/// fatal — the file is still written — but on a shared box it matters.
fn restrict_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
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
    /// Run the active probes behind a realistic blend-in random persona from
    /// this seed. See `fingerprint random`.
    #[arg(long)]
    persona_seed: Option<u64>,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Also permit link-local / cloud-metadata destinations. Lab mode alone
    /// never un-blocks 169.254.169.254 or fe80::/10.
    #[arg(long)]
    allow_metadata: bool,
    /// Throttle to at most this many requests/second (F11). Unlimited when unset.
    #[arg(long)]
    rate: Option<f64>,
    /// Run only these active checks by id (repeatable): reflected-xss,
    /// error-based-sqli, open-redirect, http-method-audit. All when unset (F13).
    #[arg(long = "only")]
    only: Vec<String>,
    /// Skip these active checks by id (repeatable) (F13).
    #[arg(long = "exclude")]
    exclude: Vec<String>,
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
    let profile = profile_for_persona(args.preset, None, args.persona_seed);
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
    let base = build_request(&args.url, &args.method, &args.headers, &args.body, &None)?;
    let decision = scope.decide(&HttpExchange::new(base.clone(), Source::Scanner));

    // Active testing (plan §16): must be in scope and explicitly confirmed.
    let policy = Policy {
        allow_active: true,
        allow_destructive: false,
        require_confirmation: true,
    };
    match policy.gate_action_with(ActionClass::Active, &scope, decision, args.confirm) {
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
    let limiter = camio_core::RateLimiter::new(None, args.rate.filter(|r| *r > 0.0));

    // The sender is the one place scope is re-enforced on every probe (plan §16).
    let send = |req: HttpRequest| -> Option<HttpExchange> {
        if !scope
            .decide(&HttpExchange::new(req.clone(), Source::Scanner))
            .is_sendable()
        {
            return None;
        }
        limiter.acquire(&req.host().unwrap_or_default());
        match eng.send(req, Source::Scanner) {
            Ok(mut ex) => {
                // Adopt the stored row id so findings link to real evidence.
                match store.borrow_mut().insert(&ex) {
                    Ok(id) => ex.id = id,
                    Err(e) => camio_core::note_failure("storing a probe exchange", e),
                }
                Some(ex)
            }
            Err(e) => {
                eprintln!("probe send failed: {e}");
                None
            }
        }
    };
    let mut findings = camio_active::run_active_filtered(&base, &send, &args.only, &args.exclude);

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
// Autopilot — one-shot automated recon + active sweep
// ===========================================================================

#[derive(Parser)]
struct AutopilotArgs {
    /// Authorized target URL.
    url: String,
    #[arg(long, short = 'X', default_value = "GET")]
    method: String,
    #[arg(long = "header", short = 'H')]
    headers: Vec<String>,
    #[arg(long)]
    body: Option<String>,
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    /// Run behind a realistic blend-in random persona from this seed.
    #[arg(long)]
    persona_seed: Option<u64>,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Also permit link-local / cloud-metadata destinations.
    #[arg(long)]
    allow_metadata: bool,
    /// Also probe write methods (PUT/DELETE/PATCH) for capability. These are
    /// mutating sends (though aimed at a non-existent sub-path, never the real
    /// resource), so this upgrades the action class to DESTRUCTIVE and requires
    /// --confirm.
    #[arg(long)]
    aggressive: bool,
    /// Crawl the target first (same-origin, scope-gated) and run the active
    /// checks on every discovered page, not just the seed URL.
    #[arg(long)]
    crawl: bool,
    /// Max pages to crawl / sweep when --crawl is set.
    #[arg(long, default_value_t = 15)]
    crawl_pages: usize,
    /// After the active sweep, also fuzz the stack-suggested payload-DB
    /// categories against discovered query/body inputs. Bounded by --fuzz-budget
    /// and still scope- and policy-gated on every probe.
    #[arg(long)]
    fuzz: bool,
    /// Max probe attempts for the --fuzz phase (split evenly across categories).
    /// Capped at 2000.
    #[arg(long, default_value_t = 300)]
    fuzz_budget: usize,
    /// Throttle the whole sweep to at most this many requests/second
    /// (politeness / rate control, F11). Unlimited when unset.
    #[arg(long)]
    rate: Option<f64>,
    /// Also run OAST-driven blind-SSRF detection: start a collector on this
    /// address and inject correlated callback URLs into each input.
    #[arg(long)]
    oast_listen: Option<String>,
    /// Authority (host:port) embedded in OAST callback URLs (defaults to
    /// --oast-listen; set to an address the target can reach).
    #[arg(long)]
    oast_base: Option<String>,
    /// Milliseconds to wait after each SSRF probe for the out-of-band callback.
    #[arg(long, default_value_t = 1500)]
    oast_settle_ms: u64,
    /// Actually run the sweep. Without this, prints what would run.
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

fn autopilot_cmd(args: AutopilotArgs) -> Result<()> {
    let profile = profile_for_persona(args.preset, None, args.persona_seed);
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
    let base = build_request(&args.url, &args.method, &args.headers, &args.body, &None)?;
    let decision = scope.decide(&HttpExchange::new(base.clone(), Source::Scanner));

    // Write-method probing is mutating, so it is gated as DESTRUCTIVE; the
    // read-only sweep is ACTIVE. Either way: in scope, explicit target, confirmed.
    let class = if args.aggressive {
        ActionClass::Destructive
    } else {
        ActionClass::Active
    };
    let policy = Policy {
        allow_active: true,
        allow_destructive: args.aggressive,
        require_confirmation: true,
    };
    match policy.gate_action_with(class, &scope, decision, args.confirm) {
        PolicyOutcome::Deny(reason) => bail!("refused: {reason}"),
        PolicyOutcome::NeedsConfirmation(reason) => {
            println!("{reason}.");
            println!(
                "Autopilot would, in scope {}: send a baseline {} to {}, fingerprint the stack \
                 (tech/WAF/takeover), run the active checks (reflected XSS, error-based SQLi, open \
                 redirect, HTTP method audit{}){}, and bucket every response by status class.",
                decision.as_str(),
                args.method,
                args.url,
                if args.aggressive {
                    " incl. PUT/DELETE/PATCH capability probes"
                } else {
                    ""
                },
                if args.fuzz {
                    format!(
                        ", then fuzz the stack-suggested payload-DB categories against discovered \
                         inputs (≤{} probes)",
                        args.fuzz_budget.min(2000)
                    )
                } else {
                    String::new()
                }
            );
            println!("Re-run with --confirm to execute (authorized targets only).");
            return Ok(());
        }
        PolicyOutcome::Allow => {}
    }
    if args.aggressive {
        eprintln!(
            "aggressive: PUT/DELETE/PATCH capability probes enabled — they target a non-existent \
             sub-path and never the real resource."
        );
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
    // Every probe's status, for the response summary (the 2xx/5xx view).
    let statuses = RefCell::new(Vec::<Option<u16>>::new());
    // Optional throttle across the whole sweep (F11 politeness/rate control).
    let limiter = camio_core::RateLimiter::new(None, args.rate.filter(|r| *r > 0.0));
    if limiter.is_limited() {
        eprintln!("rate limit: ≤{} request(s)/second", args.rate.unwrap_or(0.0));
    }

    // The one place scope is re-enforced on every probe (plan §16).
    let send = |req: HttpRequest| -> Option<HttpExchange> {
        if !scope
            .decide(&HttpExchange::new(req.clone(), Source::Scanner))
            .is_sendable()
        {
            return None;
        }
        // Throttle before the send (blocks until a slot is free).
        limiter.acquire(&req.host().unwrap_or_default());
        match eng.send(req, Source::Scanner) {
            Ok(mut ex) => {
                statuses
                    .borrow_mut()
                    .push(ex.response.as_ref().map(|r| r.status));
                // Adopt the stored row id so findings link to real evidence.
                match store.borrow_mut().insert(&ex) {
                    Ok(id) => ex.id = id,
                    Err(e) => camio_core::note_failure("storing an autopilot exchange", e),
                }
                Some(ex)
            }
            Err(e) => {
                eprintln!("probe send failed: {e}");
                None
            }
        }
    };

    // 1. Baseline send → attack-surface synthesis (tech/WAF/takeover → payloads).
    let baseline_ex = send(base.clone());
    let surface = baseline_ex
        .as_ref()
        .map(camio_scan::analyze_attack_surface);

    // 2. Active sweep: every default check (incl. the read-only method audit),
    //    plus the opt-in write-method probes when --aggressive.
    let mut findings = camio_active::run_active(&base, &send);
    if args.aggressive {
        findings.extend(camio_active::HttpMethodAudit::with_write_methods().run_write_probes(&base, &send));
    }

    // 2b. Optional crawl: discover more pages (same-origin, scope-gated) and run
    //     the active checks on each, so the sweep covers the site, not one URL.
    //     Discovered pages are also collected as fuzz targets below.
    let mut crawl_targets: Vec<HttpRequest> = Vec::new();
    if args.crawl {
        let opts = camio_active::CrawlOptions {
            max_pages: args.crawl_pages.max(1),
            same_origin_only: true,
        };
        let result = camio_active::crawl(&base.url, &send, &opts);
        for url in result
            .discovered
            .iter()
            .filter(|u| u.as_str() != base.url)
            .take(args.crawl_pages)
        {
            let page = HttpRequest::get(url);
            if !scope
                .decide(&HttpExchange::new(page.clone(), Source::Scanner))
                .is_sendable()
            {
                continue;
            }
            // The seed already reports host-level method findings; keep only the
            // resource-specific findings from each crawled page.
            findings.extend(
                camio_active::run_active(&page, &send)
                    .into_iter()
                    .filter(|f| !camio_active::is_host_level_finding(f)),
            );
            crawl_targets.push(page);
        }
        eprintln!("crawl: swept {} additional page(s)", crawl_targets.len());
    }

    // 3. Optional bounded payload-DB fuzz of the stack-suggested categories —
    //    the hand-off from "recon recommends" to "act on it", still gated: every
    //    probe flows through the same scope-checked `send` closure (plan §16).
    let baseline = baseline_ex
        .as_ref()
        .and_then(|ex| ex.response.as_ref())
        .map(|r| Baseline {
            status: r.status,
            body_len: r.body.len(),
        });
    let fuzz = if args.fuzz {
        let budget = args.fuzz_budget.min(2000);
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
            eprintln!(
                "--fuzz: none of the suggested categories matched the payload DB (see `camio payloads`); skipping fuzz."
            );
            None
        } else {
            // Fuzz the seed and every crawled page, sharing the budget across
            // them so a site sweep fuzzes the discovered parameterized endpoints.
            let targets: Vec<&HttpRequest> =
                std::iter::once(&base).chain(crawl_targets.iter()).collect();
            let per_target = (budget / targets.len().max(1)).max(1);
            eprintln!(
                "fuzzing {} payload categor{} across {} target(s) (≤{per_target} probes each)…",
                cats.len(),
                if cats.len() == 1 { "y" } else { "ies" },
                targets.len()
            );
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

    // 3b. Optional OAST-driven blind-SSRF detection with a live collector.
    if let Some(oast_listen) = &args.oast_listen {
        let listener = std::net::TcpListener::bind(oast_listen)
            .with_context(|| format!("binding OAST collector on {oast_listen}"))?;
        let local = listener.local_addr().context("reading OAST address")?;
        let base_auth = args.oast_base.clone().unwrap_or_else(|| local.to_string());
        let collector = camio_oast::Collector::new(base_auth.clone());
        let handle = camio_oast::OastServer::new(collector.clone())
            .on_interaction(|i| {
                eprintln!("  OAST callback: {} {} from {}", i.method, i.target, i.source);
            })
            .spawn(listener)
            .context("starting OAST collector")?;
        eprintln!(
            "OAST collector on {local} (callback base http://{base_auth}/) — probing inputs for blind SSRF…"
        );
        findings.extend(camio_active::run_oast_ssrf(
            &base,
            &send,
            &collector,
            std::time::Duration::from_millis(args.oast_settle_ms),
        ));
        handle.stop_and_join();
    }

    // 4. Response status summary across every probe sent above (incl. fuzz).
    let summary = camio_automate::StatusSummary::from_statuses(statuses.borrow().iter().copied());

    if args.json {
        let surface_json = surface.as_ref().map(|s| {
            let techs: Vec<_> = s
                .technologies
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name, "version": t.version, "categories": t.categories,
                        "confidence": t.confidence, "implied": t.implied,
                    })
                })
                .collect();
            serde_json::json!({
                "host": s.host,
                "technologies": techs,
                "wafs": s.wafs,
                "takeover_candidate": s.takeover,
                "suggested_payload_categories": s.suggested_payload_categories,
                "suggested_evasion_encodings": s.suggested_encodings.iter().map(|e| format!("{e:?}")).collect::<Vec<_>>(),
                "suggested_scope_rule": s.suggested_scope_rule,
                "notes": s.notes,
            })
        });
        let out = serde_json::json!({
            "target": args.url,
            "scope_decision": decision.as_str(),
            "attack_surface": surface_json,
            "findings": findings,
            "status_summary": summary,
            "fuzz": fuzz,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("== Autopilot: {} ({}) ==\n", args.url, decision.as_str());
        if let Some(s) = &surface {
            if s.technologies.is_empty() {
                println!("stack: (none fingerprinted)");
            } else {
                let techs: Vec<String> = s
                    .technologies
                    .iter()
                    .map(|t| match &t.version {
                        Some(v) => format!("{} {v}", t.name),
                        None => t.name.clone(),
                    })
                    .collect();
                println!("stack: {}", techs.join(", "));
            }
            if !s.wafs.is_empty() {
                println!("waf/cdn: {}", s.wafs.join(", "));
            }
            if let Some(service) = &s.takeover {
                println!("takeover candidate: {service}");
            }
        } else {
            println!("stack: (baseline request was refused — nothing to fingerprint)");
        }

        println!("\n-- active findings --");
        print_findings(&findings);

        println!("\n-- responses by status --");
        println!("  {}", summary.oneline());
        for (code, count) in &summary.by_code {
            println!("    {code}: {count}");
        }

        if let Some(fz) = &fuzz {
            println!(
                "\n-- fuzz results ({} sent, {} flagged) --",
                fz.sent,
                fz.results.len()
            );
            if fz.results.is_empty() {
                println!("  (no payload produced a flagged response)");
            } else {
                for r in &fz.results {
                    let st = r
                        .result
                        .status
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    println!(
                        "  [{}] {} = {:?}  -> {} [{}]",
                        r.category,
                        r.input_name,
                        r.payload,
                        st,
                        r.result.flags.join(",")
                    );
                }
            }
        }

        if let Some(s) = &surface {
            println!("\n-- recommended next steps --");
            if !s.suggested_payload_categories.is_empty() {
                println!(
                    "payload categories: {}",
                    s.suggested_payload_categories.join(", ")
                );
                if let Some(cat) = s.suggested_payload_categories.first() {
                    let rule = s
                        .suggested_scope_rule
                        .clone()
                        .unwrap_or_else(|| "host:<target>".to_string());
                    println!(
                        "  e.g.  camio fuzz \"{}\" --payloads db:{cat} --scope-include {rule} --budget 200 --confirm",
                        args.url
                    );
                }
            }
            if !s.suggested_encodings.is_empty() {
                let encs: Vec<String> =
                    s.suggested_encodings.iter().map(|e| format!("{e:?}")).collect();
                println!("evasion encodings (WAF present): {}", encs.join(", "));
            }
        }

        println!(
            "\n{} finding(s); {} request(s) sent. Stored in {}.",
            findings.len(),
            summary.total,
            args.db.display()
        );
    }

    if args.save {
        let mut n = 0;
        for f in &findings {
            if store.borrow_mut().insert_finding(f).is_ok() {
                n += 1;
            }
        }
        if !args.json {
            println!("saved {n} finding(s) to {}", args.db.display());
        }
    }
    Ok(())
}

// ===========================================================================
// Headless DAST run with a machine-readable result contract (F25)
// ===========================================================================

/// Documented exit codes for `camio dast`, so a CI job can branch on the result
/// without parsing stdout. A runtime error still surfaces as the process-wide
/// exit 1 (an `Err` from the command); these are the *completed-run* outcomes.
const DAST_EXIT_CLEAN: i32 = 0;
const DAST_EXIT_FINDINGS: i32 = 3;

/// Count findings at or above `threshold` (the CI gate).
fn dast_gate_count(findings: &[Finding], threshold: Severity) -> usize {
    findings.iter().filter(|f| f.severity >= threshold).count()
}

/// Severity breakdown of a finding set, most severe first, keeping only the
/// non-empty buckets — the machine-readable contract's `severity_breakdown`.
fn dast_severity_breakdown(findings: &[Finding]) -> Vec<SeverityCount> {
    [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .into_iter()
    .filter_map(|sev| {
        let count = findings.iter().filter(|f| f.severity == sev).count();
        (count > 0).then(|| SeverityCount {
            severity: severity_label(sev).to_string(),
            count,
        })
    })
    .collect()
}

#[derive(serde::Serialize)]
struct SeverityCount {
    severity: String,
    count: usize,
}

#[derive(serde::Serialize)]
struct DastGate {
    threshold: Option<String>,
    over_threshold: usize,
    passed: bool,
}

/// The machine-readable result contract emitted by `camio dast` (stable JSON for
/// CI: a pipeline reads `gate.passed` / the exit code and keeps the document as a
/// build artifact).
#[derive(serde::Serialize)]
struct DastRun {
    tool: &'static str,
    version: &'static str,
    target: String,
    scope_decision: String,
    engine: String,
    fingerprint_matched: bool,
    checks_run: usize,
    exchanges_sent: usize,
    total_findings: usize,
    severity_breakdown: Vec<SeverityCount>,
    gate: DastGate,
}

#[derive(Parser)]
struct DastArgs {
    /// Authorized target URL.
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
    #[arg(long)]
    allow_metadata: bool,
    /// Severity gate: exit 3 if any finding is at or above this
    /// (info|low|medium|high|critical). Omitted → the run never fails on findings.
    #[arg(long)]
    fail_on: Option<String>,
    /// Persist findings to the store.
    #[arg(long)]
    save: bool,
    /// Write the JSON result contract here instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Actually run (sends traffic). Without it, prints the plan and exits 0.
    #[arg(long)]
    confirm: bool,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
}

/// Headless DAST for CI (F25): a bounded baseline + active + passive run over the
/// matched engine that emits a machine-readable [`DastRun`] contract and a stable
/// exit code. Non-interactive and still fully gated — scope is re-checked on every
/// send, the action class is ACTIVE, and an explicit `--confirm` is required.
fn dast_cmd(args: DastArgs) -> Result<()> {
    let profile = profile_for_persona(args.preset, None, None);
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
    let base = build_request(&args.url, &args.method, &args.headers, &args.body, &None)?;
    let decision = scope.decide(&HttpExchange::new(base.clone(), Source::Scanner));
    let threshold = args.fail_on.as_deref().map(parse_severity).transpose()?;

    let policy = Policy {
        allow_active: true,
        allow_destructive: false,
        require_confirmation: true,
    };
    match policy.gate_action_with(ActionClass::Active, &scope, decision, args.confirm) {
        PolicyOutcome::Deny(reason) => {
            best_effort_audit(
                &args.db,
                &camio_store::NewAudit::new("cli", "ACTIVE", "dast", "denied")
                    .target(args.url.clone())
                    .detail(reason.clone()),
            );
            bail!("refused: {reason}")
        }
        PolicyOutcome::NeedsConfirmation(reason) => {
            eprintln!("{reason}.");
            eprintln!(
                "DAST would, in scope {}: send a baseline {} to {}, run the active checks and \
                 every passive check over the response, then emit a JSON result contract{}. \
                 Re-run with --confirm to execute (authorized targets only).",
                decision.as_str(),
                args.method,
                args.url,
                threshold
                    .map(|t| format!(" and exit {DAST_EXIT_FINDINGS} if any finding is ≥ {}", t.as_str()))
                    .unwrap_or_default()
            );
            return Ok(());
        }
        PolicyOutcome::Allow => {}
    }

    let eng = matched_engine(&profile).context("building matched request engine")?;
    let store = RefCell::new(
        Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?,
    );
    let sent = RefCell::new(0usize);
    // The one place scope is re-enforced on every probe (plan §16).
    let send = |req: HttpRequest| -> Option<HttpExchange> {
        if !scope
            .decide(&HttpExchange::new(req.clone(), Source::Scanner))
            .is_sendable()
        {
            return None;
        }
        match eng.send(req, Source::Scanner) {
            Ok(mut ex) => {
                *sent.borrow_mut() += 1;
                match store.borrow_mut().insert(&ex) {
                    Ok(id) => ex.id = id,
                    Err(e) => camio_core::note_failure("storing a dast exchange", e),
                }
                Some(ex)
            }
            Err(e) => {
                eprintln!("probe send failed: {e}");
                None
            }
        }
    };

    // Baseline → active sweep → passive scan of the baseline response.
    let baseline_ex = send(base.clone());
    let mut findings = camio_active::run_active(&base, &send);
    if let Some(ex) = &baseline_ex {
        findings.extend(camio_scan::scan_exchange(ex));
    }

    if args.save {
        let mut store = store.borrow_mut();
        for f in &findings {
            let _ = store.insert_finding(f);
        }
    }

    let over = threshold.map(|t| dast_gate_count(&findings, t)).unwrap_or(0);
    let run = DastRun {
        tool: "camio",
        version: env!("CARGO_PKG_VERSION"),
        target: args.url.clone(),
        scope_decision: decision.as_str().to_string(),
        engine: eng.label().to_string(),
        fingerprint_matched: eng.is_fingerprint_matched(),
        checks_run: camio_active::default_active_checks().len() + camio_scan::default_checks().len(),
        exchanges_sent: *sent.borrow(),
        total_findings: findings.len(),
        severity_breakdown: dast_severity_breakdown(&findings),
        gate: DastGate {
            threshold: threshold.map(|t| t.as_str().to_string()),
            over_threshold: over,
            passed: over == 0,
        },
    };
    // Durable audit (plan §F02): the DAST sweep ran. One row summarizes it
    // (exchanges sent, findings, gate), never any body.
    if let Err(e) = store.borrow().record_audit(
        &camio_store::NewAudit::new("cli", "ACTIVE", "dast", "allowed")
            .target(args.url.clone())
            .detail(format!(
                "sent={} findings={} gate={}",
                run.exchanges_sent,
                run.total_findings,
                if run.gate.passed { "passed" } else { "over" }
            )),
    ) {
        eprintln!("warning: could not write audit log: {e}");
    }

    let json = serde_json::to_string_pretty(&run)?;
    match &args.out {
        Some(path) => {
            std::fs::write(path, &json)
                .with_context(|| format!("writing DAST contract to {}", path.display()))?;
            eprintln!("wrote DAST result contract to {}", path.display());
        }
        None => println!("{json}"),
    }

    // Stable, documented exit code so CI can gate without parsing stdout.
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    std::process::exit(if over > 0 {
        DAST_EXIT_FINDINGS
    } else {
        DAST_EXIT_CLEAN
    });
}

// ===========================================================================
// Typed workflow execution (F12)
// ===========================================================================

/// A named step's output, carried forward so later steps can reference it.
enum StepOutput {
    Exchange(Box<HttpExchange>),
    Text(String),
}

/// Resolve a transform `input`: a `$step_id.field` reference into an earlier
/// step's output, or a literal string. Validation already proved any reference
/// targets an earlier step, so a missing/!wrong-kind output here is a runtime
/// error on the referenced value, not a dangling reference.
fn resolve_workflow_input(
    input: &str,
    outputs: &std::collections::HashMap<String, StepOutput>,
) -> Result<String> {
    let Some((id, field)) = camio_automate::parse_reference(input) else {
        return Ok(input.to_string()); // literal
    };
    match outputs.get(id) {
        Some(StepOutput::Exchange(ex)) => match field {
            "body" => Ok(ex
                .response
                .as_ref()
                .map(|r| r.body.as_text().to_string())
                .unwrap_or_default()),
            "status" => Ok(ex
                .response
                .as_ref()
                .map(|r| r.status.to_string())
                .unwrap_or_default()),
            "url" => Ok(ex.request.url.clone()),
            other => bail!("`${id}.{other}`: a request step exposes only body/status/url"),
        },
        Some(StepOutput::Text(s)) => match field {
            "value" => Ok(s.clone()),
            other => bail!("`${id}.{other}`: a transform step exposes only `value`"),
        },
        None => bail!("`${id}` produced no output (did that step run?)"),
    }
}

#[derive(Parser)]
struct WorkflowCmdArgs {
    /// Path to the workflow document (JSON).
    file: PathBuf,
    /// Validate the document and print the plan, but do not execute.
    #[arg(long)]
    check: bool,
    #[arg(long, value_enum, default_value_t = Preset::Balanced)]
    preset: Preset,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    #[arg(long)]
    allow_metadata: bool,
    /// Persist findings produced by scan steps.
    #[arg(long)]
    save: bool,
    /// Actually execute network steps (request/active_scan). Without it, a
    /// workflow that sends traffic is validated and planned only.
    #[arg(long)]
    confirm: bool,
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
}

/// Execute a typed workflow document (F12). The document is validated first; a
/// workflow that sends traffic requires `--confirm`, and every send is re-checked
/// against scope (plan §16). Transform-only workflows need no network and run
/// without confirmation.
fn workflow_cmd(args: WorkflowCmdArgs) -> Result<()> {
    use camio_automate::{WorkflowAction, WorkflowDoc};

    let text = std::fs::read_to_string(&args.file)
        .with_context(|| format!("reading workflow {}", args.file.display()))?;
    let doc = WorkflowDoc::from_json(&text).context("parsing the workflow document")?;
    if let Err(errs) = doc.validate() {
        bail!(
            "workflow `{}` is invalid:\n  - {}",
            doc.name,
            errs.join("\n  - ")
        );
    }

    let has_network = doc.steps.iter().any(|s| {
        matches!(
            s.action,
            WorkflowAction::Request { .. } | WorkflowAction::ActiveScan { .. }
        )
    });
    if args.check || (has_network && !args.confirm) {
        println!("workflow `{}` — {} step(s), valid.", doc.name, doc.steps.len());
        for step in &doc.steps {
            println!("  - {:<12} {}", step.action.kind(), step.id);
        }
        if has_network && !args.check {
            println!(
                "This workflow sends traffic (request/active_scan steps are scope-gated per send). \
                 Re-run with --confirm to execute (authorized targets only)."
            );
        }
        return Ok(());
    }

    let profile = profile_for_persona(args.preset, None, None);
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
    let eng = matched_engine(&profile).context("building matched request engine")?;
    let store = RefCell::new(
        Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?,
    );
    let send = |req: HttpRequest| -> Option<HttpExchange> {
        if !scope
            .decide(&HttpExchange::new(req.clone(), Source::Scanner))
            .is_sendable()
        {
            return None;
        }
        match eng.send(req, Source::Scanner) {
            Ok(mut ex) => {
                match store.borrow_mut().insert(&ex) {
                    Ok(id) => ex.id = id,
                    Err(e) => camio_core::note_failure("storing a workflow exchange", e),
                }
                Some(ex)
            }
            Err(e) => {
                eprintln!("workflow send failed: {e}");
                None
            }
        }
    };

    let mut outputs: std::collections::HashMap<String, StepOutput> = std::collections::HashMap::new();
    let mut findings: Vec<Finding> = Vec::new();
    println!("running workflow `{}` ({} steps)…", doc.name, doc.steps.len());
    for step in &doc.steps {
        let line = match &step.action {
            WorkflowAction::Request {
                url,
                method,
                headers,
                body,
            } => {
                let req = build_request(url, method, headers, body, &None)?;
                match send(req) {
                    Some(ex) => {
                        let status = ex.response.as_ref().map(|r| r.status);
                        outputs.insert(step.id.clone(), StepOutput::Exchange(Box::new(ex)));
                        format!("request  `{}` → {}", step.id, status.map(|s| s.to_string()).unwrap_or_else(|| "no response".into()))
                    }
                    None => format!("request  `{}` → skipped (out of scope or send failed)", step.id),
                }
            }
            WorkflowAction::PassiveScan { on } => match outputs.get(on) {
                Some(StepOutput::Exchange(ex)) => {
                    let found = camio_scan::scan_exchange(ex);
                    let n = found.len();
                    findings.extend(found);
                    format!("scan     `{}` over `{on}` → {n} finding(s)", step.id)
                }
                _ => bail!(
                    "step `{}`: passive_scan `on` = `{on}` did not produce a response to scan",
                    step.id
                ),
            },
            WorkflowAction::ActiveScan { url } => {
                let base = build_request(url, "GET", &[], &None, &None)?;
                let found = camio_active::run_active(&base, &send);
                let n = found.len();
                findings.extend(found);
                format!("active   `{}` on {url} → {n} finding(s)", step.id)
            }
            WorkflowAction::Transform { input, op } => {
                let resolved = resolve_workflow_input(input, &outputs)?;
                let t = camio_convert::Transform::from_name(op)
                    .ok_or_else(|| anyhow::anyhow!("unknown transform `{op}`"))?;
                let out = t
                    .apply(resolved.as_bytes())
                    .map_err(|e| anyhow::anyhow!("transform `{op}` failed: {e}"))?;
                let s = String::from_utf8_lossy(&out).into_owned();
                let preview: String = s.chars().take(60).collect();
                outputs.insert(step.id.clone(), StepOutput::Text(s));
                format!("transform`{}` {op} → {preview}", step.id)
            }
        };
        println!("  ✓ {line}");
    }

    if args.save && !findings.is_empty() {
        let mut store = store.borrow_mut();
        let mut n = 0;
        for f in &findings {
            if store.insert_finding(f).is_ok() {
                n += 1;
            }
        }
        println!("saved {n} finding(s) to {}", args.db.display());
    }
    println!(
        "workflow complete: {} step(s), {} finding(s).",
        doc.steps.len(),
        findings.len()
    );
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
    /// Run a structured AI-assist task over the prompt instead of a free chat:
    /// attack-plan (next-step vectors from a surface/findings summary),
    /// payload-mutations (WAF-evasion variants of the prompt as a payload), or
    /// triage (prioritize a findings summary). Authorized testing only.
    #[arg(long, value_enum)]
    task: Option<AiTaskArg>,
    /// For --task payload-mutations: an optional context hint (e.g. "reflected in
    /// an HTML attribute; WAF blocks <script>").
    #[arg(long)]
    context: Option<String>,
}

#[derive(Copy, Clone, ValueEnum)]
enum AiTaskArg {
    AttackPlan,
    PayloadMutations,
    Triage,
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
    // Structured AI-assist tasks (attack planning / payload mutation / triage)
    // run over the prompt and return before the free-chat path.
    if let Some(task) = args.task {
        match task {
            AiTaskArg::AttackPlan => {
                let plan = camio_ai::run_attack_plan(&client, &prompt)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("{plan}");
            }
            AiTaskArg::PayloadMutations => {
                let variants =
                    camio_ai::run_payload_mutations(&client, &prompt, args.context.as_deref())
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                for v in &variants {
                    println!("{v}");
                }
                eprintln!("{} mutation(s)", variants.len());
            }
            AiTaskArg::Triage => {
                let triage =
                    camio_ai::run_triage(&client, &prompt).map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("{triage}");
            }
        }
        return Ok(());
    }
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
    /// Start the app with a realistic blend-in random persona from this seed.
    /// See `fingerprint random`.
    #[arg(long)]
    persona_seed: Option<u64>,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Also permit link-local / cloud-metadata destinations. Lab mode alone
    /// never un-blocks 169.254.169.254 or fe80::/10.
    #[arg(long)]
    allow_metadata: bool,
    /// Allow active (fuzz) actions from the app. Off by default.
    #[arg(long)]
    allow_active: bool,
}

fn app_cmd(args: AppArgs) -> Result<()> {
    let profile = profile_for_persona(args.preset, None, args.persona_seed);
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
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
    /// Start the web UI with a realistic blend-in random persona from this seed.
    /// See `fingerprint random`.
    #[arg(long)]
    persona_seed: Option<u64>,
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    #[arg(long)]
    allow_private: bool,
    /// Also permit link-local / cloud-metadata destinations. Lab mode alone
    /// never un-blocks 169.254.169.254 or fe80::/10.
    #[arg(long)]
    allow_metadata: bool,
    /// Allow active (fuzz) actions from the UI. Off by default.
    #[arg(long)]
    allow_active: bool,
}

fn ui_cmd(args: UiArgs) -> Result<()> {
    let profile = profile_for_persona(args.preset, None, args.persona_seed);
    let scope = build_scope_full(
        &args.scope_include,
        &args.scope_exclude,
        args.allow_private,
        args.allow_metadata,
    )?;
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
        // A world-readable AI session key is the whole failure this file is
        // supposed to prevent, so a failed chmod must fail the save rather than
        // leaving the key on disk with whatever mode the filesystem gave it.
        std::fs::set_permissions(&path, perms)
            .with_context(|| format!("restricting {} to owner-only (0600)", path.display()))?;
    }
    Ok(path)
}

fn load_key(dir: &std::path::Path, session_id: &str) -> Result<camio_core::SessionKey> {
    let path = dir.join(format!("{session_id}.key"));
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "reading {} (did you `camio ai bind` first?)",
            path.display()
        )
    })?;
    let bytes = hex_decode(text.trim())
        .map_err(|e| anyhow::anyhow!("invalid hex in {}: {e}", path.display()))?;
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

/// Decode hex, naming the first byte that is not a hex digit. A bare `()` made
/// "wrong length" and "invalid character" the same answer.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("{} is not an even number of hex digits", s.len()));
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
        // The source error is unit-typed and carries no information; the
        // replacement names the offending byte, which is the useful part.
        // audit-allow: B7
        let h = from_hex(b[i])
            .map_err(|_| format!("byte {i} (`{}`) is not a hex digit", b[i] as char))?;
        // The source error is unit-typed and carries no information;
        // the replacement names the offending byte or column.
        // audit-allow: B7
        let l = from_hex(b[i + 1])
            .map_err(|_| format!("byte {} (`{}`) is not a hex digit", i + 1, b[i + 1] as char))?;
        out.push((h << 4) | l);
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
        .with_context(|| {
            "bind_session_with_integrity failed (malformed target or unreadable lock path?)"
        })?
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
    // The key is loaded to prove it can be decrypted with this session; its
    // value is not used further.
    // audit-allow: B14
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
                    // A pair that is not two strings is skipped: indexing a
                    // JSON array by position is how a malformed spec becomes a
                    // panic.
                    if let [n_value, v_value] = pair.as_slice() {
                        if let (Some(n), Some(v)) = (n_value.as_str(), v_value.as_str()) {
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
                println!(
                    "  [{}] {} {}",
                    s.step_label, s.request.method, s.request.url
                );
            }
            Ok(())
        }
        Err(e) => bail!("refused: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        dast_gate_count, dast_severity_breakdown, forward_redirect_headers, named_profile_dir,
        resolve_url,
    };
    use camio_core::{Confidence, Finding, FindingId, HttpRequest, Severity};
    use std::path::Path;

    fn finding_sev(sev: Severity) -> Finding {
        Finding {
            id: FindingId(0),
            title: "t".into(),
            severity: sev,
            confidence: Confidence::Firm,
            detail: String::new(),
            evidence: vec![],
            created_at_ms: 0,
            rule: None,
        }
    }

    #[test]
    fn dast_gate_counts_findings_at_or_above_threshold() {
        let fs = vec![
            finding_sev(Severity::Info),
            finding_sev(Severity::Low),
            finding_sev(Severity::High),
            finding_sev(Severity::Critical),
        ];
        // At/above Medium = High + Critical.
        assert_eq!(dast_gate_count(&fs, Severity::Medium), 2);
        // At/above Info = all of them.
        assert_eq!(dast_gate_count(&fs, Severity::Info), 4);
        // At/above Critical = just the one.
        assert_eq!(dast_gate_count(&fs, Severity::Critical), 1);
        assert_eq!(dast_gate_count(&[], Severity::Low), 0);
    }

    #[test]
    fn dast_breakdown_is_most_severe_first_and_omits_empty_buckets() {
        let fs = vec![
            finding_sev(Severity::Low),
            finding_sev(Severity::Low),
            finding_sev(Severity::Critical),
            finding_sev(Severity::Info),
        ];
        let b = dast_severity_breakdown(&fs);
        // Critical first, then low, then info; no medium/high buckets.
        let pairs: Vec<(&str, usize)> =
            b.iter().map(|c| (c.severity.as_str(), c.count)).collect();
        assert_eq!(
            pairs,
            vec![("critical", 1), ("low", 2), ("info", 1)],
            "breakdown must be ranked and skip empty buckets"
        );
    }

    #[test]
    fn named_profile_dir_isolates_and_prevents_traversal() {
        let root = Path::new("/profiles");
        // A normal name becomes a single segment under the root.
        assert_eq!(
            named_profile_dir(root, "client-a").unwrap(),
            Path::new("/profiles/client-a")
        );
        // Path separators and traversal are neutralised: the result is a direct
        // child of the root (a single sanitised segment), never an escape.
        let p = named_profile_dir(root, "../../etc/passwd").unwrap();
        assert_eq!(p.parent(), Some(root), "must be a direct child of the root");
        // Empty / dot-only names are rejected.
        assert!(named_profile_dir(root, "").is_none());
        assert!(named_profile_dir(root, "..").is_none());
        assert!(named_profile_dir(root, "///").is_none());
    }

    #[test]
    fn redirect_headers_preserve_content_type_for_307_body_same_host() {
        // A POST with a body being redirected 307 to the same host: the body (and
        // thus Content-Type) and the session context must survive the hop.
        let mut req = HttpRequest::get("https://host.test/a");
        req.headers.push("Content-Type", "application/json");
        req.headers.push("Authorization", "Bearer secret");
        req.headers.push("Cookie", "sid=abc");
        req.headers.push("Host", "host.test");
        let out = forward_redirect_headers(&req, /*cross_host=*/ false, /*keeps_body=*/ true);
        assert_eq!(out.get("Content-Type"), Some("application/json"));
        assert_eq!(out.get("Authorization"), Some("Bearer secret"));
        assert_eq!(out.get("Cookie"), Some("sid=abc"));
        // Host is always recomputed from the new URL, never carried.
        assert_eq!(out.get("Host"), None);
    }

    #[test]
    fn redirect_headers_drop_credentials_cross_host() {
        let mut req = HttpRequest::get("https://host.test/a");
        req.headers.push("Authorization", "Bearer secret");
        req.headers.push("Cookie", "sid=abc");
        req.headers.push("Accept", "text/html");
        let out = forward_redirect_headers(&req, /*cross_host=*/ true, /*keeps_body=*/ true);
        // No credential leak to another origin...
        assert_eq!(out.get("Authorization"), None);
        assert_eq!(out.get("Cookie"), None);
        // ...but ordinary headers still travel.
        assert_eq!(out.get("Accept"), Some("text/html"));
    }

    #[test]
    fn redirect_headers_drop_content_headers_when_falling_back_to_get() {
        // 301/302/303 → GET with no body: content headers must not linger.
        let mut req = HttpRequest::get("https://host.test/a");
        req.headers.push("Content-Type", "application/json");
        req.headers.push("Content-Length", "42");
        req.headers.push("Accept", "application/json");
        let out = forward_redirect_headers(&req, /*cross_host=*/ false, /*keeps_body=*/ false);
        assert_eq!(out.get("Content-Type"), None);
        assert_eq!(out.get("Content-Length"), None);
        assert_eq!(out.get("Accept"), Some("application/json"));
    }

    #[test]
    fn resolve_url_handles_relative_and_absolute_locations() {
        let base = "http://host.test/a/b?x=1";
        // Origin-relative.
        assert_eq!(
            resolve_url(base, "/next").as_deref(),
            Some("http://host.test/next")
        );
        // Path-relative (relative to the directory of the current path).
        assert_eq!(
            resolve_url(base, "c").as_deref(),
            Some("http://host.test/a/c")
        );
        // Scheme-relative.
        assert_eq!(
            resolve_url(base, "//other.test/p").as_deref(),
            Some("http://other.test/p")
        );
        // Absolute (possibly cross-origin — the caller re-gates scope).
        assert_eq!(
            resolve_url(base, "https://evil.test/x").as_deref(),
            Some("https://evil.test/x")
        );
        // Unparseable base → None (chain stops).
        assert_eq!(resolve_url("not a url", "/x"), None);
    }
}
