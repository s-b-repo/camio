//! `camio proxy` — run the intercepting HTTP/HTTPS proxy.
//!
//! This wires the transport-agnostic [`camio_proxy::ProxyServer`] to the real
//! Camio pieces: the fingerprint-matched request engine forwards upstream, the
//! SQLite store captures every exchange, and the shared scope/policy/Match &
//! Replace types gate and rewrite traffic — the same ones `camio send` and the
//! scanners use.

use anyhow::{Context, Result};
use camio_core::{HttpExchange, Policy};
use camio_proxy::{
    AutoForward, CertAuthority, EngineForwarder, ExchangeSink, Forwarder, Interceptor, ProxyConfig,
    ProxyServer,
};
use camio_store::Store;
use clap::Parser;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
pub struct ProxyArgs {
    /// Address to listen on for browser proxy connections.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,
    /// Scope include rule in CamioQL (repeatable). With none, every non-guarded
    /// host is in scope (Burp-style); out-of-scope requests are refused.
    #[arg(long = "scope-include")]
    scope_include: Vec<String>,
    /// Scope exclude rule in CamioQL (repeatable).
    #[arg(long = "scope-exclude")]
    scope_exclude: Vec<String>,
    /// Lab mode: allow private/loopback/metadata destinations (SSRF guard off).
    #[arg(long)]
    allow_private: bool,
    /// Fingerprint preset the upstream engine impersonates.
    #[arg(long, value_enum, default_value_t = crate::Preset::Balanced)]
    preset: crate::Preset,
    /// Match & Replace rule applied in-flight (repeatable).
    /// Format: `PART|FIND|REPLACE`, PART = url|method|body|header=NAME|
    /// resp-header=NAME|resp-body|status-reason.
    #[arg(long = "rewrite")]
    rewrites: Vec<String>,
    /// SQLite project database to capture exchanges into.
    #[arg(long, default_value = "camio.db")]
    db: PathBuf,
    /// Decrypt in-scope HTTPS by terminating TLS with Camio's own CA
    /// (fingerprint-changing). Without it, HTTPS is blind-relayed end-to-end so
    /// the browser's own TLS fingerprint is preserved and only the host is seen.
    #[arg(long)]
    tls_intercept: bool,
    /// Directory holding the proxy CA (camio-ca.pem / camio-ca.key). Created on
    /// first use. Defaults to $XDG_CONFIG_HOME/camio (or ~/.config/camio).
    #[arg(long)]
    ca_dir: Option<PathBuf>,
    /// Common name for a freshly generated intercept CA (an existing CA keeps its
    /// name). Default is neutral ("Internal Root CA") so the certificate chain
    /// does not announce the proxy; set one that blends into the environment you
    /// are authorized to test.
    #[arg(long)]
    ca_name: Option<String>,
    /// Write the CA certificate to this path and exit (for browser/OS import).
    #[arg(long)]
    export_ca: Option<PathBuf>,
    /// Rotate the intercept CA: mint a new key + certificate and exit. Anything
    /// that imported the old CA must re-import this one.
    #[arg(long)]
    rotate_ca: bool,
    /// Remove the persisted intercept CA (cert + key) and exit. Stops Camio from
    /// minting leaves as that identity; the browser trust store keeps what it
    /// already imported, so also remove it there to revoke trust.
    #[arg(long)]
    remove_ca: bool,
    /// Automatically run the passive scanner on every IN-SCOPE captured exchange
    /// and store its findings. Out-of-scope traffic is recorded but never tested.
    #[arg(long)]
    auto_scan: bool,
    /// Chain upstream traffic through another proxy (e.g. http://127.0.0.1:8081
    /// for Burp/ZAP, or socks5://… with the engine's `socks` feature). Applies to
    /// engine-forwarded traffic (plain HTTP + TLS-intercepted HTTPS); blind-relay
    /// and WebSocket go direct.
    #[arg(long)]
    upstream_proxy: Option<String>,
    /// Per-host requests-per-second cap on engine-forwarded upstream sends
    /// (paces traffic so a target isn't hammered). 0/unset = unlimited.
    #[arg(long)]
    rate_limit: Option<f64>,
    /// Suppress the per-exchange capture log line.
    #[arg(long)]
    quiet: bool,
}

pub fn run(args: ProxyArgs) -> Result<()> {
    let ca_dir = args.ca_dir.clone().unwrap_or_else(default_ca_dir);
    let ca_name = args
        .ca_name
        .clone()
        .unwrap_or_else(|| camio_proxy::DEFAULT_CA_COMMON_NAME.to_string());

    // Setup-only mode: export the CA and exit.
    if let Some(path) = &args.export_ca {
        let ca = CertAuthority::load_or_create_named(&ca_dir, &ca_name)
            .with_context(|| format!("loading/creating CA in {}", ca_dir.display()))?;
        std::fs::write(path, ca.ca_cert_pem())
            .with_context(|| format!("writing {}", path.display()))?;
        println!("Wrote the Camio proxy CA certificate to {}", path.display());
        print_import_hint();
        return Ok(());
    }

    // Rotate: a new key + cert; prior imports no longer match.
    if args.rotate_ca {
        // The handle is not needed after rotation (the CA is persisted to disk
        // inside `rotate`), but it is bound so the value is not dropped mid-
        // statement.
        // audit-allow: B14
        let _ca = CertAuthority::rotate(&ca_dir, &ca_name)
            .with_context(|| format!("rotating the CA in {}", ca_dir.display()))?;
        println!("Rotated the Camio proxy CA in {}.", ca_dir.display());
        println!("Re-import the new certificate into the browser/OS trust store;");
        println!("the previous CA no longer matches any leaf this proxy mints.");
        print_import_hint();
        return Ok(());
    }

    // Remove: stop minting leaves as this identity.
    if args.remove_ca {
        let removed = CertAuthority::remove(&ca_dir)
            .with_context(|| format!("removing the CA in {}", ca_dir.display()))?;
        if removed {
            println!(
                "Removed the Camio proxy CA (certificate + key) from {}.",
                ca_dir.display()
            );
            println!("Camio can no longer intercept TLS as this identity. Also remove it from");
            println!("the browser/OS trust store to revoke trust fully.");
        } else {
            println!("No Camio proxy CA found in {}.", ca_dir.display());
        }
        return Ok(());
    }

    let scope = crate::build_scope(&args.scope_include, &args.scope_exclude, args.allow_private)?;
    let rules = crate::build_ruleset(&args.rewrites)?;
    let profile = crate::profile_for(args.preset);

    // The operator started the proxy with an explicit scope, which is the
    // session-level confirmation — so relayed sends don't each need one.
    let policy = Policy {
        require_confirmation: false,
        ..Policy::safe()
    };
    // One limiter shared by the forwarder and the raw-relayed `ws://` path, so
    // `--rate-limit` paces the whole proxy rather than only HTTP requests.
    let limiter = args
        .rate_limit
        .filter(|rps| *rps > 0.0)
        .map(|rps| Arc::new(camio_core::RateLimiter::new(Some(rps), None)));
    let config = ProxyConfig {
        scope,
        policy,
        rules,
        tls_intercept: args.tls_intercept,
        ws_rate_limit: limiter.clone(),
        ..ProxyConfig::default()
    };

    let engine_forwarder = Arc::new(
        EngineForwarder::spawn_with_proxy(profile, args.upstream_proxy.clone())
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    );
    let forwarder: Arc<dyn Forwarder> = match limiter {
        Some(limiter) => Arc::new(camio_proxy::RateLimitedForwarder::new(
            engine_forwarder,
            limiter,
        )),
        None => engine_forwarder,
    };
    let store = Store::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?;
    let sink = Arc::new(StoreSink::new(store, !args.quiet, args.auto_scan));
    let interceptor: Arc<dyn Interceptor> = Arc::new(AutoForward);

    let listener =
        TcpListener::bind(&args.listen).with_context(|| format!("binding {}", args.listen))?;
    let local = listener.local_addr().context("reading local address")?;

    let mut server = ProxyServer::new(config, forwarder, sink, interceptor);
    if args.tls_intercept {
        let ca = Arc::new(
            CertAuthority::load_or_create_named(&ca_dir, &ca_name)
                .with_context(|| format!("loading/creating CA in {}", ca_dir.display()))?,
        );
        eprintln!(
            "TLS interception ON — in-scope HTTPS is decrypted (fingerprint-CHANGING).\n  CA: {}/camio-ca.pem  — import it into your browser/OS trust store first.",
            ca_dir.display()
        );
        server = server.with_ca(ca);
    } else {
        eprintln!(
            "TLS interception OFF — HTTPS is blind-relayed (fingerprint-true; host recorded only).\n  Add --tls-intercept to decrypt in-scope HTTPS."
        );
    }

    eprintln!("Camio proxy listening on {local}");
    eprintln!("  capture database : {}", args.db.display());
    eprintln!("  fingerprint      : {} preset", args.preset.label());
    if let Some(up) = &args.upstream_proxy {
        eprintln!("  upstream proxy   : {up} (engine-forwarded traffic only)");
    }
    if let Some(rps) = args.rate_limit.filter(|r| *r > 0.0) {
        eprintln!("  rate limit       : {rps} req/s per host");
    }
    eprintln!(
        "  auto-scan        : {}",
        if args.auto_scan {
            "ON (passive checks on in-scope traffic)"
        } else {
            "off (use --auto-scan)"
        }
    );
    eprintln!("Point your browser's HTTP and HTTPS proxy at {local}. Press Ctrl-C to stop.");

    server
        .serve_with_listener(listener)
        .context("serving proxy")?;
    Ok(())
}

fn default_ca_dir() -> PathBuf {
    // XDG_CONFIG_HOME unset is the common case, not an error.
    // audit-allow: B4
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        // HOME unset is the common case, not an error.
        // audit-allow: B4
        return PathBuf::from(xdg).join("camio");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("camio");
    }
    PathBuf::from("camio-ca")
}

fn print_import_hint() {
    println!();
    println!("Import it so your browser trusts intercepted HTTPS:");
    println!("  Firefox : Settings ▸ Privacy & Security ▸ Certificates ▸ View Certificates");
    println!("            ▸ Authorities ▸ Import ▸ (trust it to identify websites)");
    println!("  Chrome  : Settings ▸ Privacy and security ▸ Security ▸ Manage certificates");
    println!("            ▸ Authorities ▸ Import");
    println!("  Linux   : sudo cp <file> /usr/local/share/ca-certificates/camio.crt &&");
    println!("            sudo update-ca-certificates");
    println!();
    println!("Only import this on a machine you control for authorized testing. The CA");
    println!("private key (camio-ca.key) stays local and is written with 0600 permissions.");
}

// ---------------------------------------------------------------------------
// Sink: persist each captured exchange into the project store.
//
// The upstream forwarder is `camio_proxy::EngineForwarder` (the fingerprint-
// matched engine, confined to one worker thread so its current-thread Tokio
// runtime is never entered concurrently).
// ---------------------------------------------------------------------------

struct StoreSink {
    store: Mutex<Store>,
    verbose: bool,
    auto_scan: bool,
}

impl StoreSink {
    fn new(store: Store, verbose: bool, auto_scan: bool) -> Self {
        StoreSink {
            store: Mutex::new(store),
            verbose,
            auto_scan,
        }
    }
}

impl ExchangeSink for StoreSink {
    fn record(&self, exchange: &HttpExchange) {
        let mut store = match self.store.lock() {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  capture skipped: store mutex poisoned");
                return;
            }
        };
        let id = match store.insert(exchange) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("  capture store error: {e}");
                return;
            }
        };

        // Scope-aware automation: only IN-SCOPE traffic is tested. Out-of-scope
        // exchanges are recorded above but never scanned or attacked.
        let mut findings = 0usize;
        if self.auto_scan
            && exchange.scope == Some(camio_core::ScopeDecision::InScope)
            && exchange.response.is_some()
        {
            // The passive checks link evidence to the exchange id, so stamp the
            // stored id onto a copy before scanning.
            let mut scanned = exchange.clone();
            scanned.id = id;
            let found = camio_scan::scan_exchange(&scanned);
            findings = found.len();
            if findings > 0 {
                if let Err(e) = store.insert_findings(&found) {
                    eprintln!("  finding store error: {e}");
                }
            }
        }

        if self.verbose {
            let status = exchange.response.as_ref().map(|r| r.status).unwrap_or(0);
            let decision = exchange.scope.map(|d| d.as_str()).unwrap_or("?");
            let suffix = if findings > 0 {
                format!(" [{findings} finding(s)]")
            } else {
                String::new()
            };
            eprintln!(
                "  [{decision}] {} {} -> {status} (#{id}){suffix}",
                exchange.request.method, exchange.request.url
            );
        }
    }
}
