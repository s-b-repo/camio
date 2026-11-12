//! `camio` — command-line entry point for the Camio workbench (early scaffold).
//!
//! Implemented today:
//!   * `camio engine info`            — pinned Camoufox build + install status
//!   * `camio engine unpack`          — extract a downloaded Camoufox zip
//!   * `camio fingerprint show`       — render the anti-detection policy
//!   * `camio launch`                 — launch the managed browser with a policy

use anyhow::{bail, Context, Result};
use camio_core::{FingerprintPolicy, FingerprintProfile};
use camio_engine::{self as engine, Camoufox, LaunchOptions};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "camio", version, about = "Fingerprint-transparent web security workbench")]
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
    /// Inspect the anti-detection fingerprint policy.
    Fingerprint {
        #[command(subcommand)]
        action: FpCmd,
    },
    /// Launch the managed browser with a fingerprint policy applied.
    Launch(LaunchArgs),
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
        format!("win-firefox-{}-{}", camio_core::ALIGNED_FIREFOX_MAJOR, preset.label()),
        engine::PINNED_VERSION,
    );
    p.policy = preset.policy();
    p
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Engine { action } => engine_cmd(action),
        Command::Fingerprint { action } => fingerprint_cmd(action),
        Command::Launch(args) => launch_cmd(args),
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
                    println!("{}", serde_json::to_string_pretty(&profile.to_camoufox_config())?)
                }
                Format::Json => println!("{}", serde_json::to_string_pretty(&profile)?),
            }
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
        println!("  profile prefs written to {}", args.profile.join("user.js").display());
        return Ok(());
    }

    println!(
        "Launching Camoufox ({}) with '{}' fingerprint policy...",
        engine::PINNED_VERSION,
        args.preset.label()
    );
    match cam.launch(&args.profile, &profile, &opts)? {
        Some(mut child) => {
            println!("Browser started (pid {}). Close it to exit.", child.id());
            let status = child.wait().context("waiting for browser")?;
            println!("Browser exited: {status}");
        }
        None => {}
    }
    Ok(())
}
