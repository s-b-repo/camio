//! Standalone launcher for the Camio native desktop app with safe defaults.
//!
//! The richer entry point is `camio app` (the CLI), which applies the selected
//! fingerprint preset, scope rules and policy. This binary opens the window with
//! the default balanced profile against `camio.db` in the current directory.

use camio_app::{run, AppConfig};
use camio_core::{FingerprintProfile, Policy, Scope};
use std::path::PathBuf;

fn main() {
    let profile = FingerprintProfile::new(
        format!("win-firefox-{}-balanced", camio_core::ALIGNED_FIREFOX_MAJOR),
        "158.0.1-beta.41",
    );
    let cfg = AppConfig {
        db: PathBuf::from("camio.db"),
        profile,
        scope: Scope::new(),
        policy: Policy::safe(),
    };
    if let Err(e) = run(cfg) {
        eprintln!("camio-app: {e}");
        std::process::exit(1);
    }
}
