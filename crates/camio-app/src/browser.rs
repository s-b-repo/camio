//! Launching the user's managed browser (plan §6.2, §9).
//!
//! The managed browser is a Firefox-family fork — **LibreWolf** or **Camoufox**
//! (both privacy/anti-detect Firefox forks) — launched with Camio's fingerprint
//! profile applied. Camio **ports the Camoufox fingerprint onto whatever binary
//! is used**: it writes the profile's `user.js` (the `about:config` preference
//! layer) into the browser profile and passes Camoufox's engine-level config
//! through the same `CAMOU_CONFIG_*` environment variables the engine reads, so
//! the browser and the matched request engine share one identity (plan §6.3).
//!
//! The browser is launched **automation-ready** (`-marionette`, Firefox's remote
//! control protocol on 127.0.0.1:2828) so it can be driven by an agent — the
//! WebDriver-BiDi/Marionette control frontier the plan reserves (§9, §18). Camio
//! enables the channel and hides the `navigator.webdriver` tell via the profile;
//! a full agent-control layer over that channel is future work.

use camio_core::FingerprintProfile;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Candidate Firefox-family binary names, in preference order. Camio's own fork
/// (`camio-browser`, installed from the `.deb` to `/usr/bin/camio-browser`) wins
/// when present, then LibreWolf, then Camoufox, then stock Firefox.
pub const CANDIDATES: &[&str] = &[
    "camio-browser",
    "librewolf",
    "camoufox",
    "camoufox-bin",
    "firefox",
];

/// Resolve the browser binary: an explicit path if given and present, else the
/// first candidate found on `PATH`, else a vendored Camoufox under the engine
/// install root.
pub fn resolve_binary(explicit: &str, install_root: &str) -> Option<PathBuf> {
    let explicit = explicit.trim();
    if !explicit.is_empty() {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Some(p);
        }
    }
    for name in CANDIDATES {
        if let Some(p) = which(name) {
            return Some(p);
        }
    }
    camio_engine::locate_binary(Path::new(install_root.trim()))
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
    })
}

/// A launched browser process.
pub struct Launched {
    pub pid: u32,
    pub binary: PathBuf,
    pub marionette: bool,
}

/// Launch `binary` with Camio's fingerprint profile applied to `profile_dir`,
/// opening `url`. When `marionette` is set, the browser's remote-automation
/// channel is enabled so an agent can drive it.
/// Camio's black-&-blue browser chrome (userChrome.css), matching the native
/// app's "Sentinel Blue" theme: black toolbars, light-blue text, and the
/// `#83bcff` sky-blue accent on the URL bar, selected tab, buttons, popups and
/// sidebar. Kept byte-for-byte in sync with `browser/branding/userChrome.css`
/// so a stock LibreWolf Camio launches gets the same theme as the baked-in
/// `camio-browser` fork.
pub const CAMIO_USERCHROME_CSS: &str = include_str!("../../../browser/branding/userChrome.css");

/// Write the launched profile's files: the fingerprint `user.js` (with legacy
/// stylesheets enabled) and the Camio black/blue `chrome/userChrome.css`.
/// Split out from [`launch`] so it is testable without spawning a browser.
pub fn write_profile(profile_dir: &Path, profile: &FingerprintProfile) -> Result<(), String> {
    std::fs::create_dir_all(profile_dir)
        .map_err(|e| format!("creating profile dir {}: {e}", profile_dir.display()))?;
    // Port the Camoufox fingerprint (about:config layer) + enable userChrome.css.
    let mut user_js = profile.to_user_js();
    user_js.push_str("\n// Camio browser theme (black & blue chrome).\n");
    user_js.push_str("user_pref(\"toolkit.legacyUserProfileCustomizations.stylesheets\", true);\n");
    std::fs::write(profile_dir.join("user.js"), user_js)
        .map_err(|e| format!("writing user.js: {e}"))?;

    let chrome = profile_dir.join("chrome");
    std::fs::create_dir_all(&chrome).map_err(|e| format!("creating {}: {e}", chrome.display()))?;
    std::fs::write(chrome.join("userChrome.css"), CAMIO_USERCHROME_CSS)
        .map_err(|e| format!("writing userChrome.css: {e}"))?;
    Ok(())
}

pub fn launch(
    binary: &Path,
    profile: &FingerprintProfile,
    profile_dir: &Path,
    url: &str,
    marionette: bool,
) -> Result<Launched, String> {
    write_profile(profile_dir, profile)?;

    let mut cmd = Command::new(binary);
    cmd.arg("-profile")
        .arg(profile_dir)
        .arg("-no-remote")
        .arg("-new-instance");
    if marionette {
        cmd.arg("-marionette");
    }
    if !url.trim().is_empty() {
        cmd.arg(url.trim());
    }
    // ...and the engine-level overrides (navigator/screen/WebGL/timezone), via the
    // same chunked env protocol Camoufox reads. A plain LibreWolf/Firefox ignores
    // these; Camoufox applies them — either way the about:config layer still lands.
    for (k, v) in camio_engine::config_env_vars(&profile.to_camoufox_config()) {
        cmd.env(k, v);
    }
    cmd.env("TZ", &profile.persona.timezone);

    let child = cmd
        .spawn()
        .map_err(|e| format!("launching {}: {e}", binary.display()))?;
    Ok(Launched {
        pid: child.id(),
        binary: binary.to_path_buf(),
        marionette,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::FingerprintProfile;

    #[test]
    fn write_profile_emits_user_js_and_blue_userchrome() {
        let dir = std::env::temp_dir().join(format!("camio-prof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let profile = FingerprintProfile::new("t", "158.0.1-beta.41");
        write_profile(&dir, &profile).unwrap();

        let user_js = std::fs::read_to_string(dir.join("user.js")).unwrap();
        assert!(user_js.contains("general.useragent.override"));
        assert!(user_js.contains("legacyUserProfileCustomizations.stylesheets"));

        let css = std::fs::read_to_string(dir.join("chrome").join("userChrome.css")).unwrap();
        assert!(css.contains("#83bcff")); // the Cyber Sec "Sentinel Blue" accent
        assert!(css.contains("#navigator-toolbox"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
