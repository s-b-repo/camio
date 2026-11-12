//! `camio-engine` — the Camoufox engine supervisor (plan §13 item 2).
//!
//! Responsibilities implemented here:
//!   * pin a reproducible Camoufox release and know its download URL,
//!   * unpack a downloaded release into a managed location,
//!   * locate the `camoufox` executable,
//!   * prepare a browser profile by writing the fingerprint policy's `user.js`,
//!   * launch the browser with the engine-level fingerprint config applied.
//!
//! It deliberately does NOT route the browser through a TLS MITM — the whole
//! point (plan §6) is that the browser makes the real connection so the server
//! sees Camoufox's genuine fingerprint, not a proxy's.

use anyhow::{anyhow, bail, Context, Result};
use camio_core::FingerprintProfile;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

/// The pinned Camoufox release Camio is built and tested against. Bump this in
/// lock-step with `camio_core::ALIGNED_FIREFOX_MAJOR`.
pub const PINNED_VERSION: &str = "158.0.1-beta.41";

/// Build the release asset name for the current platform/arch.
pub fn asset_name() -> Result<String> {
    let plat = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "lin.x86_64",
        ("linux", "aarch64") => "lin.arm64",
        ("macos", "x86_64") => "mac.x86_64",
        ("macos", "aarch64") => "mac.arm64",
        ("windows", "x86_64") => "win.x86_64",
        (os, arch) => bail!("unsupported platform for Camoufox: {os}/{arch}"),
    };
    Ok(format!("camoufox-{PINNED_VERSION}-{plat}.zip"))
}

/// The GitHub release download URL for the current platform's asset.
pub fn download_url() -> Result<String> {
    Ok(format!(
        "https://github.com/daijro/camoufox/releases/download/v{PINNED_VERSION}/{}",
        asset_name()?
    ))
}

/// Unpack a downloaded Camoufox zip into `dest`, returning the located binary.
///
/// `dest` should be a fresh, dedicated directory (the zip is a large upstream
/// artifact; keep it isolated from Camio's own code).
pub fn unpack(zip_path: &Path, dest: &Path) -> Result<PathBuf> {
    let file =
        fs::File::open(zip_path).with_context(|| format!("opening {}", zip_path.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("reading zip archive")?;

    fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let Some(rel) = entry.enclosed_name() else {
            // Skip entries with unsafe paths (traversal / absolute).
            continue;
        };
        let out = dest.join(rel);

        if entry.is_dir() {
            fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out_file =
            fs::File::create(&out).with_context(|| format!("writing {}", out.display()))?;
        io::copy(&mut entry, &mut out_file)?;

        // Preserve the executable bit from the archive on unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = entry.unix_mode() {
                fs::set_permissions(&out, fs::Permissions::from_mode(mode)).ok();
            }
        }
    }

    let bin = locate_binary(dest)
        .ok_or_else(|| anyhow!("no 'camoufox' executable found under {}", dest.display()))?;
    ensure_executable(&bin)?;
    Ok(bin)
}

/// Find the Camoufox executable under `root` (depth-limited recursive search).
pub fn locate_binary(root: &Path) -> Option<PathBuf> {
    fn is_candidate(name: &str) -> bool {
        name == "camoufox" || name == "camoufox-bin" || name == "camoufox.exe"
    }
    fn walk(dir: &Path, depth: u32) -> Option<PathBuf> {
        if depth > 6 {
            return None;
        }
        let entries = fs::read_dir(dir).ok()?;
        let mut subdirs = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let ft = entry.file_type().ok()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if ft.is_file() && is_candidate(&name) {
                return Some(path);
            }
            if ft.is_dir() {
                subdirs.push(path);
            }
        }
        for sub in subdirs {
            if let Some(found) = walk(&sub, depth + 1) {
                return Some(found);
            }
        }
        None
    }
    walk(root, 0)
}

fn ensure_executable(bin: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(bin)?.permissions();
        perms.set_mode(perms.mode() | 0o755);
        fs::set_permissions(bin, perms)?;
    }
    let _ = bin;
    Ok(())
}

/// Split a Camoufox JSON config into the chunked environment variables the
/// engine reads (`CAMOU_CONFIG_1`, `CAMOU_CONFIG_2`, ...). The engine joins the
/// chunks back together; chunking exists because some platforms cap env-var
/// length.
///
/// NOTE: this follows Camoufox's documented env protocol but must be verified
/// against the pinned build in the Phase-0 spike (plan §15).
pub fn config_env_vars(config: &serde_json::Value) -> Vec<(String, String)> {
    const CHUNK: usize = 2000;
    let json = config.to_string();
    let bytes = json.as_bytes();
    let mut out = Vec::new();
    let mut idx = 1usize;
    let mut start = 0usize;
    while start < bytes.len() {
        let end = (start + CHUNK).min(bytes.len());
        // Avoid splitting a multi-byte UTF-8 char across chunks.
        let mut end = end;
        while end < bytes.len() && (bytes[end] & 0xC0) == 0x80 {
            end -= 1;
        }
        let part = std::str::from_utf8(&bytes[start..end])
            .unwrap_or("")
            .to_string();
        out.push((format!("CAMOU_CONFIG_{idx}"), part));
        idx += 1;
        start = end;
    }
    if out.is_empty() {
        out.push(("CAMOU_CONFIG_1".to_string(), "{}".to_string()));
    }
    out
}

/// Options for a browser launch.
#[derive(Debug, Clone, Default)]
pub struct LaunchOptions {
    /// Initial URL to open (authorized target).
    pub url: Option<String>,
    pub headless: bool,
    /// If true, build the command but do not spawn (for inspection/tests).
    pub dry_run: bool,
}

/// A located Camoufox installation.
#[derive(Debug, Clone)]
pub struct Camoufox {
    pub binary: PathBuf,
}

impl Camoufox {
    /// Locate an already-unpacked Camoufox under `install_root`.
    pub fn find(install_root: &Path) -> Result<Self> {
        let binary = locate_binary(install_root).ok_or_else(|| {
            anyhow!(
                "Camoufox not found under {}. Run `camio engine unpack` first.",
                install_root.display()
            )
        })?;
        Ok(Camoufox { binary })
    }

    /// Prepare a profile directory by writing the fingerprint policy's `user.js`.
    pub fn prepare_profile(&self, profile_dir: &Path, profile: &FingerprintProfile) -> Result<()> {
        fs::create_dir_all(profile_dir)
            .with_context(|| format!("creating profile dir {}", profile_dir.display()))?;
        let user_js = profile_dir.join("user.js");
        fs::write(&user_js, profile.to_user_js())
            .with_context(|| format!("writing {}", user_js.display()))?;
        Ok(())
    }

    /// Build the launch [`Command`] with fingerprint env + prefs applied.
    pub fn build_command(
        &self,
        profile_dir: &Path,
        profile: &FingerprintProfile,
        opts: &LaunchOptions,
    ) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("-profile")
            .arg(profile_dir)
            .arg("-no-remote")
            .arg("-new-instance");
        if opts.headless {
            cmd.arg("-headless");
        }
        if let Some(url) = &opts.url {
            cmd.arg(url);
        }

        // Engine-level fingerprint overrides.
        for (k, v) in config_env_vars(&profile.to_camoufox_config()) {
            cmd.env(k, v);
        }
        // Timezone also via TZ so OS-level calls agree with the persona.
        cmd.env("TZ", &profile.persona.timezone);
        cmd
    }

    /// Prepare the profile and launch the browser. Returns the child process
    /// unless `opts.dry_run` is set.
    pub fn launch(
        &self,
        profile_dir: &Path,
        profile: &FingerprintProfile,
        opts: &LaunchOptions,
    ) -> Result<Option<Child>> {
        self.prepare_profile(profile_dir, profile)?;
        let mut cmd = self.build_command(profile_dir, profile, opts);
        if opts.dry_run {
            return Ok(None);
        }
        let child = cmd
            .spawn()
            .with_context(|| format!("launching Camoufox binary {}", self.binary.display()))?;
        Ok(Some(child))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_and_url_are_pinned() {
        // On the CI platform this resolves; just assert the URL shape.
        if let Ok(url) = download_url() {
            assert!(url.contains(PINNED_VERSION));
            assert!(url.starts_with("https://github.com/daijro/camoufox/releases/"));
        }
    }

    #[test]
    fn config_chunks_rejoin_to_original() {
        let cfg = serde_json::json!({
            "navigator.userAgent": "x".repeat(5000),
            "timezone": "America/New_York",
        });
        let vars = config_env_vars(&cfg);
        assert!(vars.len() >= 3, "large config should chunk");
        let joined: String = vars.iter().map(|(_, v)| v.as_str()).collect();
        assert_eq!(joined, cfg.to_string());
    }

    #[test]
    fn build_command_sets_profile_and_tz() {
        let tmp = std::env::temp_dir().join("camio_test_prof");
        let cam = Camoufox {
            binary: PathBuf::from("/nonexistent/camoufox"),
        };
        let prof = FingerprintProfile::new("t", PINNED_VERSION);
        let cmd = cam.build_command(&tmp, &prof, &LaunchOptions::default());
        let envs: Vec<_> = cmd.get_envs().collect();
        assert!(envs.iter().any(|(k, _)| *k == std::ffi::OsStr::new("TZ")));
        assert!(envs
            .iter()
            .any(|(k, _)| k.to_string_lossy().starts_with("CAMOU_CONFIG_")));
    }
}
