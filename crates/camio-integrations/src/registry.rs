//! Integration registry and health probe (plan §F16 "integration registry").
//!
//! A small, bounded "which tools are available" check so the GUI/CLI/MCP can show
//! what external integrations are usable before offering to run them. Each probe
//! runs the tool's version command with a short timeout and never blocks.

use crate::IntegrationError;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A known external tool Camio can drive.
#[derive(Debug, Clone, Copy)]
pub struct ToolInfo {
    pub name: &'static str,
    pub binary: &'static str,
    pub purpose: &'static str,
    /// Args that print the version (and exit).
    pub version_args: &'static [&'static str],
    /// When set, the version output must contain this marker (case-insensitive)
    /// for the binary to count as the tool Camio drives — so a *different*
    /// program squatting on the name is reported as not installed rather than
    /// shown working (plan §5.1 actionable diagnostics).
    pub compat_marker: Option<&'static str>,
}

/// The tools Camio has adapters for.
pub const KNOWN_TOOLS: &[ToolInfo] = &[
    ToolInfo {
        name: "nuclei",
        binary: "nuclei",
        purpose: "template vulnerability scanner",
        version_args: &["-version"],
        compat_marker: Some("nuclei"),
    },
    ToolInfo {
        name: "httpx",
        binary: "httpx",
        purpose: "HTTP prober (reachability + tech metadata)",
        version_args: &["-version"],
        // Only ProjectDiscovery's Go tool reports "Current Version: vX.Y.Z";
        // another `httpx` implementation is not this adapter's tool.
        compat_marker: Some(crate::httpx::EXPECTED_VERSION_MARKER),
    },
    ToolInfo {
        name: "subfinder",
        binary: "subfinder",
        purpose: "passive subdomain enumeration",
        version_args: &["-version"],
        compat_marker: None,
    },
];

/// The availability of one tool.
#[derive(Debug, Clone)]
pub struct ToolStatus {
    pub name: &'static str,
    pub purpose: &'static str,
    pub installed: bool,
    /// First line of the version output, when it could be read.
    pub version: Option<String>,
}

/// Probe one tool's availability within `timeout`.
pub fn probe_tool(info: &ToolInfo, timeout: Duration) -> ToolStatus {
    let version = match run_version(info.binary, info.version_args, timeout) {
        Ok(v) => Some(v).filter(|s| !s.is_empty()),
        Err(IntegrationError::NotInstalled(_)) => {
            return ToolStatus {
                name: info.name,
                purpose: info.purpose,
                installed: false,
                version: None,
            };
        }
        Err(_) => None,
    };
    // A binary that runs but is not the expected tool is not "installed" for
    // this adapter's purposes; say so instead of showing a green status.
    let installed = match (info.compat_marker, version.as_deref()) {
        (Some(marker), Some(line)) => line
            .to_ascii_lowercase()
            .contains(&marker.to_ascii_lowercase()),
        (Some(_), None) => false,
        (None, _) => true,
    };
    ToolStatus {
        name: info.name,
        purpose: info.purpose,
        installed,
        version,
    }
}

/// Probe every [`KNOWN_TOOLS`] entry with a short default timeout.
pub fn registry() -> Vec<ToolStatus> {
    KNOWN_TOOLS
        .iter()
        .map(|t| probe_tool(t, Duration::from_secs(5)))
        .collect()
}

/// Run `binary version_args`, bounded, and return the first non-empty output
/// line (stdout or stderr). `NotInstalled` if the binary is not on PATH.
fn run_version(binary: &str, args: &[&str], timeout: Duration) -> Result<String, IntegrationError> {
    let mut child = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                IntegrationError::NotInstalled(binary.to_string())
            } else {
                IntegrationError::Run(e.to_string())
            }
        })?;

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    // The version probe hung; kill it. reap() then does the
                    // wait, so a kill that lost the race with the child's own
                    // exit needs no report.
                    camio_core::expected(child.kill());
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(IntegrationError::Run(e.to_string())),
        }
    }
    // Reap the probe: kill is a no-op once exited, wait clears the zombie.
    camio_core::sync::reap(&mut child);

    // Version output is tiny; read both pipes after exit (no deadlock risk).
    let mut combined = String::new();
    if let Some(out) = child.stdout.take() {
        let mut s = String::new();
        read_some(out, &mut s, "stdout");
        combined.push_str(&s);
    }
    if let Some(err) = child.stderr.take() {
        let mut s = String::new();
        read_some(err, &mut s, "stderr");
        combined.push_str(&s);
    }
    let line = combined
        .lines()
        .map(clean_version_line)
        .find(|l| !l.is_empty())
        .unwrap_or_default();
    Ok(line)
}

/// Strip ANSI escapes and a leading `[INF]`/`[WRN]`-style log marker from a
/// tool's version line, so a probed version reads cleanly.
/// Read at most `limit` bytes of a tool's version output, reporting a read
/// failure. A failed read and "the tool printed nothing" both end in an empty
/// string, but only one of them means the tool is missing.
fn read_some(pipe: impl Read, buf: &mut String, which: &str) {
    let mut limited = pipe.take(8192);
    if let Err(e) = limited.read_to_string(buf) {
        eprintln!("camio-integrations: reading version output ({which}): {e}");
    }
}

fn clean_version_line(line: &str) -> String {
    // Drop CSI escape sequences (ESC '[' ... final byte).
    let mut out = String::with_capacity(line.len());
    let mut bytes = line.bytes().peekable();
    while let Some(b) = bytes.next() {
        if b == 0x1b {
            if bytes.peek() == Some(&b'[') {
                bytes.next();
                for c in bytes.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(b as char);
    }
    let trimmed = out.trim();
    // Strip a leading "[XXX] " log-level marker if present.
    let trimmed = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.split_once("] ").map(|(_, after)| after))
        .unwrap_or(trimmed);
    trimmed.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_tool_reports_not_installed() {
        let info = ToolInfo {
            name: "nope",
            binary: "camio-definitely-not-a-real-binary-xyz",
            purpose: "test",
            version_args: &["--version"],
            compat_marker: None,
        };
        let st = probe_tool(&info, Duration::from_secs(2));
        assert!(!st.installed);
        assert!(st.version.is_none());
    }

    #[test]
    fn cleans_ansi_and_log_prefix() {
        // ESC[34m [INF] ESC[0m Nuclei Engine Version: v3.11.1
        let raw = "\x1b[34m[INF]\x1b[0m Nuclei Engine Version: v3.11.1";
        assert_eq!(clean_version_line(raw), "Nuclei Engine Version: v3.11.1");
        assert_eq!(clean_version_line("plain v1.0"), "plain v1.0");
    }

    #[test]
    fn registry_covers_known_tools() {
        let reg = registry();
        assert_eq!(reg.len(), KNOWN_TOOLS.len());
        assert!(reg.iter().any(|t| t.name == "nuclei"));
        assert!(reg.iter().any(|t| t.name == "subfinder"));
    }
}
