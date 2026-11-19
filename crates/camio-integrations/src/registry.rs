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
}

/// The tools Camio has adapters for.
pub const KNOWN_TOOLS: &[ToolInfo] = &[
    ToolInfo {
        name: "nuclei",
        binary: "nuclei",
        purpose: "template vulnerability scanner",
        version_args: &["-version"],
    },
    ToolInfo {
        name: "subfinder",
        binary: "subfinder",
        purpose: "passive subdomain enumeration",
        version_args: &["-version"],
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
    ToolStatus {
        name: info.name,
        purpose: info.purpose,
        installed: true,
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
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(IntegrationError::Run(e.to_string())),
        }
    }
    let _ = child.wait();

    // Version output is tiny; read both pipes after exit (no deadlock risk).
    let mut combined = String::new();
    if let Some(out) = child.stdout.take() {
        let mut s = String::new();
        let _ = out.take(8192).read_to_string(&mut s);
        combined.push_str(&s);
    }
    if let Some(err) = child.stderr.take() {
        let mut s = String::new();
        let _ = err.take(8192).read_to_string(&mut s);
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
