//! A process-based plugin system (plan §8 Extensions, §13 "Extension host …
//! else a small local RPC boundary", §16 "isolate untrusted extensions").
//!
//! A plugin is a directory containing a `plugin.json` manifest that names a
//! command to run. Camio discovers plugins from a plugins directory, lists them,
//! and runs one on demand: the selected input is written to the plugin process's
//! stdin and its stdout is captured as the result. Because each plugin is a
//! separate OS process, a plugin can be written in any language and cannot share
//! Camio's address space.
//!
//! **Trust model:** a plugin runs an arbitrary command with the operator's
//! privileges. Plugins are therefore run only when the operator explicitly asks
//! (never automatically), and the UI shows the exact command before running it.
//! Treat third-party plugins as untrusted code and review the manifest first.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A plugin manifest (`plugin.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// A free-form category hint, e.g. `transform`, `scan`, `action`.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// The command to run. The first element is the program; the rest are args.
    /// Input is fed on stdin; output is read from stdout.
    pub command: Vec<String>,
}

fn default_kind() -> String {
    "transform".to_string()
}

/// A discovered plugin: its manifest plus the directory it was found in.
#[derive(Clone, Debug)]
pub struct Plugin {
    pub manifest: PluginManifest,
    pub dir: PathBuf,
}

impl Plugin {
    /// The command rendered for display (so the operator sees what will run).
    pub fn command_display(&self) -> String {
        self.manifest.command.join(" ")
    }
}

/// Discover plugins under `dir`: every immediate subdirectory containing a
/// `plugin.json`. Unreadable or invalid manifests are skipped silently.
pub fn discover(dir: &Path) -> Vec<Plugin> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("plugin.json");
        if !manifest_path.exists() {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&manifest_path) {
            if let Ok(manifest) = serde_json::from_str::<PluginManifest>(&text) {
                if !manifest.command.is_empty() {
                    out.push(Plugin {
                        manifest,
                        dir: path,
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| a.manifest.name.cmp(&b.manifest.name));
    out
}

/// Run a plugin: feed `input` on stdin, return captured stdout. A non-zero exit
/// is an error carrying the plugin's stderr.
pub fn run(plugin: &Plugin, input: &str) -> Result<String, String> {
    let cmd = &plugin.manifest.command;
    if cmd.is_empty() {
        return Err("plugin manifest has an empty command".to_string());
    }
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .current_dir(&plugin.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawning `{}`: {e}", cmd[0]))?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
        // `stdin` is dropped here, closing the pipe so the child sees EOF.
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("waiting for plugin: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "plugin exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses_with_defaults() {
        let m: PluginManifest =
            serde_json::from_str(r#"{"name":"x","command":["tr","a-z","A-Z"]}"#).unwrap();
        assert_eq!(m.name, "x");
        assert_eq!(m.kind, "transform"); // default
        assert_eq!(m.command, vec!["tr", "a-z", "A-Z"]);
    }

    #[test]
    fn run_uppercase_plugin_via_tr() {
        // Uses coreutils `tr` so the test needs no bespoke script.
        let plugin = Plugin {
            manifest: PluginManifest {
                name: "upper".into(),
                description: String::new(),
                kind: "transform".into(),
                command: vec!["tr".into(), "a-z".into(), "A-Z".into()],
            },
            dir: std::env::temp_dir(),
        };
        let out = run(&plugin, "hello camio").unwrap();
        assert_eq!(out, "HELLO CAMIO");
    }

    #[test]
    fn missing_program_is_an_error() {
        let plugin = Plugin {
            manifest: PluginManifest {
                name: "nope".into(),
                description: String::new(),
                kind: "transform".into(),
                command: vec!["camio_no_such_program_zzz".into()],
            },
            dir: std::env::temp_dir(),
        };
        assert!(run(&plugin, "x").is_err());
    }
}
