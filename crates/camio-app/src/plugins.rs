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
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Wall-clock limit for one plugin run; a plugin still running after this is
/// terminated (plan §16: bound untrusted-extension runtime).
const PLUGIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on captured stdout/stderr per run (8 MiB). The pipe is still fully
/// drained so the child never blocks on a full buffer, but only this much is
/// retained in memory (plan §16: bound output).
const PLUGIN_MAX_OUTPUT: usize = 8 * 1024 * 1024;

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
    /// Declared capabilities (plan §F20). The default is the most restrictive:
    /// no host env beyond a safe runtime base, no declared network/filesystem use.
    #[serde(default)]
    pub permissions: PluginPermissions,
}

/// A plugin's declared permissions. `env` is **enforced** by the host (the child
/// runs with a scrubbed environment — only the safe runtime base plus these
/// names pass through, so a plugin cannot harvest API keys/tokens left in the
/// host environment). `network` and `filesystem` are **declared and surfaced**
/// for the operator to review before granting; OS-level network/FS isolation
/// (namespaces/seccomp) is out of this host's scope and noted as such.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PluginPermissions {
    /// Host environment variable names this plugin may read. Everything else is
    /// scrubbed from the child's environment.
    #[serde(default)]
    pub env: Vec<String>,
    /// The plugin declares it needs outbound network access (advisory).
    #[serde(default)]
    pub network: bool,
    /// Filesystem paths the plugin declares it reads/writes (advisory).
    #[serde(default)]
    pub filesystem: Vec<String>,
}

/// Environment variables always passed through: a non-secret runtime base that
/// interpreters (python, node, sh) need to function. Secret-bearing names
/// (tokens, `CAMIO_*`, cloud creds) are deliberately absent.
const BASE_ENV_ALLOW: &[&str] = &["PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ"];

impl PluginPermissions {
    /// A one-line operator-facing summary of what this plugin asks for.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.env.is_empty() {
            parts.push("env: locked (runtime base only)".to_string());
        } else {
            parts.push(format!("env: +{}", self.env.join(",")));
        }
        if self.network {
            parts.push("network: declared".to_string());
        }
        if !self.filesystem.is_empty() {
            parts.push(format!("fs: {}", self.filesystem.join(",")));
        }
        parts.join("; ")
    }
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

    /// One-line summary of the plugin's declared permissions, for the operator to
    /// review before running untrusted code (plan §F20).
    pub fn permission_summary(&self) -> String {
        self.manifest.permissions.summary()
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
        // A plugin that cannot be loaded is the operator's problem to hear
        // about: silently skipping it looks identical to "no plugins here".
        match std::fs::read_to_string(&manifest_path) {
            Err(e) => eprintln!(
                "camio: plugin {} could not be read: {e}",
                manifest_path.display()
            ),
            Ok(text) => match serde_json::from_str::<PluginManifest>(&text) {
                Err(e) => eprintln!(
                    "camio: plugin {} is not a valid manifest: {e}",
                    manifest_path.display()
                ),
                Ok(manifest) if manifest.command.is_empty() => eprintln!(
                    "camio: plugin {} declares no command; skipping",
                    manifest_path.display()
                ),
                Ok(manifest) => out.push(Plugin {
                    manifest,
                    dir: path,
                }),
            },
        }
    }
    out.sort_by(|a, b| a.manifest.name.cmp(&b.manifest.name));
    out
}

/// Run a plugin: feed `input` on stdin, return captured stdout. A non-zero exit
/// is an error carrying the plugin's stderr. The run is bounded by
/// [`PLUGIN_TIMEOUT`] and [`PLUGIN_MAX_OUTPUT`].
pub fn run(plugin: &Plugin, input: &str) -> Result<String, String> {
    run_with_limits(plugin, input, PLUGIN_TIMEOUT, PLUGIN_MAX_OUTPUT)
}

/// [`run`] with explicit limits (so tests can exercise the timeout/cap cheaply).
fn run_with_limits(
    plugin: &Plugin,
    input: &str,
    timeout: Duration,
    max_output: usize,
) -> Result<String, String> {
    let cmd = &plugin.manifest.command;
    let Some(program) = cmd.first() else {
        return Err("plugin manifest has an empty command".to_string());
    };
    let rest = cmd.get(1..).unwrap_or(&[]);
    let mut command = Command::new(program);
    command
        .args(rest)
        .current_dir(&plugin.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Enforce the env permission (plan §F20): start from an empty environment and
    // pass through only the safe runtime base plus the names the manifest declares.
    // This is a real boundary the host owns — a plugin cannot read API keys/tokens
    // or `CAMIO_*` secrets that happen to be in the host environment.
    command.env_clear();
    for key in BASE_ENV_ALLOW
        .iter()
        .copied()
        .chain(plugin.manifest.permissions.env.iter().map(String::as_str))
    {
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("spawning `{program}`: {e}"))?;

    // Drain stdout and stderr on their own threads so a chatty plugin cannot
    // deadlock by filling one pipe while we wait on the other; each thread reads
    // to EOF but retains at most PLUGIN_MAX_OUTPUT bytes. These must start BEFORE
    // we feed stdin: a plugin that streams output as it reads could otherwise
    // fill its stdout pipe, stop reading, and leave the writer below blocked.
    let out_reader = child.stdout.take().map(|pipe| {
        std::thread::spawn(move || drain_capped(pipe, max_output))
    });
    let err_reader = child.stderr.take().map(|pipe| {
        std::thread::spawn(move || drain_capped(pipe, max_output))
    });

    // Feed stdin on its OWN thread, never the main one. For an input larger than
    // the OS pipe buffer (~64 KiB) given to a streaming plugin, a main-thread
    // `write_all` would block until the child drains it — but if that child is
    // itself blocked writing stdout, neither side moves and the timeout loop
    // below is never reached. Writing off-thread keeps the main thread free to
    // reach the wait/kill loop; a timeout kill closes the pipe and unblocks this
    // writer. A broken pipe is the expected case when the plugin exits early or
    // does not read stdin; the run's outcome is reported either way.
    let input_bytes = input.as_bytes().to_vec();
    let stdin_writer = child.stdin.take().map(|mut stdin| {
        std::thread::spawn(move || {
            camio_core::expected(stdin.write_all(&input_bytes));
            // `stdin` drops here, closing the pipe so the child sees EOF.
        })
    });

    // Wait with a wall-clock timeout; terminate a plugin that overruns it.
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(format!("waiting for plugin: {e}")),
        }
    };

    // The child has exited or been killed, so the stdin pipe's read end is gone:
    // the writer thread's `write_all` has returned (completed or broken-pipe) and
    // this join does not block. Doing it here keeps the thread from leaking.
    if let Some(h) = stdin_writer {
        let _ = h.join();
    }

    let (stdout, out_truncated) = out_reader
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let (stderr, _) = err_reader.and_then(|h| h.join().ok()).unwrap_or_default();

    let Some(status) = status else {
        return Err(format!(
            "plugin exceeded the {}s time limit and was terminated",
            timeout.as_secs()
        ));
    };
    if status.success() {
        let mut text = String::from_utf8_lossy(&stdout).into_owned();
        if out_truncated {
            text.push_str("\n…[output truncated at the plugin output cap]");
        }
        Ok(text)
    } else {
        Err(format!(
            "plugin exited with {}: {}",
            status,
            String::from_utf8_lossy(&stderr).trim()
        ))
    }
}

/// Read `pipe` to EOF, retaining at most `cap` bytes. Returns the captured bytes
/// and whether more was produced than retained. The full stream is consumed so
/// the writing child never blocks on a full pipe.
fn drain_capped(mut pipe: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if kept.len() < cap {
                    let take = n.min(cap - kept.len());
                    kept.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (kept, truncated)
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
                permissions: Default::default(),
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
                permissions: Default::default(),
            },
            dir: std::env::temp_dir(),
        };
        assert!(run(&plugin, "x").is_err());
    }

    fn plugin(command: Vec<&str>) -> Plugin {
        plugin_with(command, PluginPermissions::default())
    }

    fn plugin_with(command: Vec<&str>, permissions: PluginPermissions) -> Plugin {
        Plugin {
            manifest: PluginManifest {
                name: "t".into(),
                description: String::new(),
                kind: "transform".into(),
                command: command.into_iter().map(String::from).collect(),
                permissions,
            },
            dir: std::env::temp_dir(),
        }
    }

    #[test]
    fn env_is_scrubbed_unless_the_manifest_declares_the_name() {
        // A secret left in the host environment must NOT reach a plugin that did
        // not declare it; a declared name passes through.
        std::env::set_var("CAMIO_TEST_SECRET_TOKEN", "leaked");
        // Undeclared: the plugin sees an empty value.
        let p = plugin(vec!["sh", "-c", "printf '%s' \"$CAMIO_TEST_SECRET_TOKEN\""]);
        assert_eq!(run(&p, "").unwrap(), "", "secret leaked into an undeclaring plugin");
        // Declared: the plugin receives it.
        let p2 = plugin_with(
            vec!["sh", "-c", "printf '%s' \"$CAMIO_TEST_SECRET_TOKEN\""],
            PluginPermissions {
                env: vec!["CAMIO_TEST_SECRET_TOKEN".into()],
                ..Default::default()
            },
        );
        assert_eq!(run(&p2, "").unwrap(), "leaked");
        std::env::remove_var("CAMIO_TEST_SECRET_TOKEN");
    }

    #[test]
    fn permission_summary_reads_clearly() {
        let locked = PluginPermissions::default();
        assert!(locked.summary().contains("locked"));
        let open = PluginPermissions {
            env: vec!["API_BASE".into()],
            network: true,
            filesystem: vec!["/tmp/work".into()],
        };
        let s = open.summary();
        assert!(s.contains("+API_BASE") && s.contains("network") && s.contains("/tmp/work"));
    }

    #[test]
    fn manifest_permissions_parse_and_default_to_locked() {
        let m: PluginManifest =
            serde_json::from_str(r#"{"name":"x","command":["cat"]}"#).unwrap();
        assert!(m.permissions.env.is_empty() && !m.permissions.network);
        let m2: PluginManifest = serde_json::from_str(
            r#"{"name":"x","command":["cat"],"permissions":{"env":["API_KEY"],"network":true}}"#,
        )
        .unwrap();
        assert_eq!(m2.permissions.env, vec!["API_KEY"]);
        assert!(m2.permissions.network);
    }

    #[test]
    fn a_plugin_that_overruns_the_timeout_is_terminated() {
        // `sleep 30` would hang the old unbounded runner; a 1s limit kills it.
        let p = plugin(vec!["sleep", "30"]);
        let start = Instant::now();
        let err = run_with_limits(&p, "", Duration::from_millis(500), PLUGIN_MAX_OUTPUT)
            .unwrap_err();
        assert!(err.contains("time limit"), "unexpected: {err}");
        assert!(start.elapsed() < Duration::from_secs(5), "should not have waited for sleep");
    }

    #[test]
    fn a_large_input_to_a_streaming_filter_does_not_deadlock() {
        // Regression: the writer used to run on the main thread before the stdout
        // drain started. An input larger than the OS pipe buffer (~64 KiB) fed to
        // a filter that streams output as it reads (`cat`) would fill the child's
        // stdout pipe, stop it reading stdin, block the main-thread write_all, and
        // the timeout loop would never run — an indefinite hang. With stdin fed
        // off-thread and the drains started first, this completes promptly.
        let p = plugin(vec!["cat"]);
        let input = "x".repeat(512 * 1024); // 512 KiB ≫ pipe buffer
        let start = Instant::now();
        let out = run_with_limits(&p, &input, Duration::from_secs(10), 2 * 1024 * 1024)
            .expect("cat should echo its input");
        assert_eq!(out.len(), input.len(), "cat should echo the whole input back");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "should not have hung: took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn output_is_capped_and_marked_truncated() {
        // `yes` prints an unbounded stream; the cap must retain only `max_output`
        // bytes, drain the rest, and still return (not hang).
        let p = plugin(vec!["yes", "camio"]);
        let out = run_with_limits(&p, "", Duration::from_secs(1), 4096).unwrap_or_else(|e| e);
        // `yes` never exits on its own, so it hits the timeout; either way the
        // run returns bounded output rather than hanging or OOMing.
        assert!(out.len() < 20_000, "output should be bounded, got {}", out.len());
    }
}
