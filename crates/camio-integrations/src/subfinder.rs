//! Subfinder adapter: run ProjectDiscovery's passive subdomain enumerator and
//! normalize its JSONL into a deduplicated host list.
//!
//! Subfinder output is reconnaissance *assets* (hostnames), not findings — so
//! this adapter returns hosts the operator can fold into scope/targets rather
//! than fabricating findings. The parser is tolerant and the runner is bounded
//! (timeout + process kill), matching the rest of the integration layer.

use crate::{IntegrationError, MAX_OUTPUT_BYTES};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// One discovered subdomain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subdomain {
    pub host: String,
    /// The root domain the search started from.
    pub input: Option<String>,
    /// The passive source that reported it (e.g. `crtsh`).
    pub source: Option<String>,
}

#[derive(Deserialize)]
struct RawSubfinder {
    #[serde(default)]
    host: String,
    #[serde(default)]
    input: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

/// Parse subfinder JSONL (one object per line). Blank/unparseable lines and
/// records with no `host` are skipped.
pub fn parse_subfinder_jsonl(output: &str) -> Vec<Subdomain> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(raw) = serde_json::from_str::<RawSubfinder>(line) else {
            continue;
        };
        if raw.host.is_empty() {
            continue;
        }
        out.push(Subdomain {
            host: raw.host.to_ascii_lowercase(),
            input: raw.input,
            source: raw.source,
        });
    }
    out
}

/// The unique hosts from a set of subdomain records, sorted.
pub fn unique_hosts(items: &[Subdomain]) -> Vec<String> {
    let mut hosts: Vec<String> = items.iter().map(|s| s.host.clone()).collect();
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}

/// Options for a bounded subfinder run.
pub struct SubfinderOptions {
    /// Restrict to these passive sources; empty = subfinder's default set.
    pub sources: Vec<String>,
    /// Use every source (`-all`).
    pub all_sources: bool,
    /// Overall wall-clock timeout; the process is killed if it runs longer.
    pub timeout: Duration,
    /// Extra raw args appended verbatim.
    pub extra_args: Vec<String>,
}

impl Default for SubfinderOptions {
    fn default() -> Self {
        SubfinderOptions {
            sources: Vec::new(),
            all_sources: false,
            timeout: Duration::from_secs(120),
            extra_args: Vec::new(),
        }
    }
}

/// Run subfinder against `domains` (passed on stdin) and return discovered
/// subdomains. Bounded per plan §4.2; a missing binary yields
/// [`IntegrationError::NotInstalled`].
pub fn run_subfinder(
    domains: &[String],
    opts: &SubfinderOptions,
) -> Result<Vec<Subdomain>, IntegrationError> {
    let mut cmd = Command::new("subfinder");
    cmd.args(["-silent", "-json"]);
    if opts.all_sources {
        cmd.arg("-all");
    }
    if !opts.sources.is_empty() {
        cmd.args(["-sources", &opts.sources.join(",")]);
    }
    for a in &opts.extra_args {
        cmd.arg(a);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            IntegrationError::NotInstalled("subfinder".into())
        } else {
            IntegrationError::Run(e.to_string())
        }
    })?;

    if let Some(mut stdin) = child.stdin.take() {
        for d in domains {
            let _ = writeln!(stdin, "{d}");
        }
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| IntegrationError::Run("no stdout pipe".into()))?;
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if buf.len() + line.len() <= MAX_OUTPUT_BYTES {
                        buf.push_str(&line);
                    }
                }
            }
        }
        buf
    });

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > opts.timeout {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(IntegrationError::Run(e.to_string())),
        }
    }
    let _ = child.wait();
    let output = reader.join().unwrap_or_default();
    Ok(parse_subfinder_jsonl(&output))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
{"host":"www.Example.com","input":"example.com","source":"crtsh"}
{"host":"api.example.com","input":"example.com","source":"dnsdumpster"}
garbage line
{"input":"example.com","source":"nohost"}
{"host":"www.example.com","input":"example.com","source":"otx"}
"#;

    #[test]
    fn parses_and_lowercases_hosts() {
        let items = parse_subfinder_jsonl(SAMPLE);
        // The garbage line and the host-less record are skipped.
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].host, "www.example.com"); // lowercased
        assert_eq!(items[0].source.as_deref(), Some("crtsh"));
    }

    #[test]
    fn unique_hosts_are_sorted_and_deduped() {
        let items = parse_subfinder_jsonl(SAMPLE);
        let hosts = unique_hosts(&items);
        assert_eq!(hosts, vec!["api.example.com", "www.example.com"]);
    }

    #[test]
    fn empty_is_no_hosts() {
        assert!(parse_subfinder_jsonl("").is_empty());
        assert!(unique_hosts(&[]).is_empty());
    }
}
