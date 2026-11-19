//! Nuclei adapter: run ProjectDiscovery's template scanner and normalize its
//! JSONL results into Camio [`Finding`]s.
//!
//! The parser is tolerant — it skips lines it can't read rather than failing the
//! whole run — because a long scan shouldn't be lost to one malformed record.
//! The runner disables Nuclei's update check and its public interactsh OOB
//! server by default (Camio is local-first and ships its own OAST collector).

use crate::{IntegrationError, MAX_OUTPUT_BYTES};
use camio_core::{Confidence, Finding, FindingId, Severity};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// One normalized Nuclei result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NucleiFinding {
    pub template_id: String,
    pub name: String,
    /// Raw severity token (`info`/`low`/`medium`/`high`/`critical`/`unknown`).
    pub severity: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    /// Protocol/type (`http`, `dns`, `tcp`, …).
    pub kind: String,
    pub host: Option<String>,
    /// The exact location that matched (usually a URL).
    pub matched_at: Option<String>,
}

/// The subset of Nuclei's JSONL record Camio reads.
#[derive(Deserialize)]
struct RawNuclei {
    #[serde(rename = "template-id", default)]
    template_id: String,
    #[serde(default)]
    info: RawInfo,
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(rename = "matched-at", default)]
    matched_at: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawInfo {
    #[serde(default)]
    name: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: TagsField,
}

/// Nuclei's `tags` is usually an array but can be a comma-joined string.
#[derive(Default)]
struct TagsField(Vec<String>);

impl<'de> Deserialize<'de> for TagsField {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let v = serde_json::Value::deserialize(d)?;
        match v {
            serde_json::Value::Array(items) => Ok(TagsField(
                items
                    .into_iter()
                    .filter_map(|i| i.as_str().map(str::to_string))
                    .collect(),
            )),
            serde_json::Value::String(s) => Ok(TagsField(
                s.split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect(),
            )),
            serde_json::Value::Null => Ok(TagsField(Vec::new())),
            _ => Err(D::Error::custom("tags must be an array or string")),
        }
    }
}

/// Parse Nuclei JSONL (one JSON object per line). Blank and unparseable lines
/// are skipped so a single bad record never discards a whole scan.
pub fn parse_nuclei_jsonl(output: &str) -> Vec<NucleiFinding> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(raw) = serde_json::from_str::<RawNuclei>(line) else {
            continue;
        };
        out.push(NucleiFinding {
            template_id: raw.template_id,
            name: raw.info.name,
            severity: raw.info.severity,
            description: raw.info.description,
            tags: raw.info.tags.0,
            kind: raw.kind,
            host: raw.host,
            matched_at: raw.matched_at,
        });
    }
    out
}

/// Map Nuclei's severity token to Camio's [`Severity`] (unknown → `Info`).
pub fn map_severity(sev: &str) -> Severity {
    match sev.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Convert normalized Nuclei results into Camio findings. Evidence is empty: a
/// Nuclei match references an external location, not a stored Camio exchange, so
/// the matched URL is recorded in the detail rather than fabricated as evidence.
pub fn nuclei_to_findings(items: &[NucleiFinding]) -> Vec<Finding> {
    items
        .iter()
        .map(|n| {
            let title = if n.name.is_empty() {
                format!("Nuclei: {}", n.template_id)
            } else {
                format!("{} [{}]", n.name, n.template_id)
            };
            let mut detail = String::new();
            if let Some(d) = &n.description {
                if !d.is_empty() {
                    detail.push_str(d);
                    detail.push_str("\n\n");
                }
            }
            if let Some(m) = &n.matched_at {
                detail.push_str(&format!("- Matched at: `{m}`\n"));
            } else if let Some(h) = &n.host {
                detail.push_str(&format!("- Host: `{h}`\n"));
            }
            detail.push_str(&format!("- Template: `{}` ({})\n", n.template_id, n.kind));
            if !n.tags.is_empty() {
                detail.push_str(&format!("- Tags: {}\n", n.tags.join(", ")));
            }
            detail.push_str("- Source: nuclei (external)\n");
            Finding {
                id: FindingId(0),
                title,
                severity: map_severity(&n.severity),
                confidence: Confidence::Firm,
                detail,
                evidence: Vec::new(),
                created_at_ms: 0,
            }
        })
        .collect()
}

/// Options for a bounded Nuclei run.
pub struct NucleiOptions {
    /// Limit to these severities (comma-joined for `-severity`); empty = all.
    pub severities: Vec<String>,
    /// Limit to templates with these tags; empty = all.
    pub tags: Vec<String>,
    /// Requests-per-second cap (`-rate-limit`).
    pub rate_limit: Option<u32>,
    /// Overall wall-clock timeout; the process is killed if it runs longer.
    pub timeout: Duration,
    /// Extra raw args appended verbatim (e.g. `-t`, a template path).
    pub extra_args: Vec<String>,
}

impl Default for NucleiOptions {
    fn default() -> Self {
        NucleiOptions {
            severities: Vec::new(),
            tags: Vec::new(),
            rate_limit: None,
            timeout: Duration::from_secs(300),
            extra_args: Vec::new(),
        }
    }
}

/// Run Nuclei against `targets` (fed on stdin) and return normalized findings.
///
/// Bounded per plan §4.2: the process is killed after `opts.timeout`, stdout is
/// capped at [`MAX_OUTPUT_BYTES`], and Nuclei's update check and public OOB
/// server are disabled. A missing binary yields [`IntegrationError::NotInstalled`].
pub fn run_nuclei(
    targets: &[String],
    opts: &NucleiOptions,
) -> Result<Vec<NucleiFinding>, IntegrationError> {
    let mut cmd = Command::new("nuclei");
    cmd.args([
        "-silent",
        "-jsonl",
        "-no-interactsh",
        "-disable-update-check",
    ]);
    if !opts.severities.is_empty() {
        cmd.args(["-severity", &opts.severities.join(",")]);
    }
    if !opts.tags.is_empty() {
        cmd.args(["-tags", &opts.tags.join(",")]);
    }
    if let Some(rl) = opts.rate_limit {
        cmd.args(["-rate-limit", &rl.to_string()]);
    }
    for a in &opts.extra_args {
        cmd.arg(a);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            IntegrationError::NotInstalled("nuclei".into())
        } else {
            IntegrationError::Run(e.to_string())
        }
    })?;

    // Feed targets on stdin, then close it so Nuclei starts.
    if let Some(mut stdin) = child.stdin.take() {
        for t in targets {
            let _ = writeln!(stdin, "{t}");
        }
    }

    // Capture stdout on a thread (bounded), killing the process on timeout.
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
    Ok(parse_nuclei_jsonl(&output))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
{"template-id":"tech-detect","info":{"name":"Wappalyzer Technology Detection","severity":"info","tags":["tech"]},"type":"http","host":"https://ex.test","matched-at":"https://ex.test/"}
{"template-id":"CVE-2021-1234","info":{"name":"Example RCE","severity":"critical","description":"Remote code execution.","tags":"cve,rce"},"type":"http","host":"https://ex.test","matched-at":"https://ex.test/api?x=1"}
not json, should be skipped
{"template-id":"weak-cipher","info":{"name":"Weak TLS Cipher","severity":"low"},"type":"ssl","host":"ex.test:443"}
"#;

    #[test]
    fn parses_jsonl_tolerantly() {
        let items = parse_nuclei_jsonl(SAMPLE);
        assert_eq!(items.len(), 3, "the non-JSON line must be skipped");
        assert_eq!(items[0].template_id, "tech-detect");
        assert_eq!(items[0].tags, vec!["tech"]);
        assert_eq!(items[1].severity, "critical");
        // tags-as-string is split.
        assert_eq!(items[1].tags, vec!["cve", "rce"]);
        assert_eq!(
            items[1].matched_at.as_deref(),
            Some("https://ex.test/api?x=1")
        );
        assert_eq!(items[2].kind, "ssl");
        assert!(items[2].matched_at.is_none());
    }

    #[test]
    fn severity_maps_to_camio() {
        assert_eq!(map_severity("critical"), Severity::Critical);
        assert_eq!(map_severity("HIGH"), Severity::High);
        assert_eq!(map_severity("medium"), Severity::Medium);
        assert_eq!(map_severity("low"), Severity::Low);
        assert_eq!(map_severity("info"), Severity::Info);
        assert_eq!(map_severity("unknown"), Severity::Info);
    }

    #[test]
    fn maps_to_findings_with_context() {
        let items = parse_nuclei_jsonl(SAMPLE);
        let findings = nuclei_to_findings(&items);
        assert_eq!(findings.len(), 3);
        let rce = &findings[1];
        assert_eq!(rce.severity, Severity::Critical);
        assert!(rce.title.contains("Example RCE"));
        assert!(rce.title.contains("CVE-2021-1234"));
        assert!(rce.detail.contains("Remote code execution."));
        assert!(rce.detail.contains("https://ex.test/api?x=1"));
        assert!(rce.detail.contains("nuclei (external)"));
        assert!(rce.evidence.is_empty(), "no fabricated exchange evidence");
    }

    #[test]
    fn empty_output_is_no_findings() {
        assert!(parse_nuclei_jsonl("").is_empty());
        assert!(parse_nuclei_jsonl("\n  \n").is_empty());
    }
}
