//! ProjectDiscovery httpx adapter (plan §6).
//!
//! Two halves, like every adapter here: a **pure parser** that normalizes
//! httpx's JSONL output into [`ProbeResult`]s (unit-tested from fixtures, no
//! binary needed), and a **bounded runner** that drives the real binary with a
//! timeout, an output cap, and cooperative cancellation (plan §4.2).
//!
//! httpx results are *observations*, not vulnerabilities: reachability,
//! metadata, and technology notes that enrich the project inventory. They are
//! stored as `source=httpx` observations (see [`ArtifactFormat::Httpx`]) and
//! never promoted to findings — a live host is not a finding.
//!
//! Flag selection is deliberately conservative: only long-documented flags are
//! passed by default, everything else arrives as explicit `extra_args` the
//! operator reviewed. httpx's update check is disabled so opening a project
//! never reaches out on its own (plan §5.1).

use crate::{IntegrationError, MAX_OUTPUT_BYTES};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// One normalized httpx probe result.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProbeResult {
    /// The target as given (the `input` field).
    pub input: String,
    /// The URL httpx reports (post any scheme/redirect decision).
    pub url: String,
    pub scheme: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub path: Option<String>,
    /// HTTP status when the host answered.
    pub status: Option<u16>,
    pub title: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub web_server: Option<String>,
    /// Detected technologies (from `-td`), lowercased as httpx reports them.
    pub technologies: Vec<String>,
    /// Resolved A records (`-ip`).
    pub ips: Vec<String>,
    /// Resolved CNAMEs (`-cname`).
    pub cnames: Vec<String>,
    /// CDN name when httpx identifies one (`-cdn`).
    pub cdn: Option<String>,
    /// CN and SANs from the leaf certificate (`-tls`).
    pub tls_cn: Option<String>,
    pub tls_sans: Vec<String>,
    /// Response time in milliseconds (`-rt`).
    pub duration_ms: Option<u64>,
    /// httpx marks a failed probe (`failed: true`) rather than omitting it;
    /// unreachable targets must stay visible as an outcome (plan §6).
    pub failed: bool,
    /// Error lines httpx reports for a failed probe.
    pub errors: Vec<String>,
}

/// The subset of an httpx JSONL record Camio reads. Field spellings vary
/// across httpx versions (`status-code` before `status_code`), so both are
/// accepted and anything unknown is ignored.
#[derive(Deserialize)]
struct RawHttpx {
    #[serde(default)]
    input: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    scheme: Option<String>,
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    path: Option<String>,
    #[serde(rename = "status-code", alias = "status_code", default)]
    status: Option<u16>,
    #[serde(default)]
    title: Option<String>,
    #[serde(rename = "content-type", alias = "content_type", default)]
    content_type: Option<String>,
    #[serde(rename = "content-length", alias = "content_length", default)]
    content_length: Option<u64>,
    #[serde(rename = "webserver", alias = "server", default)]
    web_server: Option<String>,
    #[serde(default)]
    technologies: Vec<String>,
    #[serde(default)]
    a: Vec<String>,
    #[serde(default)]
    cname: Vec<String>,
    #[serde(default)]
    cdn: CdnField,
    #[serde(default)]
    failed: bool,
    #[serde(default)]
    error: Vec<String>,
    #[serde(rename = "tech", default)]
    tech: Vec<String>,
    #[serde(default)]
    duration: Option<String>,
    #[serde(default)]
    tls: Option<RawTls>,
}

#[derive(Deserialize, Default)]
struct RawTls {
    #[serde(rename = "subject-cn", alias = "subject_cn", default)]
    subject_cn: Option<String>,
    #[serde(rename = "subject-an", alias = "subject_an", default)]
    subject_an: Vec<String>,
    #[serde(rename = "subject-dns-names", default)]
    subject_dns_names: Vec<String>,
}

/// httpx writes `cdn: false` when no CDN was detected and the provider name as
/// a string when one was — a bool-or-string field.
#[derive(Default)]
struct CdnField(Option<String>);

impl<'de> Deserialize<'de> for CdnField {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        match v {
            serde_json::Value::String(s) => {
                let s = s.trim().to_string();
                Ok(CdnField((!s.is_empty()).then_some(s)))
            }
            serde_json::Value::Bool(_) | serde_json::Value::Null => Ok(CdnField(None)),
            other => Ok(CdnField(Some(other.to_string()))),
        }
    }
}

/// Parse httpx JSONL (one JSON object per line). Tolerant: blank and
/// unparseable lines are skipped, and partially-populated records are kept so a
/// successful probe with one missing field is not lost.
pub fn parse_httpx_jsonl(output: &str) -> Vec<ProbeResult> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(raw) = serde_json::from_str::<RawHttpx>(line) else {
            continue;
        };
        out.push(normalize(raw));
    }
    out
}

fn normalize(raw: RawHttpx) -> ProbeResult {
    let tls = raw.tls.unwrap_or_default();
    let mut technologies = raw.technologies;
    technologies.extend(raw.tech);
    let mut tls_sans = tls.subject_an;
    tls_sans.extend(tls.subject_dns_names);
    ProbeResult {
        input: raw.input,
        url: raw.url,
        scheme: raw.scheme,
        host: raw.host,
        port: raw.port,
        path: raw.path,
        status: raw.status,
        title: raw.title,
        content_type: raw.content_type,
        content_length: raw.content_length,
        web_server: raw.web_server,
        technologies,
        ips: raw.a,
        cnames: raw.cname,
        cdn: raw.cdn.0,
        tls_cn: tls.subject_cn,
        tls_sans,
        duration_ms: parse_duration_ms(raw.duration.as_deref()),
        failed: raw.failed,
        errors: raw.error,
    }
}

/// httpx reports response time as a Go-style duration string ("137.4ms").
fn parse_duration_ms(s: Option<&str>) -> Option<u64> {
    let s = s?.trim();
    if s.is_empty() {
        return None;
    }
    let lowered = s.to_ascii_lowercase();
    let (num, unit_ms) = if let Some(v) = lowered.strip_suffix("ms") {
        (v, 1.0)
    } else if let Some(v) = lowered.strip_suffix('s') {
        (v, 1_000.0)
    } else if let Some(v) = lowered.strip_suffix("µs") {
        (v, 0.001)
    } else {
        (lowered.as_str(), 0.000_001) // plain nanoseconds
    };
    num.trim().parse::<f64>().ok().map(|n| (n * unit_ms) as u64)
}

/// Options for a bounded httpx run. Only defaults that cannot surprise the
/// operator are set: no host expansion, no scheme fallback, no redirect
/// following, no browser/screenshot activity — those are opt-in flags (plan §6).
#[derive(Debug, Clone)]
pub struct HttpxOptions {
    /// Requests-per-second cap (`-rl`).
    pub rate_limit: Option<u32>,
    /// Concurrent probes (`-c`); bounded so a misconfigured run can't flood.
    pub concurrency: Option<u32>,
    /// Per-probe timeout in seconds (`-timeout`).
    pub timeout_secs: Option<u64>,
    /// Follow redirects (`-follow-redirects`); off unless the plan allows it.
    pub follow_redirects: bool,
    /// Extra raw args appended verbatim (already reviewed by the operator).
    pub extra_args: Vec<String>,
    /// Maximum targets probed in one run (a bound on the whole run).
    pub max_targets: Option<usize>,
    /// Retain only observations whose response is at most this many bytes.
    /// Applied client-side after parsing (httpx's own size flags vary by
    /// version), so the bound is exact regardless of the installed build.
    pub max_response_bytes: Option<usize>,
    /// Overall wall-clock timeout; the process is killed if it runs longer.
    pub timeout: Duration,
}

impl Default for HttpxOptions {
    fn default() -> Self {
        HttpxOptions {
            rate_limit: None,
            concurrency: Some(25),
            timeout_secs: Some(10),
            follow_redirects: false,
            extra_args: Vec::new(),
            max_targets: None,
            max_response_bytes: None,
            timeout: Duration::from_secs(120),
        }
    }
}

/// The default probe flags: structured JSONL output, a readable metadata set,
/// no color, and no update check. Redirect following and host expansion stay
/// off (plan §6: never silently widen an approved plan).
/// Bound on retained tool stderr used for diagnostics.
const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024;

/// ProjectDiscovery's httpx reports its version as `Current Version: vX.Y.Z`.
/// Another tool named `httpx` on PATH (a similarly named utility) must not be
/// mistaken for the Go binary this adapter drives, so the marker is checked
/// before any probe runs.
pub const EXPECTED_VERSION_MARKER: &str = "current version";

/// What a `httpx -version` preflight found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpxHealth {
    /// The first non-empty version line, when the binary answered.
    pub version_line: Option<String>,
    /// Whether the binary is (very likely) ProjectDiscovery's httpx.
    pub compatible: bool,
}

/// Run `binary -version` (bounded) and report whether it looks like the Go
/// tool. Never blocks: a missing binary is simply `compatible: false`.
pub fn health(binary: &str, timeout: Duration) -> HttpxHealth {
    let child = Command::new(binary)
        .arg("-version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let Ok(mut child) = child else {
        return HttpxHealth {
            version_line: None,
            compatible: false,
        };
    };
    let out = child
        .stdout
        .take()
        .map(|mut s| {
            let mut buf = String::new();
            let _ = std::io::Read::read_to_string(&mut s, &mut buf);
            buf
        })
        .unwrap_or_default();
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => break,
        }
    }
    let _ = child.wait();
    let first = out
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string);
    let compatible = first
        .as_deref()
        .is_some_and(|l| l.to_ascii_lowercase().contains(EXPECTED_VERSION_MARKER));
    HttpxHealth {
        version_line: first,
        compatible,
    }
}

/// Verify the `httpx` on PATH is the Go tool this adapter drives, failing with
/// an actionable [`IntegrationError::Incompatible`] when it is not.
pub fn ensure_compatible(timeout: Duration) -> Result<(), IntegrationError> {
    let found = health("httpx", timeout);
    if found.compatible {
        return Ok(());
    }
    Err(match found.version_line {
        Some(line) => IntegrationError::Incompatible {
            tool: "httpx".into(),
            detail: format!(
                "the `httpx` on PATH reports \"{line}\", which is not ProjectDiscovery's \
                 httpx (expected a version line containing \"{EXPECTED_VERSION_MARKER}\"); \
                 install the Go tool from https://github.com/projectdiscovery/httpx and put it \
                 first on PATH, or import an existing JSONL export"
            ),
        },
        None => IntegrationError::NotInstalled("httpx".into()),
    })
}

const DEFAULT_FLAGS: &[&str] = &[
    "-silent",
    "-jsonl",
    "-no-color",
    "-disable-update-check",
    "-sc",
    "-title",
    "-cl",
    "-server",
    "-td",
    "-ip",
    "-cname",
    "-cdn",
    "-rt",
    "-tls",
];

/// Run httpx and return its raw JSONL stdout. Bounded per plan §4.2: killed at
/// `opts.timeout`, stdout capped at [`MAX_OUTPUT_BYTES`], cancellation via
/// `should_cancel`. Callers that persist raw evidence (plan §4.1: "Preserve raw
/// external artifacts separately") store this text and parse it locally.
pub fn run_httpx_raw<C: Fn() -> bool>(
    targets: &[String],
    opts: &HttpxOptions,
    should_cancel: C,
) -> Result<String, IntegrationError> {
    // Refuse a differently-named tool masquerading as httpx before any
    // probe traffic goes anywhere (plan §5.1 actionable diagnostics).
    ensure_compatible(Duration::from_secs(5))?;

    let mut cmd = Command::new("httpx");
    cmd.args(DEFAULT_FLAGS.iter().copied());
    if let Some(rl) = opts.rate_limit {
        cmd.args(["-rl", &rl.to_string()]);
    }
    if let Some(c) = opts.concurrency {
        cmd.args(["-c", &c.to_string()]);
    }
    if let Some(t) = opts.timeout_secs {
        cmd.args(["-timeout", &t.to_string()]);
    }
    if opts.follow_redirects {
        cmd.arg("-follow-redirects");
    }
    for a in &opts.extra_args {
        cmd.arg(a);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            IntegrationError::NotInstalled("httpx".into())
        } else {
            IntegrationError::Run(e.to_string())
        }
    })?;

    // Keep a bounded stderr snippet so a zero-record run can say *why*
    // instead of silently looking like "no probes answered".
    let stderr_pipe = child.stderr.take();
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(mut pipe) = stderr_pipe {
            let mut chunk = [0u8; 4096];
            use std::io::Read as _;
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if buf.len() < MAX_DIAGNOSTIC_BYTES {
                            let take = n.min(MAX_DIAGNOSTIC_BYTES - buf.len());
                            buf.push_str(&String::from_utf8_lossy(&chunk[..take]));
                        }
                    }
                }
            }
        }
        buf
    });

    // Bound the run before it starts: the target list is capped, so a
    // misconfigured `--from-sitemap` cannot probe an entire inventory at once.
    let bounded: &[String] = match opts.max_targets {
        Some(max) if targets.len() > max => &targets[..max],
        _ => targets,
    };
    // Feed targets on stdin, then close it so httpx starts.
    if let Some(mut stdin) = child.stdin.take() {
        for t in bounded {
            let _ = writeln!(stdin, "{t}");
        }
    }

    // Capture stdout on a thread (bounded); probe results stream in order.
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
                if start.elapsed() > opts.timeout || should_cancel() {
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
    // Response-size bound (client-side, exact for any installed version).
    let output = match opts.max_response_bytes {
        Some(max) => cap_response_sizes(&output, max),
        None => output,
    };
    let diagnostics = stderr_reader.join().unwrap_or_default();
    if output.trim().is_empty() && !diagnostics.trim().is_empty() {
        return Err(IntegrationError::Run(format!(
            "httpx produced no probe records: {}",
            diagnostics.trim().lines().next().unwrap_or_default()
        )));
    }
    Ok(output)
}

/// Run httpx against `targets` (fed on stdin, one per line) and return parsed
/// probe results.
pub fn run_httpx(
    targets: &[String],
    opts: &HttpxOptions,
) -> Result<Vec<ProbeResult>, IntegrationError> {
    run_httpx_cancellable(targets, opts, || false)
}

/// Like [`run_httpx`] but kills the process when `should_cancel()` returns
/// `true`, so a background task's cancellation actually stops the probe.
pub fn run_httpx_cancellable<C: Fn() -> bool>(
    targets: &[String],
    opts: &HttpxOptions,
    should_cancel: C,
) -> Result<Vec<ProbeResult>, IntegrationError> {
    Ok(parse_httpx_jsonl(&run_httpx_raw(
        targets,
        opts,
        should_cancel,
    )?))
}

/// Drop probe results whose `content_length` exceeds `max` bytes. Runs on the
/// JSONL text so the bound is exact regardless of the installed httpx build's
/// own size flags (which vary across versions).
fn cap_response_sizes(jsonl: &str, max: usize) -> String {
    jsonl
        .lines()
        .filter(|line| {
            let len = serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|v| {
                    v.get("content-length")
                        .or_else(|| v.get("content_length"))
                        .and_then(serde_json::Value::as_u64)
                });
            match len {
                Some(n) => n <= max as u64,
                None => true, // not a JSON record (or no length): keep it
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One-line human summary of a probe result (for the CLI table).
pub fn summarize(p: &ProbeResult) -> String {
    if p.failed {
        let err = p.errors.join("; ");
        return if err.is_empty() {
            "unreachable".to_string()
        } else {
            format!("unreachable ({err})")
        };
    }
    let mut parts = Vec::new();
    if let Some(status) = p.status {
        parts.push(status.to_string());
    }
    if let Some(t) = &p.title {
        if !t.trim().is_empty() {
            parts.push(t.clone());
        }
    }
    if let Some(ct) = &p.content_type {
        parts.push(ct.clone());
    }
    if let Some(srv) = &p.web_server {
        parts.push(srv.clone());
    }
    if !p.technologies.is_empty() {
        parts.push(p.technologies.join(", "));
    }
    if parts.is_empty() {
        "reachable".to_string()
    } else {
        parts.join(" · ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
{"input":"https://example.com","url":"https://example.com/","scheme":"https","host":"example.com","port":443,"path":"/","status_code":200,"title":"Example Domain","content-type":"text/html","content_length":1256,"webserver":"ECS (dcb/7F5B)","technologies":["Amazon Web Services","Amazon ECS"],"a":["93.184.216.34"],"cname":[],"cdn":false,"duration":"137.406261ms","tls":{"subject_cn":"www.example.com","subject_an":["www.example.com","example.com"]},"failed":false}
{"input":"https://down.test","url":"https://down.test/","scheme":"https","host":"down.test","failed":true,"error":["cannot connect to down.test: dial tcp: lookup down.test: no such host"]}
{"input":"https://old.test","url":"https://old.test/","status-code":301,"webserver":"nginx","duration":"1.2s"}
not json at all
"#;

    #[test]
    fn parses_jsonl_tolerantly() {
        let results = parse_httpx_jsonl(SAMPLE);
        assert_eq!(results.len(), 3, "the non-JSON line must be skipped");
        let first = &results[0];
        assert_eq!(first.input, "https://example.com");
        assert_eq!(first.host, "example.com");
        assert_eq!(first.status, Some(200));
        assert_eq!(first.title.as_deref(), Some("Example Domain"));
        assert_eq!(first.content_type.as_deref(), Some("text/html"));
        assert_eq!(first.content_length, Some(1256));
        assert_eq!(first.web_server.as_deref(), Some("ECS (dcb/7F5B)"));
        assert_eq!(first.technologies.len(), 2);
        assert_eq!(first.ips, vec!["93.184.216.34".to_string()]);
        assert_eq!(first.tls_cn.as_deref(), Some("www.example.com"));
        assert_eq!(first.tls_sans.len(), 2);
        assert_eq!(first.duration_ms, Some(137));
        assert!(!first.failed);
    }

    #[test]
    fn failed_probes_stay_visible() {
        let results = parse_httpx_jsonl(SAMPLE);
        let down = &results[1];
        assert!(down.failed);
        assert_eq!(down.status, None);
        assert!(down.errors[0].contains("no such host"));
        assert!(summarize(down).starts_with("unreachable"));
    }

    #[test]
    fn hyphen_spellings_parse() {
        let results = parse_httpx_jsonl(SAMPLE);
        let old = &results[2];
        assert_eq!(old.status, Some(301));
        assert_eq!(old.web_server.as_deref(), Some("nginx"));
        // A Go-style "1.2s" is 1200ms.
        assert_eq!(old.duration_ms, Some(1200));
    }

    #[test]
    fn summarize_reads_like_a_probe_table() {
        let results = parse_httpx_jsonl(SAMPLE);
        assert_eq!(
            summarize(&results[0]),
            "200 · Example Domain · text/html · ECS (dcb/7F5B) · Amazon Web Services, Amazon ECS"
        );
        assert_eq!(summarize(&results[2]), "301 · nginx");
    }

    #[test]
    fn empty_output_is_no_results() {
        assert!(parse_httpx_jsonl("").is_empty());
        assert!(parse_httpx_jsonl("\n  \n").is_empty());
    }

    #[test]
    fn default_flags_never_follow_redirects_or_update() {
        // Guard the plan §6 posture: the defaults must not silently widen the
        // approved plan or reach out on their own.
        assert!(!DEFAULT_FLAGS.contains(&"-follow-redirects"));
        assert!(DEFAULT_FLAGS.contains(&"-disable-update-check"));
        let d = HttpxOptions::default();
        assert!(!d.follow_redirects);
    }
}

#[cfg(test)]
mod cap_tests {
    use super::*;

    #[test]
    fn oversized_responses_are_dropped_from_the_output() {
        let jsonl = concat!(
            "{\"input\":\"a\",\"url\":\"https://a.test/\",\"host\":\"a.test\",\"content-length\":100}\n",
            "{\"input\":\"b\",\"url\":\"https://b.test/\",\"host\":\"b.test\",\"content-length\":9000}\n",
            "not-json-but-kept\n",
        );
        let capped = cap_response_sizes(jsonl, 1000);
        assert!(capped.contains("a.test"));
        assert!(!capped.contains("b.test"));
        assert!(
            capped.contains("not-json-but-kept"),
            "non-JSON lines are kept"
        );
    }

    #[test]
    fn a_response_with_no_length_is_kept() {
        let jsonl = "{\"input\":\"a\",\"url\":\"https://a.test/\",\"failed\":true}";
        assert!(cap_response_sizes(jsonl, 1).contains("a.test"));
    }

    #[test]
    fn the_default_options_impose_no_cap() {
        let opts = HttpxOptions::default();
        assert!(opts.max_targets.is_none());
        assert!(opts.max_response_bytes.is_none());
    }
}
