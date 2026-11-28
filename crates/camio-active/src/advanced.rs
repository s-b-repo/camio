//! Advanced opt-in active checks (plan §8 active-check matrix, expanded set):
//! server-side template injection, path traversal / LFI, CRLF response
//! splitting, CORS misconfiguration, and Host-header injection.
//!
//! Each follows the same contract as [`crate::checks`]: enumerate injectable
//! inputs (or, for the header-level checks, craft one header probe), send through
//! the scope-gated [`Sender`], and confirm by comparing the response against a
//! distinctive marker rather than guessing. Detection markers are chosen so a
//! *reflected literal* (the payload echoed back unchanged) never matches — only a
//! server that actually evaluated/decoded the payload does.

use crate::params::{dedup_params, discovered_params, with_param};
use crate::{finding, ActiveCheck, Sender};
use camio_core::{Confidence, Finding, HttpRequest, Severity};
use regex::Regex;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Server-Side Template Injection (SSTI)
// ---------------------------------------------------------------------------

/// `91 * 131 = 11921`, bracketed by markers so a template engine that evaluates
/// the expression yields `cx11921xc`, while a server that merely reflects the
/// payload returns the literal `cx{{91*131}}xc` (which never contains `11921`).
const SSTI_RESULT: &str = "cx11921xc";

/// Probe expressions across the common template syntaxes (Jinja2/Twig `{{}}`,
/// FreeMarker/JSP-EL `${}`, Ruby/Thymeleaf `#{}`). One send per syntax per input.
const SSTI_PROBES: &[&str] = &["cx{{91*131}}xc", "cx${91*131}xc", "cx#{91*131}xc"];

/// Injects arithmetic template expressions and reports any input whose response
/// contains the *computed* result — a server-side template injection sink.
pub struct Ssti;

impl ActiveCheck for Ssti {
    fn id(&self) -> &'static str {
        "ssti"
    }
    fn title(&self) -> &'static str {
        "Server-side template injection"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn run(&self, base: &HttpRequest, send: &Sender) -> Vec<Finding> {
        let mut out = Vec::new();
        for (kind, name) in dedup_params(discovered_params(base)) {
            for probe_value in SSTI_PROBES {
                let probe = with_param(base, kind, &name, probe_value);
                let Some(ex) = send(probe) else { continue };
                let Some(resp) = &ex.response else { continue };
                if resp.body.as_text().contains(SSTI_RESULT) {
                    out.push(finding(
                        format!("Server-side template injection (`{name}`)"),
                        Severity::High,
                        Confidence::Firm,
                        format!(
                            "Parameter `{name}` evaluated the template expression `{probe_value}`: \
                             the response contains the computed result `{SSTI_RESULT}` (91×131=11921), \
                             which only appears if the value was rendered by a server-side template \
                             engine. SSTI frequently escalates to remote code execution — confirm the \
                             engine and sandbox, and never pass user input into a template."
                        ),
                        ex.id,
                    ));
                    break; // one finding per input is enough
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Path traversal / local file inclusion
// ---------------------------------------------------------------------------

/// Traversal probes. Values are sent *raw* (the sender percent-encodes once, the
/// target decodes once); the `....//` variant defeats naive single-pass `../`
/// stripping. Both POSIX and Windows targets are probed.
const TRAVERSAL_PROBES: &[&str] = &[
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "../../../../../../../../windows/win.ini",
];

/// `/etc/passwd` and `win.ini` signatures. A reflected traversal *path* never
/// matches these — only the file's actual contents do.
fn traversal_signature() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // `root:x:0:0:` style passwd line, or a win.ini section header.
        Regex::new(r"(?i)root:[^:\r\n]*:0:0:|\[(extensions|fonts|mci extensions)\]|; for 16-bit app support")
            .expect("static traversal regex is valid")
    })
}

/// Injects directory-traversal sequences and reports an input whose response
/// returns the contents of a well-known system file.
pub struct PathTraversal;

impl ActiveCheck for PathTraversal {
    fn id(&self) -> &'static str {
        "path-traversal"
    }
    fn title(&self) -> &'static str {
        "Path traversal / local file inclusion"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn run(&self, base: &HttpRequest, send: &Sender) -> Vec<Finding> {
        let mut out = Vec::new();
        for (kind, name) in dedup_params(discovered_params(base)) {
            for probe_value in TRAVERSAL_PROBES {
                let probe = with_param(base, kind, &name, probe_value);
                let Some(ex) = send(probe) else { continue };
                let Some(resp) = &ex.response else { continue };
                if traversal_signature().is_match(&resp.body.as_text()) {
                    out.push(finding(
                        format!("Path traversal / LFI (`{name}`)"),
                        Severity::High,
                        Confidence::Firm,
                        format!(
                            "Parameter `{name}` returned the contents of a system file for the \
                             traversal payload `{probe_value}` (matched an `/etc/passwd` or `win.ini` \
                             signature). The application resolves a user-controlled path without \
                             containment — an attacker can read arbitrary files. Canonicalize and \
                             confine paths to an allow-listed base directory."
                        ),
                        ex.id,
                    ));
                    break;
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// CRLF injection / HTTP response splitting
// ---------------------------------------------------------------------------

/// Raw CR-LF followed by a distinctive header the server would only emit if it
/// reflected the (decoded) value into the response head unsanitized.
const CRLF_PROBE: &str = "camio\r\nX-Camio-Crlf: injected";
const CRLF_HEADER: &str = "X-Camio-Crlf";

/// Injects a CR-LF + header sequence and reports any input that splits into the
/// response headers — HTTP response splitting / CRLF injection.
pub struct CrlfInjection;

impl ActiveCheck for CrlfInjection {
    fn id(&self) -> &'static str {
        "crlf-injection"
    }
    fn title(&self) -> &'static str {
        "CRLF injection / HTTP response splitting"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn run(&self, base: &HttpRequest, send: &Sender) -> Vec<Finding> {
        let mut out = Vec::new();
        for (kind, name) in dedup_params(discovered_params(base)) {
            let probe = with_param(base, kind, &name, CRLF_PROBE);
            let Some(ex) = send(probe) else { continue };
            let Some(resp) = &ex.response else { continue };
            if resp.headers.get(CRLF_HEADER).is_some() {
                out.push(finding(
                    format!("CRLF injection / response splitting (`{name}`)"),
                    Severity::High,
                    Confidence::Firm,
                    format!(
                        "Parameter `{name}` injected a CR-LF sequence that the server reflected into \
                         the response head: the crafted `{CRLF_HEADER}` header appears in the \
                         response. This permits header injection, response splitting, and cache \
                         poisoning. Strip CR/LF from any value placed into a response header."
                    ),
                    ex.id,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// CORS misconfiguration
// ---------------------------------------------------------------------------

/// A hostile origin the target should never trust. If it comes back in
/// `Access-Control-Allow-Origin`, the server reflects arbitrary origins.
const CORS_EVIL_ORIGIN: &str = "https://camio-evil.example";

/// Sends a cross-origin probe and reports an `Access-Control-Allow-Origin` that
/// trusts an attacker-controlled (or `null`) origin — worst with credentials.
pub struct CorsMisconfig;

impl ActiveCheck for CorsMisconfig {
    fn id(&self) -> &'static str {
        "cors-misconfig"
    }
    fn title(&self) -> &'static str {
        "CORS misconfiguration"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn run(&self, base: &HttpRequest, send: &Sender) -> Vec<Finding> {
        let mut probe = base.clone();
        probe.headers.push("Origin", CORS_EVIL_ORIGIN);
        let Some(ex) = send(probe) else { return Vec::new() };
        let Some(resp) = &ex.response else { return Vec::new() };
        let acao = resp.headers.get("Access-Control-Allow-Origin");
        let credentials = resp
            .headers
            .get("Access-Control-Allow-Credentials")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let (matched, severity, confidence, detail): (bool, Severity, Confidence, String) =
            match acao {
                Some(o) if o == CORS_EVIL_ORIGIN => (
                    true,
                    if credentials { Severity::High } else { Severity::Medium },
                    Confidence::Firm,
                    format!(
                        "The server reflected the attacker-controlled `Origin` back in \
                         `Access-Control-Allow-Origin: {CORS_EVIL_ORIGIN}`{}. Any site can read \
                         cross-origin responses{}. Echo only an allow-listed set of origins.",
                        if credentials { " with `Access-Control-Allow-Credentials: true`" } else { "" },
                        if credentials { ", including authenticated ones — full account takeover of the CORS surface" } else { "" },
                    ),
                ),
                Some(o) if o.eq_ignore_ascii_case("null") => (
                    true,
                    Severity::Medium,
                    Confidence::Firm,
                    "`Access-Control-Allow-Origin: null` is trusted — reachable from a sandboxed \
                     iframe or a `data:`/`file:` document, so an attacker page can read responses. \
                     Never allow the `null` origin."
                        .to_string(),
                ),
                Some(o) if o == "*" && credentials => (
                    true,
                    Severity::Medium,
                    Confidence::Firm,
                    "`Access-Control-Allow-Origin: *` is sent together with \
                     `Access-Control-Allow-Credentials: true` (an invalid-but-dangerous combo some \
                     stacks mishandle). Pin a concrete allow-listed origin instead of `*`."
                        .to_string(),
                ),
                _ => (false, Severity::Medium, Confidence::Firm, String::new()),
            };
        if matched {
            vec![finding(
                "CORS misconfiguration",
                severity,
                confidence,
                detail,
                ex.id,
            )]
        } else {
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Host-header injection
// ---------------------------------------------------------------------------

/// A poisoned host an attacker would use to hijack password-reset links, cache
/// keys, or SSRF. Injected via `X-Forwarded-Host` (the common reflected vector;
/// the real `Host` is pinned to the URL by the engine).
const HOST_EVIL: &str = "camio-evil.example";

/// Sends a poisoned `X-Forwarded-Host`/`X-Host` and reports the value reflected
/// into a redirect `Location` or the response body (absolute links).
pub struct HostHeaderInjection;

impl ActiveCheck for HostHeaderInjection {
    fn id(&self) -> &'static str {
        "host-header-injection"
    }
    fn title(&self) -> &'static str {
        "Host-header injection"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn run(&self, base: &HttpRequest, send: &Sender) -> Vec<Finding> {
        let mut probe = base.clone();
        probe.headers.push("X-Forwarded-Host", HOST_EVIL);
        probe.headers.push("X-Host", HOST_EVIL);
        let Some(ex) = send(probe) else { return Vec::new() };
        let Some(resp) = &ex.response else { return Vec::new() };
        let in_location = resp
            .headers
            .get("Location")
            .map(|l| l.contains(HOST_EVIL))
            .unwrap_or(false);
        // Only a reflection in an absolute URL context is interesting; a bare
        // substring in arbitrary body text would be noisy, so require a scheme.
        let body = resp.body.as_text();
        let in_body = body.contains(&format!("//{HOST_EVIL}"));
        if in_location || in_body {
            let where_ = if in_location { "redirect `Location` header" } else { "response body (absolute URL)" };
            vec![finding(
                "Host-header injection",
                Severity::Medium,
                Confidence::Firm,
                format!(
                    "The poisoned `X-Forwarded-Host: {HOST_EVIL}` was reflected into the {where_}. \
                     The application derives absolute URLs from a client-controlled host header, \
                     enabling password-reset-link hijacking, cache poisoning, and routing abuse. \
                     Derive URLs from a trusted, server-configured host, not request headers."
                ),
                ex.id,
            )]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, ExchangeId, HeaderList, HttpExchange, HttpResponse, HttpVersion, Source};

    /// Build a stored exchange with a chosen body and response headers.
    fn exchange(req: HttpRequest, id: i64, headers: &[(&str, &str)], body: &str) -> HttpExchange {
        let mut hl = HeaderList::new();
        for (n, v) in headers {
            hl.push(*n, *v);
        }
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: hl,
            body: Body::from_text(body),
        };
        let mut ex = HttpExchange::new(req, Source::Scanner).with_response(resp);
        ex.id = ExchangeId(id);
        ex
    }

    fn get_with_param() -> HttpRequest {
        HttpRequest::get("https://app.test/page?q=hello")
    }

    #[test]
    fn ssti_fires_when_the_expression_is_evaluated() {
        // The evaluated result appears → finding.
        let hit = |req: HttpRequest| Some(exchange(req, 1, &[], "result is cx11921xc here"));
        let f = Ssti.run(&get_with_param(), &hit);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].title.contains("template injection"));
    }

    #[test]
    fn ssti_does_not_fire_on_a_reflected_literal() {
        // The payload is echoed verbatim (not evaluated) → no finding.
        let echo = |req: HttpRequest| Some(exchange(req, 1, &[], "you sent cx{{91*131}}xc"));
        assert!(Ssti.run(&get_with_param(), &echo).is_empty());
    }

    #[test]
    fn path_traversal_fires_on_a_passwd_signature() {
        let hit = |req: HttpRequest| {
            Some(exchange(req, 1, &[], "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"))
        };
        let f = PathTraversal.run(&get_with_param(), &hit);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("passwd") || f[0].title.contains("traversal"));
    }

    #[test]
    fn path_traversal_fires_on_win_ini() {
        let hit = |req: HttpRequest| Some(exchange(req, 1, &[], "[extensions]\r\nmp3=foo"));
        assert_eq!(PathTraversal.run(&get_with_param(), &hit).len(), 1);
    }

    #[test]
    fn path_traversal_quiet_on_normal_body() {
        let ok = |req: HttpRequest| Some(exchange(req, 1, &[], "<html>welcome</html>"));
        assert!(PathTraversal.run(&get_with_param(), &ok).is_empty());
    }

    #[test]
    fn crlf_fires_when_the_injected_header_appears() {
        let hit = |req: HttpRequest| Some(exchange(req, 1, &[("X-Camio-Crlf", "injected")], "ok"));
        let f = CrlfInjection.run(&get_with_param(), &hit);
        assert_eq!(f.len(), 1);
        assert!(f[0].title.contains("CRLF"));
    }

    #[test]
    fn crlf_quiet_without_the_header() {
        let ok = |req: HttpRequest| Some(exchange(req, 1, &[], "ok"));
        assert!(CrlfInjection.run(&get_with_param(), &ok).is_empty());
    }

    #[test]
    fn cors_flags_reflected_origin_with_credentials_as_high() {
        let hit = |req: HttpRequest| {
            Some(exchange(
                req,
                1,
                &[
                    ("Access-Control-Allow-Origin", CORS_EVIL_ORIGIN),
                    ("Access-Control-Allow-Credentials", "true"),
                ],
                "ok",
            ))
        };
        let f = CorsMisconfig.run(&get_with_param(), &hit);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn cors_flags_null_origin_as_medium() {
        let hit = |req: HttpRequest| {
            Some(exchange(req, 1, &[("Access-Control-Allow-Origin", "null")], "ok"))
        };
        let f = CorsMisconfig.run(&get_with_param(), &hit);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn cors_quiet_on_a_same_origin_policy() {
        let hit = |req: HttpRequest| {
            Some(exchange(req, 1, &[("Access-Control-Allow-Origin", "https://app.test")], "ok"))
        };
        assert!(CorsMisconfig.run(&get_with_param(), &hit).is_empty());
    }

    #[test]
    fn host_header_injection_fires_on_reflected_location() {
        let hit = |req: HttpRequest| {
            Some(exchange(req, 1, &[("Location", "https://camio-evil.example/reset")], "ok"))
        };
        let f = HostHeaderInjection.run(&get_with_param(), &hit);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn host_header_injection_quiet_when_not_reflected() {
        let ok = |req: HttpRequest| Some(exchange(req, 1, &[("Location", "https://app.test/next")], "ok"));
        assert!(HostHeaderInjection.run(&get_with_param(), &ok).is_empty());
    }
}
