//! Task-oriented AI assist capabilities for authorized security testing (plan
//! §11: "summarizing project data and proposing actions").
//!
//! Three capabilities, each split into a **pure** prompt-builder (fully
//! unit-testable, no I/O, no model call) and a thin convenience runner that
//! feeds the pair to [`AiClient::complete`] and parses the reply:
//!
//! * [`attack_plan_prompt`] / [`run_attack_plan`] — from an attack-surface /
//!   findings summary, propose prioritized, concrete next-step test vectors.
//! * [`payload_mutations_prompt`] / [`run_payload_mutations`] — from a base
//!   payload (and optional context hint), propose evasion/mutation variants for
//!   authorized WAF-bypass testing; [`parse_mutation_list`] turns the reply into
//!   individual payloads.
//! * [`triage_prompt`] / [`run_triage`] — prioritize findings by real-world
//!   impact and suggest validation steps.
//!
//! ## Untrusted input
//!
//! Attack-surface text, payloads, context hints, and finding text can all carry
//! bytes the *target* controls (reflected bodies, header values, payload strings
//! copied from a scan). Every such input is routed through [`redact_untrusted`]
//! before it is embedded in a prompt, so a hostile string cannot inject control
//! characters or grow the model context without bound.
//!
//! ## Framing (safety requirement)
//!
//! Every `system` prompt here states explicitly that the work is **authorized,
//! scoped penetration testing / defensive security**, and asks for what to probe
//! next and why — never instructions for unauthorized or illegal activity. This
//! framing is mandatory and is asserted by the unit tests.

use crate::client::AiClient;
use crate::error::AiError;

/// Upper bound (bytes) on each untrusted input embedded in an assist prompt.
///
/// Mirrors the raw-dump bound used by [`crate::prompt`]: large enough for a
/// realistic attack-surface or findings summary, small enough that a single
/// hostile field cannot blow up the model context.
const UNTRUSTED_MAX: usize = 8000;

/// Sanitize an untrusted string before it is embedded in a prompt.
///
/// Truncates `s` to at most `max` **bytes** (on a UTF-8 char boundary, so the
/// result is always valid UTF-8) and strips ASCII control characters except
/// newline (`\n`) and tab (`\t`). When any content is dropped for length a short
/// `…[truncated]` marker is appended.
///
/// Used to bound and defang every target-controlled value (response bodies,
/// payloads, finding text) that reaches a model prompt, so a crafted string
/// cannot smuggle terminal/control bytes into the context or make it unbounded.
pub fn redact_untrusted(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut truncated = false;
    for ch in s.chars() {
        // Strip ASCII control characters, keeping only newline and tab so
        // multi-line inputs stay readable to the model.
        if ch.is_ascii_control() && ch != '\n' && ch != '\t' {
            continue;
        }
        if out.len() + ch.len_utf8() > max {
            truncated = true;
            break;
        }
        out.push(ch);
    }
    if truncated {
        out.push_str("…[truncated]");
    }
    out
}

// --- 1. attack_plan --------------------------------------------------------

/// Build the `(system, user)` prompt pair for the **attack-plan** task.
///
/// `surface_summary` is a caller-produced attack-surface / findings summary
/// (tech stack, WAF behavior, open findings). It is routed through
/// [`redact_untrusted`] before being embedded. The `system` prompt frames the
/// work as authorized, scoped penetration testing / defensive security and asks
/// for prioritized, concrete *next-step test vectors* — what to probe next and
/// why — not instructions for unauthorized activity.
///
/// Pure and deterministic: no I/O, no model call.
pub fn attack_plan_prompt(surface_summary: &str) -> (String, String) {
    let system = "You are a penetration-testing assistant supporting an AUTHORIZED, scoped \
security assessment conducted with the target owner's written permission. This is defensive, \
in-scope security work. Given a summary of the attack surface and current findings, respond with \
a prioritized list of concrete NEXT-STEP test vectors: for each, name the component, endpoint, or \
parameter to probe next, the technique to use, why it is worth testing (the hypothesis), and what \
a positive result would look like. Prefer high-signal, low-noise tests, order them by expected \
impact and likelihood, and keep everything within the authorized scope. Do NOT provide \
instructions for unauthorized access, illegal activity, or testing systems outside the engagement."
        .to_string();

    let user = format!(
        "Attack-surface and findings summary (authorized engagement):\n\n{}\n\n\
Propose the prioritized next-step test vectors to run.",
        redact_untrusted(surface_summary, UNTRUSTED_MAX)
    );

    (system, user)
}

/// Run the **attack-plan** task against `client` and return the model's plan
/// text.
///
/// Builds the prompt with [`attack_plan_prompt`], sends it via
/// [`AiClient::complete`], and returns the reply unchanged.
pub fn run_attack_plan(client: &AiClient, surface_summary: &str) -> Result<String, AiError> {
    let (system, user) = attack_plan_prompt(surface_summary);
    client.complete(&system, &user)
}

// --- 2. payload_mutations --------------------------------------------------

/// Build the `(system, user)` prompt pair for the **payload-mutations** task.
///
/// `base_payload` is the seed payload to mutate; `context_hint` is an optional
/// hint about where/how it lands (e.g. `"reflected in an HTML attribute, WAF
/// blocks <script>"`). Both are routed through [`redact_untrusted`]. The reply
/// is expected to be one payload variant per line; parse it with
/// [`parse_mutation_list`]. The `system` prompt frames the work as authorized
/// WAF-bypass / filter-evasion testing.
///
/// Pure and deterministic: no I/O, no model call.
pub fn payload_mutations_prompt(
    base_payload: &str,
    context_hint: Option<&str>,
) -> (String, String) {
    let system = "You are a payload-engineering assistant supporting AUTHORIZED, scoped WAF and \
input-filter bypass testing during a permitted security assessment. This is defensive, in-scope \
security work against a system the tester is authorized to test. Given a base payload and an \
optional context hint, produce a list of evasion/mutation VARIANTS of that payload that exercise \
different filter-bypass techniques (encoding, case and whitespace tricks, alternate tags or \
syntax, comment insertion, and similar). Output ONE payload variant per line, with no commentary, \
no numbering, and no code fences. Only generate variants of the provided payload for the \
authorized engagement; do not target systems outside the agreed scope."
        .to_string();

    let mut user = format!(
        "Base payload (authorized WAF-bypass testing):\n{}\n",
        redact_untrusted(base_payload, UNTRUSTED_MAX)
    );
    if let Some(hint) = context_hint {
        user.push_str(&format!(
            "\nContext hint:\n{}\n",
            redact_untrusted(hint, UNTRUSTED_MAX)
        ));
    }
    user.push_str("\nList the evasion/mutation variants, one payload per line.");

    (system, user)
}

/// Run the **payload-mutations** task against `client` and return the parsed
/// list of variant payloads.
///
/// Builds the prompt with [`payload_mutations_prompt`], sends it via
/// [`AiClient::complete`], and parses the reply with [`parse_mutation_list`].
pub fn run_payload_mutations(
    client: &AiClient,
    base_payload: &str,
    context_hint: Option<&str>,
) -> Result<Vec<String>, AiError> {
    let (system, user) = payload_mutations_prompt(base_payload, context_hint);
    let reply = client.complete(&system, &user)?;
    Ok(parse_mutation_list(&reply))
}

/// Parse a model reply into individual payload strings.
///
/// Robust to the common shapes a model returns a list in:
///
/// * numbered lists — `1. x`, `1) x`, `1.x`;
/// * bulleted lists — `- x`, `* x`, `+ x`;
/// * plain newline-separated lines.
///
/// Markdown code-fence lines (```` ``` ````, ```` ```lang ````, `~~~`) are
/// dropped, surrounding inline back-ticks are stripped, each entry is trimmed,
/// and blank entries are discarded. The result preserves input order.
pub fn parse_mutation_list(reply: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw_line in reply.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Drop markdown code-fence lines entirely (``` / ```lang / ~~~).
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            continue;
        }
        let unmarked = strip_list_marker(trimmed);
        let candidate = strip_inline_backticks(unmarked.trim()).trim();
        if candidate.is_empty() {
            continue;
        }
        out.push(candidate.to_string());
    }
    out
}

/// Strip a leading list marker (`- `, `* `, `+ `, or `<digits>.`/`<digits>)`)
/// from a single trimmed line, returning the remainder.
fn strip_list_marker(line: &str) -> &str {
    // Bulleted markers require a trailing space so a payload that legitimately
    // begins with `-`/`*`/`+` is not mangled.
    for marker in ["- ", "* ", "+ "] {
        if let Some(rest) = line.strip_prefix(marker) {
            return rest.trim_start();
        }
    }
    // Numbered markers: leading ASCII digits followed by `.` or `)`, with or
    // without a trailing space.
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    if digits > 0 {
        let after = &line[digits..];
        for sep in [". ", ") ", ".", ")"] {
            if let Some(rest) = after.strip_prefix(sep) {
                return rest.trim_start();
            }
        }
    }
    line
}

/// Strip a single matched pair of surrounding inline back-ticks, if present.
fn strip_inline_backticks(line: &str) -> &str {
    if line.len() >= 2 && line.starts_with('`') && line.ends_with('`') {
        return &line[1..line.len() - 1];
    }
    line
}

// --- 3. triage -------------------------------------------------------------

/// Build the `(system, user)` prompt pair for the **triage** task.
///
/// `findings_summary` is a caller-produced summary of open findings; it is
/// routed through [`redact_untrusted`] before being embedded. The `system`
/// prompt frames the work as authorized, defensive security triage and asks the
/// model to prioritize findings by real-world impact and suggest validation
/// steps.
///
/// Pure and deterministic: no I/O, no model call.
pub fn triage_prompt(findings_summary: &str) -> (String, String) {
    let system = "You are a security triage assistant supporting an AUTHORIZED, scoped \
security assessment. This is defensive, in-scope security work. Given a summary of findings, \
prioritize them by real-world impact: assess exploitability and blast radius, order them from \
most to least severe, and for each finding suggest concrete validation steps the tester can run \
to confirm whether it is a true positive and gauge its severity. Flag likely false positives and \
note any missing evidence needed to confirm. Keep all recommendations within the authorized scope \
and do not suggest unauthorized or illegal activity."
        .to_string();

    let user = format!(
        "Findings summary (authorized engagement):\n\n{}\n\n\
Prioritize these findings by real-world impact and suggest validation steps.",
        redact_untrusted(findings_summary, UNTRUSTED_MAX)
    );

    (system, user)
}

/// Run the **triage** task against `client` and return the model's triage text.
///
/// Builds the prompt with [`triage_prompt`], sends it via
/// [`AiClient::complete`], and returns the reply unchanged.
pub fn run_triage(client: &AiClient, findings_summary: &str) -> Result<String, AiError> {
    let (system, user) = triage_prompt(findings_summary);
    client.complete(&system, &user)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- redact_untrusted ---

    #[test]
    fn redact_keeps_plain_text_verbatim() {
        assert_eq!(redact_untrusted("hello world", 100), "hello world");
    }

    #[test]
    fn redact_keeps_newline_and_tab_but_strips_other_controls() {
        // \x07 (bell) and \x1b (escape) are stripped; \n and \t survive.
        let input = "a\x07b\nc\td\x1be";
        assert_eq!(redact_untrusted(input, 100), "ab\nc\tde");
    }

    #[test]
    fn redact_strips_nul_and_carriage_return() {
        assert_eq!(redact_untrusted("a\0b\rc", 100), "abc");
    }

    #[test]
    fn redact_truncates_to_max_bytes_with_marker() {
        let out = redact_untrusted("abcdefgh", 3);
        assert!(out.starts_with("abc"), "got: {out}");
        assert!(out.contains("[truncated]"));
        assert!(!out.contains("def"));
    }

    #[test]
    fn redact_truncation_is_utf8_safe() {
        // Each `é` is two bytes; a 3-byte cap must stop after one `é`, never
        // mid-codepoint, and the result must stay valid UTF-8.
        let out = redact_untrusted("éééé", 3);
        assert!(out.starts_with("é"));
        assert!(out.contains("[truncated]"));
        assert!(out.is_char_boundary(out.len()));
    }

    // --- attack_plan_prompt ---

    #[test]
    fn attack_plan_prompt_is_authorized_and_carries_input() {
        let (system, user) =
            attack_plan_prompt("nginx + PHP, Cloudflare WAF, open redirect on /go");
        let lower = system.to_lowercase();
        assert!(lower.contains("authorized"), "system: {system}");
        assert!(
            lower.contains("scope") || lower.contains("scoped"),
            "system: {system}"
        );
        // Asks for next-step vectors, not illegal activity.
        assert!(lower.contains("next-step") || lower.contains("next step"));
        assert!(lower.contains("unauthorized"));
        assert!(user.contains("nginx + PHP, Cloudflare WAF, open redirect on /go"));
    }

    #[test]
    fn attack_plan_prompt_redacts_control_chars_in_input() {
        let (_system, user) = attack_plan_prompt("host:\x1b[31mevil\x1b[0m\nfield");
        // The ESC control bytes are gone; the readable text (and newline) remain.
        assert!(!user.contains('\x1b'));
        assert!(user.contains("host:[31mevil[0m\nfield"));
    }

    // --- payload_mutations_prompt ---

    #[test]
    fn payload_mutations_prompt_is_authorized_and_carries_payload() {
        let (system, user) =
            payload_mutations_prompt("<script>alert(1)</script>", None);
        let lower = system.to_lowercase();
        assert!(lower.contains("authorized"), "system: {system}");
        assert!(lower.contains("waf") || lower.contains("bypass"), "system: {system}");
        assert!(user.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn payload_mutations_prompt_includes_context_hint_when_present() {
        let (_system, user) = payload_mutations_prompt(
            "' OR 1=1 --",
            Some("reflected in HTML attribute, WAF blocks <script>"),
        );
        assert!(user.contains("' OR 1=1 --"));
        assert!(user.contains("reflected in HTML attribute, WAF blocks <script>"));
        assert!(user.contains("Context hint"));
    }

    #[test]
    fn payload_mutations_prompt_omits_hint_section_when_none() {
        let (_system, user) = payload_mutations_prompt("x", None);
        assert!(!user.contains("Context hint"));
    }

    // --- parse_mutation_list ---

    #[test]
    fn parse_numbered_list() {
        let reply = "1. <SCRIPT>alert(1)</SCRIPT>\n2) <img src=x onerror=alert(1)>\n3.<svg/onload=alert(1)>";
        assert_eq!(
            parse_mutation_list(reply),
            vec![
                "<SCRIPT>alert(1)</SCRIPT>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
            ]
        );
    }

    #[test]
    fn parse_bulleted_list() {
        let reply = "- payload-a\n* payload-b\n+ payload-c";
        assert_eq!(
            parse_mutation_list(reply),
            vec!["payload-a", "payload-b", "payload-c"]
        );
    }

    #[test]
    fn parse_plain_newline_separated() {
        let reply = "first\nsecond\nthird";
        assert_eq!(parse_mutation_list(reply), vec!["first", "second", "third"]);
    }

    #[test]
    fn parse_drops_blank_lines_and_trims() {
        let reply = "\n  alpha  \n\n\tbeta\n   \n";
        assert_eq!(parse_mutation_list(reply), vec!["alpha", "beta"]);
    }

    #[test]
    fn parse_drops_code_fences_and_inline_backticks() {
        let reply = "```\n`<img src=x>`\n```\n```python\n- second\n~~~";
        // Fence lines (``` , ```python, ~~~) are dropped; the inline-back-ticked
        // first entry is unwrapped, and the bulleted entry is unmarked.
        assert_eq!(
            parse_mutation_list(reply),
            vec!["<img src=x>", "second"]
        );
    }

    #[test]
    fn parse_empty_reply_is_empty() {
        assert!(parse_mutation_list("").is_empty());
        assert!(parse_mutation_list("   \n\t\n```\n```").is_empty());
    }

    #[test]
    fn parse_preserves_payloads_that_start_like_markers() {
        // A bullet needs a trailing space, so a payload literally beginning with
        // `-`/`*` (no space) is kept intact.
        let reply = "-moz-binding\n*/alert(1)/*";
        assert_eq!(
            parse_mutation_list(reply),
            vec!["-moz-binding", "*/alert(1)/*"]
        );
    }

    // --- triage_prompt ---

    #[test]
    fn triage_prompt_is_authorized_and_carries_input() {
        let (system, user) =
            triage_prompt("Open: reflected XSS on /search; SSRF on /fetch; verbose errors");
        let lower = system.to_lowercase();
        assert!(lower.contains("authorized"), "system: {system}");
        assert!(lower.contains("impact"), "system: {system}");
        assert!(lower.contains("validation") || lower.contains("validate"));
        assert!(user.contains("Open: reflected XSS on /search; SSRF on /fetch; verbose errors"));
    }

    #[test]
    fn triage_prompt_redacts_control_chars_in_input() {
        let (_system, user) = triage_prompt("finding\x00one\nfinding\x1ftwo");
        assert!(!user.contains('\x00'));
        assert!(!user.contains('\x1f'));
        assert!(user.contains("findingone\nfindingtwo"));
    }
}
