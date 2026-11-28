//! Attack-vector chains — composing individual findings into multi-step attack
//! narratives (plan §8 "Automate"; plan §4 "findings → exploitation story").
//!
//! A single finding says "this input is injectable" or "this header is weak".
//! An operator (or a report) wants the *so-what*: how a handful of findings
//! compose into a realistic, end-to-end attack. [`suggest_attack_chains`] reads
//! the set of **rule ids** present in a finding list and emits an
//! [`AttackChain`] for each recognised composition — a named narrative with
//! ordered steps, a rationale, and an escalated severity.
//!
//! The function is **pure** over the finding set: no network, no I/O, no state.
//! It inspects only which stable check ids (`Finding::rule`) are present, so the
//! same inputs always yield the same chains. Every id it gates on is a real id
//! emitted by an active check (`camio-active`) or a passive check
//! (`camio-scan`) — nothing is invented.

use std::collections::BTreeSet;

use camio_core::{Finding, Severity};

/// A multi-step attack narrative composed from one or more findings.
///
/// `severity` is the [`Severity::as_str`] string (not the enum) so the chain
/// serializes cleanly for the CLI/web/report surfaces that consume it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttackChain {
    /// Short, human-readable name of the attack (e.g. "Template injection → RCE").
    pub name: String,
    /// Ordered steps an operator would walk to realise the chain.
    pub steps: Vec<String>,
    /// Why these findings compose into this attack.
    pub rationale: String,
    /// The chain's severity, as a [`Severity::as_str`] token
    /// (`info`/`low`/`medium`/`high`/`critical`).
    pub severity: String,
}

/// Does `present` contain `id`?
fn has(present: &BTreeSet<&str>, id: &str) -> bool {
    present.contains(id)
}

/// Maximum [`Severity`] among the findings whose `rule` is one of `rules`.
///
/// Callers gate on presence first, so at least one finding always matches in
/// practice; the `Info` fallback only guards the degenerate empty case.
fn max_severity(findings: &[Finding], rules: &[&str]) -> Severity {
    findings
        .iter()
        .filter(|f| f.rule.as_deref().map(|r| rules.contains(&r)).unwrap_or(false))
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info)
}

/// Inspect the rule ids present in `findings` and emit an [`AttackChain`] for
/// every recognised composition. Pure over the finding set; chains are returned
/// in a stable, defined order.
pub fn suggest_attack_chains(findings: &[Finding]) -> Vec<AttackChain> {
    let present: BTreeSet<&str> = findings.iter().filter_map(|f| f.rule.as_deref()).collect();
    let mut chains = Vec::new();

    // 1. SSTI → RCE. A confirmed template injection is, in practice, a path to
    //    remote code execution, so the chain severity is escalated to Critical
    //    regardless of how the individual finding was rated.
    if has(&present, "ssti") {
        chains.push(AttackChain {
            name: "Template injection → RCE".to_string(),
            steps: vec![
                "Confirm the template engine and its evaluation context".to_string(),
                "Break out of the template sandbox into the host language".to_string(),
                "Achieve remote code execution on the application server".to_string(),
            ],
            rationale: "Server-side template injection evaluates attacker input as \
                 template code; most engines expose a route from expression \
                 evaluation to arbitrary code execution."
                .to_string(),
            severity: Severity::Critical.as_str().to_string(),
        });
    }

    // 2. Path traversal → file read → disclosure → secondary exploitation.
    if has(&present, "path-traversal") {
        chains.push(AttackChain {
            name: "Arbitrary file read → secret/source disclosure → secondary exploitation"
                .to_string(),
            steps: vec![
                "Read arbitrary files outside the web root via the traversal".to_string(),
                "Disclose configuration, credentials, keys, or application source".to_string(),
                "Reuse the disclosed secrets/source to reach a deeper compromise".to_string(),
            ],
            rationale: "Reading files outside the intended directory leaks secrets and \
                 source code, which in turn enable authentication bypass, SSRF, or \
                 code execution against adjacent services."
                .to_string(),
            severity: max_severity(findings, &["path-traversal"]).as_str().to_string(),
        });
    }

    // 3. Open redirect + a security-header / CSP weakness → token/credential theft.
    if has(&present, "open-redirect")
        && (has(&present, "weak-csp") || has(&present, "missing-security-headers"))
    {
        let mut triggers = vec!["open-redirect"];
        if has(&present, "weak-csp") {
            triggers.push("weak-csp");
        }
        if has(&present, "missing-security-headers") {
            triggers.push("missing-security-headers");
        }
        chains.push(AttackChain {
            name: "Open redirect → OAuth/token or credential theft".to_string(),
            steps: vec![
                "Craft a link that redirects through the trusted origin to an attacker host"
                    .to_string(),
                "Capture OAuth codes/tokens or credentials leaked in the redirect flow"
                    .to_string(),
                "Replay the stolen token/credential to take over the account".to_string(),
            ],
            rationale: "An open redirect on a trusted origin, unconstrained by CSP or the \
                 missing security headers, lets an attacker siphon OAuth codes, bearer \
                 tokens, or credentials during the redirect."
                .to_string(),
            severity: max_severity(findings, &triggers).as_str().to_string(),
        });
    }

    // 4. Reflected XSS + a cross-origin / CSP weakness → data exfiltration.
    if has(&present, "reflected-xss")
        && (has(&present, "cors-misconfig") || has(&present, "weak-csp"))
    {
        let mut triggers = vec!["reflected-xss"];
        if has(&present, "cors-misconfig") {
            triggers.push("cors-misconfig");
        }
        if has(&present, "weak-csp") {
            triggers.push("weak-csp");
        }
        chains.push(AttackChain {
            name: "Reflected XSS → cross-origin data exfiltration / session theft".to_string(),
            steps: vec![
                "Deliver the reflected-XSS payload to a victim session".to_string(),
                "Use the CORS/CSP weakness to read cross-origin responses from script"
                    .to_string(),
                "Exfiltrate session tokens or sensitive data to an attacker endpoint".to_string(),
            ],
            rationale: "Script execution combined with a permissive CORS policy or weak CSP \
                 lets the injected code read cross-origin data and steal the victim's \
                 session."
                .to_string(),
            severity: max_severity(findings, &triggers).as_str().to_string(),
        });
    }

    // 5. CORS misconfiguration alone → cross-origin data theft.
    if has(&present, "cors-misconfig") {
        chains.push(AttackChain {
            name: "Cross-origin data theft (worse with credentials)".to_string(),
            steps: vec![
                "Host an attacker page that issues cross-origin requests to the target"
                    .to_string(),
                "Read the responses that the misconfigured CORS policy exposes".to_string(),
                "Escalate to full account data theft when credentials are reflected".to_string(),
            ],
            rationale: "A permissive Access-Control-Allow-Origin (especially with \
                 credentials) lets any attacker origin read authenticated responses on \
                 behalf of a logged-in victim."
                .to_string(),
            severity: max_severity(findings, &["cors-misconfig"]).as_str().to_string(),
        });
    }

    // 6. CRLF injection → cache poisoning → stored XSS.
    if has(&present, "crlf-injection") {
        chains.push(AttackChain {
            name: "Header injection → cache poisoning → stored XSS".to_string(),
            steps: vec![
                "Inject CRLF sequences to split the response and forge headers/body"
                    .to_string(),
                "Poison a shared cache with the attacker-controlled response".to_string(),
                "Serve stored XSS to every user hitting the poisoned cache entry".to_string(),
            ],
            rationale: "CRLF injection lets an attacker forge response headers and body; a \
                 poisoned cache then distributes the malicious (XSS) response to other \
                 users."
                .to_string(),
            severity: max_severity(findings, &["crlf-injection"]).as_str().to_string(),
        });
    }

    // 7. Host-header injection + open redirect → password-reset-link hijack.
    if has(&present, "host-header-injection") && has(&present, "open-redirect") {
        chains.push(AttackChain {
            name: "Host poisoning → password-reset-link hijack".to_string(),
            steps: vec![
                "Poison the Host header so generated links point at an attacker domain"
                    .to_string(),
                "Trigger a password-reset (or similar) email containing the poisoned link"
                    .to_string(),
                "Capture the reset token when the victim follows the redirected link"
                    .to_string(),
            ],
            rationale: "When the application builds absolute links from the Host header and \
                 an open redirect masks the destination, a password-reset token can be \
                 steered to an attacker-controlled host."
                .to_string(),
            severity: max_severity(findings, &["host-header-injection", "open-redirect"])
                .as_str()
                .to_string(),
        });
    }

    // 8. Error-based SQLi → auth bypass / data exfiltration.
    if has(&present, "error-based-sqli") {
        chains.push(AttackChain {
            name: "SQL injection → auth bypass / data exfiltration".to_string(),
            steps: vec![
                "Confirm the injection via error-based feedback and map the query".to_string(),
                "Bypass authentication or enumerate the schema through the injection"
                    .to_string(),
                "Exfiltrate credentials and sensitive records from the database".to_string(),
            ],
            rationale: "An error-based SQL injection gives direct control over the query, \
                 enabling authentication bypass and bulk extraction of database contents."
                .to_string(),
            severity: max_severity(findings, &["error-based-sqli"]).as_str().to_string(),
        });
    }

    chains
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Confidence, FindingId};

    /// Build a minimal [`Finding`] carrying just a rule id and a severity — the
    /// only fields [`suggest_attack_chains`] reads.
    fn finding(rule: &str, severity: Severity) -> Finding {
        Finding {
            id: FindingId(0),
            title: rule.to_string(),
            severity,
            confidence: Confidence::Firm,
            detail: String::new(),
            evidence: vec![],
            created_at_ms: 0,
            rule: Some(rule.to_string()),
        }
    }

    #[test]
    fn empty_findings_yield_no_chains() {
        assert!(suggest_attack_chains(&[]).is_empty());
    }

    #[test]
    fn open_redirect_plus_header_weakness_emits_redirect_chain() {
        let findings = [
            finding("open-redirect", Severity::Medium),
            finding("missing-security-headers", Severity::Low),
        ];
        let chains = suggest_attack_chains(&findings);
        let redirect = chains
            .iter()
            .find(|c| c.name.contains("Open redirect"))
            .expect("expected the open-redirect chain");
        // Severity is the max of the two triggers: Medium > Low.
        assert_eq!(redirect.severity, "medium");
        assert_eq!(redirect.steps.len(), 3);
    }

    #[test]
    fn ssti_emits_rce_chain_escalated_to_critical() {
        // Even though the finding itself is only High, the chain escalates.
        let chains = suggest_attack_chains(&[finding("ssti", Severity::High)]);
        assert_eq!(chains.len(), 1);
        assert!(chains[0].name.contains("RCE"));
        assert_eq!(chains[0].severity, "critical");
    }

    #[test]
    fn reflected_xss_alone_does_not_emit_exfil_chain() {
        // reflected-xss needs a CORS/CSP partner to compose into the exfil chain.
        let chains = suggest_attack_chains(&[finding("reflected-xss", Severity::Medium)]);
        assert!(chains.is_empty(), "got {chains:?}");
    }

    #[test]
    fn reflected_xss_plus_weak_csp_emits_exfil_chain() {
        let findings = [
            finding("reflected-xss", Severity::High),
            finding("weak-csp", Severity::Medium),
        ];
        let chains = suggest_attack_chains(&findings);
        let exfil = chains
            .iter()
            .find(|c| c.name.contains("cross-origin data exfiltration"))
            .expect("expected the XSS exfiltration chain");
        assert_eq!(exfil.severity, "high");
    }

    #[test]
    fn path_traversal_emits_file_read_chain() {
        let chains = suggest_attack_chains(&[finding("path-traversal", Severity::High)]);
        assert_eq!(chains.len(), 1);
        assert!(chains[0].name.contains("Arbitrary file read"));
        assert_eq!(chains[0].severity, "high");
    }

    #[test]
    fn host_header_plus_open_redirect_emits_reset_hijack() {
        let findings = [
            finding("host-header-injection", Severity::Medium),
            finding("open-redirect", Severity::Low),
        ];
        let chains = suggest_attack_chains(&findings);
        // The host-poisoning chain is present (and not the header-weakness
        // redirect chain, which needs weak-csp/missing-security-headers).
        assert!(chains.iter().any(|c| c.name.contains("Host poisoning")));
        assert!(!chains.iter().any(|c| c.name.contains("Open redirect →")));
    }

    #[test]
    fn error_based_sqli_emits_sqli_chain() {
        let chains = suggest_attack_chains(&[finding("error-based-sqli", Severity::Critical)]);
        assert_eq!(chains.len(), 1);
        assert!(chains[0].name.contains("SQL injection"));
        assert_eq!(chains[0].severity, "critical");
    }

    #[test]
    fn cors_misconfig_emits_data_theft_chain() {
        let chains = suggest_attack_chains(&[finding("cors-misconfig", Severity::High)]);
        assert_eq!(chains.len(), 1);
        assert!(chains[0].name.contains("Cross-origin data theft"));
    }

    #[test]
    fn crlf_injection_emits_cache_poisoning_chain() {
        let chains = suggest_attack_chains(&[finding("crlf-injection", Severity::Medium)]);
        assert_eq!(chains.len(), 1);
        assert!(chains[0].name.contains("cache poisoning"));
        assert_eq!(chains[0].severity, "medium");
    }

    #[test]
    fn unknown_rule_ids_are_ignored() {
        // A rule id we don't recognise contributes to no chain.
        let chains = suggest_attack_chains(&[finding("not-a-real-rule", Severity::High)]);
        assert!(chains.is_empty());
    }

    #[test]
    fn attack_chain_serializes_to_json() {
        let chains = suggest_attack_chains(&[finding("ssti", Severity::High)]);
        let json = serde_json::to_string(&chains[0]).unwrap();
        assert!(json.contains("\"severity\":\"critical\""));
        let back: AttackChain = serde_json::from_str(&json).unwrap();
        assert_eq!(back, chains[0]);
    }
}
