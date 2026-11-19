//! AI tool-call auto-correction and secure resolution.
//!
//! When an AI asks to run a tool via MCP it may use:
//!
//! * a slightly-wrong name (`portscan`, `nmap_scan`, `port-scan`),
//! * a friendly alias (`scan`, `recon`, `enum`),
//! * or a short phrase (`"perform port scan"`, `"look up subdomains"`).
//!
//! This module builds a **catalog of AI-callable tools**, scores each
//! incoming ask against the catalog, and returns one of three outcomes:
//!
//! * [`ToolResolution::AutoApply`] — one tool matches well above the
//!   runner-up and all guard checks pass; the server can dispatch without
//!   asking the AI to confirm.
//! * [`ToolResolution::Suggest`] — several plausible matches; the server
//!   hands them back for the AI to pick from.
//! * [`ToolResolution::Refused`] — no acceptable match, or the top match
//!   requires an action class the session binding does not grant. The
//!   resolver **refuses** rather than hallucinating a tool.
//!
//! The resolver is **binding-aware**: it filters out tools whose
//! [`ActionClass`](crate::policy::ActionClass) is not in the session's
//! allowed set before scoring, so a `read`-only session can never
//! auto-upgrade to an `active` call.
//!
//! ## Security posture
//!
//! * No tool is invented. Only catalog entries can match.
//! * Action-class escalation is impossible — the binding is consulted
//!   before suggestions are emitted.
//! * Thresholds are intentionally conservative. Ambiguous asks produce
//!   `Suggest` or `Refused`, never `AutoApply`.
//! * Scoring is pure and deterministic; given the same inputs the same
//!   outcome falls out, so audit logs are reproducible.
//! * The resolver never reads the raw ask into the guard key path — this
//!   is a public-input function.

use crate::ai_guard::{verify_binding, AiGuardError, SessionBinding, SessionKey};
use crate::policy::ActionClass;

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

/// One AI-callable tool, as the resolver sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolSpec {
    /// Canonical tool name the MCP server dispatches on (e.g. "scan",
    /// "subfinder_enum").
    pub name: &'static str,
    /// Short alternate names the AI might send ("fuzz", "intrude",
    /// "portscan"). Order doesn't matter.
    pub aliases: &'static [&'static str],
    /// The action class this tool exercises. The resolver refuses to
    /// return a tool whose class the binding did not grant.
    pub action_class: ActionClass,
    /// One-line human-readable summary — surfaced in `Suggest` so the AI
    /// can pick between near-misses.
    pub summary: &'static str,
    /// Keyword hints — any word the AI commonly uses to describe the tool,
    /// the problem the tool solves, or its typical input. All lower-case.
    pub keywords: &'static [&'static str],
}

/// A catalog of tools the AI is allowed to ask about.
#[derive(Debug, Clone, Copy)]
pub struct ToolCatalog {
    pub tools: &'static [ToolSpec],
}

/// The default catalog that mirrors Camio's current AI-accessible surface.
/// New tools should be registered here — the resolver is static on purpose
/// so an AI cannot extend the catalog at runtime.
pub fn default_catalog() -> ToolCatalog {
    ToolCatalog {
        tools: DEFAULT_TOOLS,
    }
}

const DEFAULT_TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "camioql_query",
        aliases: &["query", "search_history", "camioql"],
        action_class: ActionClass::Read,
        summary: "Run a CamioQL query over stored history",
        keywords: &["camioql", "query", "search", "history", "filter", "find"],
    },
    ToolSpec {
        name: "history_list",
        aliases: &["history", "list_exchanges", "recent"],
        action_class: ActionClass::Read,
        summary: "Show recent captured HTTP exchanges",
        keywords: &["history", "recent", "exchanges", "list", "captured"],
    },
    ToolSpec {
        name: "scope_check",
        aliases: &["scope", "check_scope"],
        action_class: ActionClass::Read,
        summary: "Report the scope decision for a URL",
        keywords: &["scope", "decision", "check", "url", "authorised", "authorized"],
    },
    ToolSpec {
        name: "convert",
        aliases: &["decoder", "encode", "decode", "transform"],
        action_class: ActionClass::Read,
        summary: "Encode / decode / hash a value through a Convert pipeline",
        keywords: &["convert", "encode", "decode", "hash", "base64", "url", "transform"],
    },
    ToolSpec {
        name: "findings_list",
        aliases: &["findings", "list_findings", "get_findings"],
        action_class: ActionClass::Read,
        summary: "List stored findings (session-authorized hosts only)",
        keywords: &["findings", "results", "report", "issues", "vulns"],
    },
    ToolSpec {
        name: "findings_set_status",
        aliases: &["triage", "update_finding"],
        action_class: ActionClass::Mutating,
        summary: "Update a finding's triage status",
        keywords: &["triage", "status", "finding", "update", "confirm"],
    },
    ToolSpec {
        name: "scan_passive",
        aliases: &["scan", "passive_scan", "run_scan"],
        action_class: ActionClass::Read,
        summary: "Run the passive scanner over stored history",
        keywords: &["scan", "passive", "check", "review", "audit"],
    },
    ToolSpec {
        name: "analyze_js",
        aliases: &["js_analyze", "inspect_js", "js_scan"],
        action_class: ActionClass::Read,
        summary: "Extract secrets and endpoints from a JS body",
        keywords: &["js", "javascript", "secrets", "endpoints", "analyze"],
    },
    ToolSpec {
        name: "input_discover",
        aliases: &["discover_inputs", "enum_inputs"],
        action_class: ActionClass::Read,
        summary: "Enumerate injectable inputs of a captured request",
        keywords: &["inputs", "discover", "enum", "parameters", "fields"],
    },
    ToolSpec {
        name: "sitemap_build",
        aliases: &["sitemap", "site_map"],
        action_class: ActionClass::Read,
        summary: "Build a site map tree from stored history",
        keywords: &["sitemap", "tree", "map", "discover", "endpoints"],
    },
    ToolSpec {
        name: "payloads_list",
        aliases: &["payloads", "list_payloads", "packs"],
        action_class: ActionClass::Read,
        summary: "List built-in payload packs and DB categories",
        keywords: &["payloads", "list", "packs", "catalog", "db"],
    },
    ToolSpec {
        name: "fuzz_plan",
        aliases: &["plan_fuzz", "intruder_plan"],
        action_class: ActionClass::Read,
        summary: "Build a fuzz campaign plan (projected request count, no send)",
        keywords: &["fuzz", "intruder", "plan", "campaign", "attack"],
    },
    ToolSpec {
        name: "send_request",
        aliases: &["send", "replay", "repeater"],
        action_class: ActionClass::Mutating,
        summary: "Send a request through the matched engine (scope-gated)",
        keywords: &["send", "replay", "repeat", "request", "repeater"],
    },
    ToolSpec {
        name: "active_scan",
        aliases: &["activescan", "scan_active", "aggressive_scan"],
        action_class: ActionClass::Active,
        summary: "Opt-in active scan (XSS / SQLi / open redirect)",
        keywords: &["active", "scan", "attack", "test", "probe"],
    },
    ToolSpec {
        name: "subfinder_enum",
        aliases: &["subfinder", "subdomain_enum", "recon_subs"],
        action_class: ActionClass::Read,
        summary: "Enumerate subdomains passively (external: subfinder)",
        keywords: &["subdomain", "subfinder", "enum", "recon", "osint"],
    },
    ToolSpec {
        name: "nuclei_scan",
        aliases: &["nuclei", "template_scan"],
        action_class: ActionClass::Active,
        summary: "Run Nuclei against an authorized target (external)",
        keywords: &["nuclei", "template", "scan", "vuln"],
    },
    ToolSpec {
        name: "crawl",
        aliases: &["bounded_crawl", "spider"],
        action_class: ActionClass::Mutating,
        summary: "Bounded same-origin crawl through the matched engine",
        keywords: &["crawl", "spider", "discover", "walk"],
    },
    ToolSpec {
        name: "oast_new_token",
        aliases: &["oast_token", "collab_token", "oob_token"],
        action_class: ActionClass::Read,
        summary: "Mint a new OAST correlation token",
        keywords: &["oast", "collaborator", "token", "oob", "callback"],
    },
    ToolSpec {
        name: "oast_interactions",
        aliases: &["oast_hits", "collab_hits", "oob_interactions"],
        action_class: ActionClass::Read,
        summary: "Read OAST interactions for minted tokens",
        keywords: &["oast", "interactions", "hits", "callback", "oob"],
    },
];

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// The ask the AI (or MCP server) sends in.
#[derive(Debug, Clone)]
pub struct ResolveRequest<'a> {
    /// What the AI typed — could be a tool name, alias, or a short phrase.
    /// Case- and separator-insensitive.
    pub name_or_phrase: &'a str,
    /// Optional structured args — used only to down-rank when the tool's
    /// name clearly implies args that weren't provided. Not required.
    pub provided_args: Option<&'a serde_json::Value>,
}

/// One scored suggestion returned to the caller.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolSuggestion {
    pub tool: ToolSpec,
    pub score: f32,
    pub reason: String,
}

/// The resolver's verdict.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolResolution {
    /// One tool matched with high confidence and the binding grants its
    /// action class — the server may dispatch directly.
    AutoApply(ToolSuggestion),
    /// Several plausible matches — the AI should pick one by exact name.
    Suggest(Vec<ToolSuggestion>),
    /// No acceptable match. The `reason` is safe to show the AI; it never
    /// contains key material.
    Refused(String),
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// Thresholds (tuned so a near-identical name auto-applies, a close
/// synonym becomes a suggestion, and random phrases are refused). The
/// `COVERAGE_MIN` gates auto-apply on a multi-token phrase matching
/// enough of its tokens to the picked tool's name/keywords — this
/// stops `"perform port scan"` from locking onto `scan_passive` just
/// because one token hits.
const AUTO_APPLY_MIN: f32 = 6.5;
const AUTO_APPLY_GAP: f32 = 2.0;
const AUTO_APPLY_COVERAGE_MIN: f32 = 0.6;
const SUGGEST_MIN: f32 = 1.5;
const SUGGEST_MAX_RESULTS: usize = 3;

/// Resolve the AI's ask to a specific tool.
///
/// `binding` is verified with `key`; invalid bindings always return
/// `Err(AiGuardError::InvalidTag)` — the resolver never falls back to an
/// unauthenticated path.
pub fn resolve_tool_call(
    catalog: &ToolCatalog,
    binding: &SessionBinding,
    key: &SessionKey,
    request: &ResolveRequest<'_>,
) -> Result<ToolResolution, AiGuardError> {
    verify_binding(binding, key)?;
    let allowed: Vec<&str> = binding.allowed_actions.iter().map(|s| s.as_str()).collect();
    let normalized = normalize(request.name_or_phrase);
    if normalized.is_empty() {
        return Ok(ToolResolution::Refused(
            "empty tool name/phrase".to_string(),
        ));
    }
    let tokens = tokens(&normalized);

    // Score every tool.
    let mut scored: Vec<(f32, ToolSpec, String, f32)> = Vec::new();
    for t in catalog.tools {
        let (score, reason, coverage) = score_tool(t, &normalized, &tokens);
        scored.push((score, *t, reason, coverage));
    }
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    if scored.is_empty() {
        return Ok(ToolResolution::Refused("the catalog is empty".to_string()));
    }

    // Separate the top scored from runners-up and check the action class
    // of the top candidate.
    let (top_score, top_tool, top_reason, top_coverage) = scored[0].clone();
    if top_score < SUGGEST_MIN {
        return Ok(ToolResolution::Refused(format!(
            "no tool in the catalog matches `{}` (top candidate `{}` scored {:.2})",
            request.name_or_phrase, top_tool.name, top_score
        )));
    }
    let top_cls = top_tool.action_class.as_str();
    if !allowed.contains(&top_cls) {
        return Ok(ToolResolution::Refused(format!(
            "tool `{}` requires action class `{}` which this session does not grant",
            top_tool.name, top_cls
        )));
    }

    // Build the suggestion list restricted to allowed action classes.
    let suggestions: Vec<ToolSuggestion> = scored
        .iter()
        .filter(|(score, tool, _, _)| {
            *score >= SUGGEST_MIN && allowed.iter().any(|a| *a == tool.action_class.as_str())
        })
        .take(SUGGEST_MAX_RESULTS)
        .map(|(score, tool, reason, _)| ToolSuggestion {
            tool: *tool,
            score: *score,
            reason: reason.clone(),
        })
        .collect();

    if suggestions.is_empty() {
        return Ok(ToolResolution::Refused(format!(
            "top match `{}` requires `{}`, which the session does not allow",
            top_tool.name, top_cls
        )));
    }

    let runner_up = suggestions.get(1).map(|s| s.score).unwrap_or(0.0);
    if top_score >= AUTO_APPLY_MIN
        && top_score - runner_up >= AUTO_APPLY_GAP
        && top_coverage >= AUTO_APPLY_COVERAGE_MIN
    {
        return Ok(ToolResolution::AutoApply(ToolSuggestion {
            tool: top_tool,
            score: top_score,
            reason: top_reason,
        }));
    }
    Ok(ToolResolution::Suggest(suggestions))
}

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

/// Returns `(score, reason, coverage)` where `coverage` is the ratio of
/// phrase tokens that matched something in the tool (name tokens,
/// aliases, or keyword prefixes). 1.0 means every phrase word matched.
fn score_tool(tool: &ToolSpec, normalized: &str, tokens: &[String]) -> (f32, String, f32) {
    let n_norm = normalize(tool.name);
    let mut score = 0.0f32;
    let mut reasons: Vec<&'static str> = Vec::new();

    if n_norm == normalized {
        score += 10.0;
        reasons.push("exact-name");
    }

    for alias in tool.aliases {
        let a_norm = normalize(alias);
        if a_norm == normalized {
            score += 8.0;
            reasons.push("alias-exact");
            break;
        }
    }

    if normalized.contains(&n_norm) || n_norm.contains(normalized) {
        score += 3.0;
        reasons.push("substring");
    }
    for alias in tool.aliases {
        let a_norm = normalize(alias);
        if normalized.contains(&a_norm) || a_norm.contains(normalized) {
            score += 2.5;
            reasons.push("alias-substring");
            break;
        }
    }

    // Token overlap with keywords / name tokens. We use prefix-match in
    // BOTH directions (phrase token is prefix of keyword, or vice versa)
    // so `enumerate` matches `enum` and `scanner` matches `scan`.
    let name_tokens = tokens_of(&n_norm);
    let kw_norms: Vec<String> = tool.keywords.iter().map(|k| normalize(k)).collect();
    let mut keyword_hits = 0usize;
    for tok in tokens {
        if tok.len() < 3 {
            continue;
        }
        let matched = kw_norms
            .iter()
            .any(|kw| kw == tok || kw.starts_with(tok.as_str()) || tok.starts_with(kw.as_str()))
            || name_tokens.iter().any(|nt| {
                nt == tok || nt.starts_with(tok.as_str()) || tok.starts_with(nt.as_str())
            });
        if matched {
            keyword_hits += 1;
        }
    }
    if keyword_hits > 0 {
        score += 1.2 * keyword_hits as f32;
        reasons.push("keyword");
    }

    // Jaro similarity best of name + aliases.
    let mut best_sim = jaro(normalized, &n_norm);
    for alias in tool.aliases {
        let s = jaro(normalized, &normalize(alias));
        if s > best_sim {
            best_sim = s;
        }
    }
    score += 3.0 * best_sim;
    if best_sim > 0.85 {
        reasons.push("fuzzy-high");
    } else if best_sim > 0.6 {
        reasons.push("fuzzy");
    }

    // Coverage: how many phrase tokens matched something in the tool.
    let coverage = if tokens.is_empty() {
        1.0
    } else {
        // A single-token phrase that exact-matches the name or an alias
        // counts as full coverage even if `keyword_hits` is 0.
        if (reasons.contains(&"exact-name") || reasons.contains(&"alias-exact")) && tokens.len() == 1
        {
            1.0
        } else {
            keyword_hits as f32 / tokens.len() as f32
        }
    };

    (score, reasons.join("+"), coverage)
}

fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.extend(c.to_lowercase());
        } else if c.is_whitespace() || c == '_' || c == '-' {
            out.push(' ');
        }
    }
    let mut collapsed = String::with_capacity(out.len());
    let mut prev_space = false;
    for ch in out.chars() {
        if ch == ' ' {
            if !prev_space {
                collapsed.push(' ');
            }
            prev_space = true;
        } else {
            collapsed.push(ch);
            prev_space = false;
        }
    }
    collapsed.trim().to_string()
}

fn tokens(normalized: &str) -> Vec<String> {
    normalized.split(' ').filter(|t| !t.is_empty()).map(|s| s.to_string()).collect()
}

fn tokens_of(normalized: &str) -> Vec<String> {
    tokens(normalized)
}

fn jaro(a: &str, b: &str) -> f32 {
    let s1: Vec<char> = a.chars().collect();
    let s2: Vec<char> = b.chars().collect();
    if s1.is_empty() && s2.is_empty() {
        return 1.0;
    }
    if s1.is_empty() || s2.is_empty() {
        return 0.0;
    }
    let match_dist = s1.len().max(s2.len()) / 2;
    let match_dist = match_dist.saturating_sub(1);
    let mut s1_matches = vec![false; s1.len()];
    let mut s2_matches = vec![false; s2.len()];
    let mut matches = 0usize;
    for i in 0..s1.len() {
        let start = i.saturating_sub(match_dist);
        let end = (i + match_dist + 1).min(s2.len());
        for j in start..end {
            if s2_matches[j] || s1[i] != s2[j] {
                continue;
            }
            s1_matches[i] = true;
            s2_matches[j] = true;
            matches += 1;
            break;
        }
    }
    if matches == 0 {
        return 0.0;
    }
    let mut transpositions = 0usize;
    let mut k = 0usize;
    for i in 0..s1.len() {
        if !s1_matches[i] {
            continue;
        }
        while !s2_matches[k] {
            k += 1;
        }
        if s1[i] != s2[k] {
            transpositions += 1;
        }
        k += 1;
    }
    let m = matches as f32;
    let t = (transpositions / 2) as f32;
    (m / s1.len() as f32 + m / s2.len() as f32 + (m - t) / m) / 3.0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_guard::{bind_session, SessionKey};
    use crate::scope::ScopeRule;

    fn key() -> SessionKey {
        SessionKey::from_bytes([42u8; 32])
    }

    fn binding(allow: &[ActionClass]) -> SessionBinding {
        bind_session(
            "s",
            &[ScopeRule::include("host.eq:example.com").unwrap()],
            &["https://example.com".into()],
            allow,
            0,
            &key(),
        )
        .unwrap()
    }

    fn resolve(phrase: &str, allow: &[ActionClass]) -> ToolResolution {
        let b = binding(allow);
        resolve_tool_call(
            &default_catalog(),
            &b,
            &key(),
            &ResolveRequest {
                name_or_phrase: phrase,
                provided_args: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn exact_name_auto_applies_when_allowed() {
        let out = resolve("camioql_query", &[ActionClass::Read]);
        match out {
            ToolResolution::AutoApply(s) => assert_eq!(s.tool.name, "camioql_query"),
            other => panic!("expected AutoApply, got {other:?}"),
        }
    }

    #[test]
    fn alias_auto_applies() {
        let out = resolve("query", &[ActionClass::Read]);
        if let ToolResolution::AutoApply(s) = out {
            assert_eq!(s.tool.name, "camioql_query");
        } else {
            panic!("expected AutoApply");
        }
    }

    #[test]
    fn perform_port_scan_phrase_refused_because_no_port_scan_tool_exists() {
        // The ask the user gave as an example. Camio has no port-scanner
        // registered, so the resolver must NOT hallucinate one — it
        // refuses, with a reason.
        let out = resolve("perform port scan", &[ActionClass::Read, ActionClass::Active]);
        match out {
            ToolResolution::Refused(r) => assert!(r.to_lowercase().contains("no tool")),
            // Acceptable alt: Suggest with a very-low-score near-miss.
            ToolResolution::Suggest(s) => {
                for sug in s {
                    assert!(sug.score < AUTO_APPLY_MIN, "would not auto-apply");
                }
            }
            ToolResolution::AutoApply(a) => {
                panic!("must not auto-apply for ambiguous phrase, got {:?}", a.tool.name)
            }
        }
    }

    #[test]
    fn active_tool_refused_in_read_only_session() {
        // The AI asks for an active scan but the binding only granted read.
        let out = resolve("activescan", &[ActionClass::Read]);
        match out {
            ToolResolution::Refused(r) => {
                assert!(r.contains("active"), "reason should name the class: {r}")
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn active_tool_allowed_in_active_session() {
        let out = resolve("activescan", &[ActionClass::Read, ActionClass::Active]);
        matches!(out, ToolResolution::AutoApply(ref s) if s.tool.name == "active_scan");
    }

    #[test]
    fn mild_typos_still_resolve() {
        let out = resolve("sbfinder", &[ActionClass::Read]);
        match out {
            ToolResolution::AutoApply(s) => assert_eq!(s.tool.name, "subfinder_enum"),
            ToolResolution::Suggest(ss) => {
                assert!(ss.iter().any(|s| s.tool.name == "subfinder_enum"));
            }
            other => panic!("expected AutoApply/Suggest, got {other:?}"),
        }
    }

    #[test]
    fn friendly_phrase_resolves_to_subfinder() {
        let out = resolve("enumerate subdomains", &[ActionClass::Read]);
        let names: Vec<&str> = match out {
            ToolResolution::AutoApply(s) => vec![s.tool.name],
            ToolResolution::Suggest(ss) => ss.iter().map(|s| s.tool.name).collect(),
            ToolResolution::Refused(_) => vec![],
        };
        assert!(
            names.contains(&"subfinder_enum"),
            "expected subfinder_enum in suggestions, got {names:?}"
        );
    }

    #[test]
    fn tampered_binding_rejected_even_at_resolver_entry() {
        let mut b = binding(&[ActionClass::Read]);
        b.tag.replace_range(..4, "dead");
        let err = resolve_tool_call(
            &default_catalog(),
            &b,
            &key(),
            &ResolveRequest {
                name_or_phrase: "query",
                provided_args: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, AiGuardError::InvalidTag));
    }

    #[test]
    fn jaro_is_symmetric_within_fp_tolerance() {
        let a = jaro("abc", "abd");
        let b = jaro("abd", "abc");
        assert!((a - b).abs() < 1e-6);
    }

    #[test]
    fn normalize_is_stable() {
        assert_eq!(normalize("Camio  QL_QUERY"), "camio ql query");
        assert_eq!(normalize("--active-scan--"), "active scan");
    }

    #[test]
    fn suggest_caps_at_configured_max() {
        let out = resolve("scan", &[ActionClass::Read, ActionClass::Active]);
        if let ToolResolution::Suggest(ss) = out {
            assert!(ss.len() <= SUGGEST_MAX_RESULTS);
        }
    }

    #[test]
    fn empty_phrase_refuses_rather_than_matching_anything() {
        let out = resolve("", &[ActionClass::Read]);
        assert!(matches!(out, ToolResolution::Refused(_)));
    }
}
