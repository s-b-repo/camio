//! Attack-surface synthesis — the **cross-feature integration** layer that ties
//! passive recon to the payload database and scope (plan §8/§10/§16).
//!
//! On its own, each passive check reports a fact: a WAF is present, the stack is
//! WordPress+PHP, a subdomain looks takeoverable. This module fuses those facts
//! into **actionable, bounded guidance** an operator (or an AI agent, via MCP)
//! can act on:
//!   * which **payload-DB categories** are worth firing at this stack
//!     (`camio-automate`'s `payloads/DB/base/*`),
//!   * which **evasion encodings** to prefer when a WAF is in the way,
//!   * a **scope rule** that keeps follow-up testing on the right host.
//!
//! It is **pure analysis**: it recommends, it does not send. Execution still
//! goes through the scope- and policy-gated engine (`active_scan` / `fuzz` /
//! `send`), so this layer cannot widen what is reachable — it only prioritises
//! what is already authorized. That separation is the integrity boundary: recon
//! informs the plan; the plan is still confirmed and gated before any traffic.

use crate::checks::{detect_takeover, detect_tech, detect_waf, DetectedTech};
use camio_automate::Encoding;
use camio_core::HttpExchange;

/// A synthesized attack surface for one captured exchange: the recon facts plus
/// the prioritised, bounded testing guidance derived from them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackSurface {
    pub host: Option<String>,
    pub technologies: Vec<DetectedTech>,
    pub wafs: Vec<String>,
    pub takeover: Option<String>,
    /// Payload-DB category names (file stems under `payloads/DB/base/`) worth
    /// testing against this stack, most relevant first, deduplicated.
    pub suggested_payload_categories: Vec<String>,
    /// Evasion encodings to prefer when a WAF is present (empty otherwise).
    pub suggested_encodings: Vec<Encoding>,
    /// A CamioQL include rule that scopes follow-up testing to this host.
    pub suggested_scope_rule: Option<String>,
    /// Human-readable notes explaining the recommendations (and their limits).
    pub notes: Vec<String>,
}

/// The payload categories always worth trying, regardless of stack: generic
/// fuzzing, header injection, redirects, SSRF, CRLF.
const BASELINE_CATEGORIES: &[&str] =
    &["fuzz", "headers", "open-redirect", "ssrf", "crlf"];

/// Analyse a captured exchange into an [`AttackSurface`].
pub fn analyze(ex: &HttpExchange) -> AttackSurface {
    let (technologies, wafs, takeover, host) = match &ex.response {
        Some(resp) => (
            detect_tech(resp),
            detect_waf(resp).into_iter().map(String::from).collect::<Vec<_>>(),
            detect_takeover(resp).map(String::from),
            ex.request.host(),
        ),
        None => (Vec::new(), Vec::new(), None, ex.request.host()),
    };

    let mut cats: Vec<String> = Vec::new();
    let add = |c: &str, cats: &mut Vec<String>| {
        if !cats.iter().any(|x| x == c) {
            cats.push(c.to_string());
        }
    };

    // Stack-specific payload selection. Both the technology name and its
    // category drive the mapping, so an implied tech (e.g. PHP under WordPress)
    // still pulls in its payloads.
    for t in &technologies {
        for cat in payloads_for_tech(&t.name, &t.categories) {
            add(cat, &mut cats);
        }
    }
    // Baseline categories come last so stack-specific ones rank first.
    for c in BASELINE_CATEGORIES {
        add(c, &mut cats);
    }

    let suggested_encodings = if wafs.is_empty() {
        Vec::new()
    } else {
        evasion_encodings()
    };

    let suggested_scope_rule = host.as_ref().map(|h| format!("host:{h}"));

    let mut notes = Vec::new();
    if !technologies.is_empty() {
        notes.push(format!(
            "Stack-aware payload categories were selected from {} detected technolog{}.",
            technologies.len(),
            if technologies.len() == 1 { "y" } else { "ies" }
        ));
    }
    if !wafs.is_empty() {
        notes.push(format!(
            "A WAF/CDN ({}) is in front of the target; evasion encodings are suggested, but expect filtering and tighter rate limits.",
            wafs.join(", ")
        ));
    }
    if let Some(service) = &takeover {
        notes.push(format!(
            "The response looks like an unclaimed {service} resource — verify the CNAME before anything else (a takeover beats any injection here)."
        ));
    }
    notes.push(
        "Guidance only. Execution stays scope- and policy-gated and requires confirmation; this does not widen what is reachable.".to_string(),
    );

    AttackSurface {
        host,
        technologies,
        wafs,
        takeover,
        suggested_payload_categories: cats,
        suggested_encodings,
        suggested_scope_rule,
        notes,
    }
}

/// Map a detected technology (by name and category) to the payload-DB categories
/// most relevant to it. Category names are the file stems under
/// `payloads/DB/base/`.
pub fn payloads_for_tech(name: &str, categories: &[String]) -> Vec<&'static str> {
    let n = name.to_ascii_lowercase();
    let cat = |c: &str| categories.iter().any(|x| x.eq_ignore_ascii_case(c));
    let mut out: Vec<&'static str> = Vec::new();

    // By concrete technology.
    match n.as_str() {
        "php" => out.extend(["lfi", "rfi", "traversal", "cmdi", "sqli", "file-upload"]),
        "wordpress" | "drupal" | "joomla" => {
            out.extend(["sqli", "lfi", "traversal", "auth-bypass", "ssrf"])
        }
        "woocommerce" | "magento" | "shopify" => out.extend(["sqli", "auth-bypass", "formula"]),
        "asp.net" => out.extend(["deserialization", "path-confusion", "ssti", "lfi"]),
        "java" | "tomcat" | "spring" => {
            out.extend(["deserialization", "log4shell", "ssti", "path-confusion"])
        }
        "node.js" | "express" | "next.js" | "nuxt.js" => {
            out.extend(["prototype-pollution", "nosqli", "ssti", "cmdi"])
        }
        "python" | "django" | "flask" | "gunicorn" => {
            out.extend(["ssti", "sqli", "deserialization", "cmdi"])
        }
        "ruby on rails" | "ruby" => out.extend(["deserialization", "ssti", "sqli"]),
        "graphql" => out.extend(["graphql"]),
        "mysql" => out.extend(["sqli", "nosqli"]),
        _ => {}
    }

    // By category (covers techs not matched by name, and implied ones).
    if cat("CMS") || cat("Ecommerce") {
        out.extend(["sqli", "auth-bypass", "lfi"]);
    }
    if cat("Web Framework") {
        out.extend(["ssti", "deserialization"]);
    }
    if cat("Reverse Proxy") || cat("Caching") || cat("CDN") {
        out.extend(["smuggling", "path-confusion", "cache-deception"]);
    }
    if cat("JavaScript Framework") || cat("JavaScript Library") {
        out.extend(["prototype-pollution", "open-redirect"]);
    }
    if n.contains("ldap") {
        out.push("ldap");
    }

    // De-dup preserving order.
    let mut seen: Vec<&'static str> = Vec::new();
    for c in out {
        if !seen.contains(&c) {
            seen.push(c);
        }
    }
    seen
}

/// Encodings that commonly slip payloads past a signature-based WAF. Ordered by
/// how often they help in practice. These are *candidates* for the
/// `camio-automate` encoding expansion, not a guarantee of bypass.
pub fn evasion_encodings() -> Vec<Encoding> {
    vec![
        Encoding::UrlEncodedDouble,
        Encoding::UnicodeEscape,
        Encoding::MixedCase,
        Encoding::HtmlEntityNumeric,
        Encoding::OverlongSlash,
        Encoding::SqlCommentObfuscation,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(url: &str, headers: &[(&str, &str)], body: &str) -> HttpExchange {
        let mut h = HeaderList::new();
        h.push("Content-Type", "text/html");
        for (k, v) in headers {
            h.push(*k, *v);
        }
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(body),
        };
        HttpExchange::new(HttpRequest::get(url), Source::Scanner).with_response(resp)
    }

    #[test]
    fn php_stack_pulls_in_php_payloads() {
        let p = payloads_for_tech("PHP", &[]);
        assert!(p.contains(&"lfi"));
        assert!(p.contains(&"cmdi"));
        assert!(p.contains(&"traversal"));
    }

    #[test]
    fn wordpress_exchange_suggests_cms_payloads_and_scope() {
        let ex = exchange(
            "https://blog.example.test/",
            &[("X-Powered-By", "PHP/8.2")],
            r#"<meta name="generator" content="WordPress 6.4"><link href="/wp-content/x.css">"#,
        );
        let s = analyze(&ex);
        assert!(s.technologies.iter().any(|t| t.name == "WordPress"));
        assert!(s.suggested_payload_categories.contains(&"sqli".to_string()));
        assert!(s.suggested_payload_categories.contains(&"lfi".to_string()));
        // Baseline categories are always present.
        assert!(s.suggested_payload_categories.contains(&"fuzz".to_string()));
        assert_eq!(s.suggested_scope_rule.as_deref(), Some("host:blog.example.test"));
        // No WAF → no evasion encodings.
        assert!(s.suggested_encodings.is_empty());
    }

    #[test]
    fn waf_present_suggests_evasion_encodings() {
        let ex = exchange(
            "https://x.test/",
            &[("Server", "cloudflare"), ("CF-RAY", "7d-DFW")],
            "<html></html>",
        );
        let s = analyze(&ex);
        assert!(s.wafs.contains(&"Cloudflare".to_string()));
        assert!(!s.suggested_encodings.is_empty());
        assert!(s.suggested_encodings.contains(&Encoding::UrlEncodedDouble));
    }

    #[test]
    fn java_stack_includes_log4shell_and_deserialization() {
        let p = payloads_for_tech("Tomcat", &["Web Server".to_string()]);
        assert!(p.contains(&"log4shell"));
        assert!(p.contains(&"deserialization"));
    }

    #[test]
    fn baseline_categories_always_present_even_with_no_tech() {
        let ex = exchange("https://x.test/", &[], "<html></html>");
        let s = analyze(&ex);
        for c in ["fuzz", "headers", "ssrf"] {
            assert!(s.suggested_payload_categories.contains(&c.to_string()), "{c}");
        }
        // The integrity note is always present.
        assert!(s.notes.iter().any(|n| n.contains("scope- and policy-gated")));
    }

    #[test]
    fn category_driven_mapping_for_reverse_proxy() {
        let p = payloads_for_tech("SomeEdge", &["Reverse Proxy".to_string()]);
        assert!(p.contains(&"smuggling"));
        assert!(p.contains(&"path-confusion"));
    }
}
