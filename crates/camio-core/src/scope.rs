//! Scope rules and the single scope-decision path (plan §16).
//!
//! Every tool — browser capture, Replay, Automate, Scanner, MCP — asks
//! [`Scope::decide`] the same question, so they cannot disagree about whether a
//! destination is in scope. Scope rules are expressed in CamioQL, so the scope
//! editor and the query bar share one language (plan §7.1).
//!
//! An SSRF/safety guard runs **first and always wins**: loopback, link-local,
//! cloud-metadata, and private destinations are blocked unless the project is a
//! lab profile that explicitly allows them (plan §16: "reject loopback,
//! link-local, metadata, and out-of-scope destinations unless explicitly
//! allowed in a lab profile").

use crate::camioql::{ParseError, Query};
use crate::model::{HttpExchange, ScopeDecision};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A single scope rule: a CamioQL query plus whether matching includes or
/// excludes the exchange.
#[derive(Debug, Clone)]
pub struct ScopeRule {
    pub query: Query,
    /// `true` = an include rule, `false` = an exclude rule.
    pub include: bool,
    pub enabled: bool,
}

impl ScopeRule {
    pub fn include(query: &str) -> Result<Self, ParseError> {
        Ok(ScopeRule {
            query: Query::compile(query)?,
            include: true,
            enabled: true,
        })
    }

    pub fn exclude(query: &str) -> Result<Self, ParseError> {
        Ok(ScopeRule {
            query: Query::compile(query)?,
            include: false,
            enabled: true,
        })
    }
}

/// An ordered set of scope rules plus the safety posture.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub rules: Vec<ScopeRule>,
    /// Lab mode: when `true`, the SSRF guard permits private/loopback targets.
    /// Off by default — a safe default that a lab profile opts out of.
    pub allow_private: bool,
}

impl Scope {
    pub fn new() -> Self {
        Scope::default()
    }

    pub fn with_rule(mut self, rule: ScopeRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Allow private/loopback/metadata destinations (lab profile only).
    pub fn allowing_private(mut self) -> Self {
        self.allow_private = true;
        self
    }

    /// Decide an exchange's scope. The SSRF guard is checked first and cannot be
    /// overridden by include rules.
    pub fn decide(&self, ex: &HttpExchange) -> ScopeDecision {
        if !self.allow_private {
            if let Some(host) = ex.request.host() {
                if is_guarded_host(&host) {
                    return ScopeDecision::Blocked;
                }
            }
        }

        let mut excluded = false;
        let mut has_include = false;
        let mut included = false;

        for rule in self.rules.iter().filter(|r| r.enabled) {
            if rule.include {
                has_include = true;
                if rule.query.matches(ex) {
                    included = true;
                }
            } else if rule.query.matches(ex) {
                excluded = true;
            }
        }

        // An explicit exclude always wins over includes.
        if excluded {
            return ScopeDecision::OutOfScope;
        }
        // With no include rules, everything not excluded is in scope (Burp-style).
        if !has_include || included {
            ScopeDecision::InScope
        } else {
            ScopeDecision::OutOfScope
        }
    }

    /// Convenience: is this exchange sendable (in scope and not blocked)?
    pub fn is_in_scope(&self, ex: &HttpExchange) -> bool {
        self.decide(ex).is_sendable()
    }
}

/// Hostnames that are blocked by the SSRF guard regardless of scope rules.
fn is_guarded_name(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h == "metadata"
        || h == "metadata.google.internal"
        || h.ends_with(".internal")
        || h.ends_with(".local")
}

/// Whether a request host must be blocked by the SSRF guard: a dangerous IP
/// literal, or a known-internal hostname.
pub fn is_guarded_host(host: &str) -> bool {
    // Strip IPv6 brackets if present (url::Host keeps them off, but be safe).
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = h.parse::<IpAddr>() {
        return is_guarded_ip(ip);
    }
    is_guarded_name(host)
}

/// Whether an IP address is in a range the guard blocks (loopback, private,
/// link-local incl. the 169.254.169.254 metadata address, unspecified, ULA).
pub fn is_guarded_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_guarded_v4(v4),
        IpAddr::V6(v6) => is_guarded_v6(v6),
    }
}

fn is_guarded_v4(a: Ipv4Addr) -> bool {
    a.is_loopback()            // 127.0.0.0/8
        || a.is_private()      // 10/8, 172.16/12, 192.168/16
        || a.is_link_local()   // 169.254.0.0/16 (incl. cloud metadata .169.254)
        || a.is_unspecified()  // 0.0.0.0
        || a.is_broadcast()    // 255.255.255.255
        || a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 0x40 // 100.64/10 CGNAT
}

fn is_guarded_v6(a: Ipv6Addr) -> bool {
    if a.is_loopback() || a.is_unspecified() {
        return true;
    }
    let seg = a.segments();
    // Unique local fc00::/7.
    if (seg[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-local fe80::/10.
    if (seg[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // IPv4-mapped (::ffff:a.b.c.d) → apply the v4 guard to the embedded address.
    if let Some(v4) = a.to_ipv4_mapped() {
        return is_guarded_v4(v4);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HttpRequest, Source};

    fn ex(url: &str) -> HttpExchange {
        HttpExchange::new(HttpRequest::get(url), Source::Scanner)
    }

    #[test]
    fn ssrf_guard_blocks_dangerous_hosts() {
        let scope = Scope::new();
        assert_eq!(
            scope.decide(&ex("http://127.0.0.1/")),
            ScopeDecision::Blocked
        );
        assert_eq!(
            scope.decide(&ex("http://localhost:8080/")),
            ScopeDecision::Blocked
        );
        assert_eq!(
            scope.decide(&ex("http://169.254.169.254/latest/meta-data/")),
            ScopeDecision::Blocked
        );
        assert_eq!(
            scope.decide(&ex("http://10.0.0.5/")),
            ScopeDecision::Blocked
        );
        assert_eq!(
            scope.decide(&ex("http://192.168.1.1/")),
            ScopeDecision::Blocked
        );
        assert_eq!(scope.decide(&ex("http://[::1]/")), ScopeDecision::Blocked);
        assert_eq!(
            scope.decide(&ex("http://metadata.google.internal/")),
            ScopeDecision::Blocked
        );
    }

    #[test]
    fn lab_profile_can_allow_private() {
        let scope = Scope::new().allowing_private();
        assert_eq!(
            scope.decide(&ex("http://127.0.0.1:3000/")),
            ScopeDecision::InScope
        );
    }

    #[test]
    fn public_host_in_scope_by_default() {
        let scope = Scope::new();
        assert_eq!(
            scope.decide(&ex("https://example.com/")),
            ScopeDecision::InScope
        );
    }

    #[test]
    fn include_rules_restrict_scope() {
        let scope =
            Scope::new().with_rule(ScopeRule::include(r#"req.host.cont:"target.test""#).unwrap());
        assert_eq!(
            scope.decide(&ex("https://target.test/a")),
            ScopeDecision::InScope
        );
        assert_eq!(
            scope.decide(&ex("https://other.test/a")),
            ScopeDecision::OutOfScope
        );
    }

    #[test]
    fn exclude_overrides_include() {
        let scope = Scope::new()
            .with_rule(ScopeRule::include(r#"req.host.cont:"target.test""#).unwrap())
            .with_rule(ScopeRule::exclude(r#"req.path.cont:"/logout""#).unwrap());
        assert_eq!(
            scope.decide(&ex("https://target.test/app")),
            ScopeDecision::InScope
        );
        assert_eq!(
            scope.decide(&ex("https://target.test/logout")),
            ScopeDecision::OutOfScope
        );
    }

    #[test]
    fn guard_beats_scope_rules() {
        // Even if an include rule matches, the SSRF guard still blocks.
        let scope = Scope::new().with_rule(ScopeRule::include("req.host.cont:127").unwrap());
        assert_eq!(
            scope.decide(&ex("http://127.0.0.1/")),
            ScopeDecision::Blocked
        );
    }
}
