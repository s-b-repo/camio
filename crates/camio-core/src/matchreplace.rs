//! Match & Replace rules (plan §7.2 "Capture … Match & Replace rules", §8).
//!
//! A [`MatchReplaceRule`] rewrites part of an [`HttpExchange`] when an optional
//! CamioQL condition matches — the same one query language used for search,
//! scope and intercept (plan §7.1), so a filter can be turned into a rewrite
//! rule with no new syntax. Rules are applied by the capture/replay layer before
//! a request goes out (or as a response is recorded); this module is the pure,
//! testable rule engine they share.
//!
//! Design rules consistent with the rest of Camio:
//!   * Header **order and casing are preserved** — a rule edits a value in place
//!     and never reorders or canonicalizes (plan §6.1 item 3).
//!   * Binary bodies are left untouched unless they are valid UTF-8, so a rule
//!     can never corrupt stored evidence (plan §13).
//!   * Regex replacement supports `$1`/`${name}` capture references (the `regex`
//!     crate's standard expansion).

use crate::camioql::{ParseError, Query};
use crate::model::{HttpExchange, HttpRequest, HttpResponse};
use regex::Regex;

/// Which part of a message a rule targets.
#[derive(Debug, Clone)]
pub enum Target {
    /// The request method token.
    Method,
    /// The full request URL.
    Url,
    /// A request header's value, matched case-insensitively by name.
    RequestHeader(String),
    /// The request body (only rewritten when it is valid UTF-8).
    RequestBody,
    /// The response reason phrase.
    ResponseReason,
    /// A response header's value, matched case-insensitively by name.
    ResponseHeader(String),
    /// The response body (only rewritten when it is valid UTF-8).
    ResponseBody,
}

/// How the rule finds text to replace.
#[derive(Debug, Clone)]
pub enum Find {
    /// A literal substring; every occurrence is replaced.
    Literal(String),
    /// A compiled regular expression; `replace` may use `$1`/`${name}` refs.
    Regex(Regex),
}

impl Find {
    /// Apply the find/replace to one string, returning `Some(new)` when it
    /// changed, or `None` when there was no match.
    fn rewrite(&self, hay: &str, replace: &str) -> Option<String> {
        match self {
            Find::Literal(needle) => {
                if needle.is_empty() || !hay.contains(needle.as_str()) {
                    None
                } else {
                    Some(hay.replace(needle.as_str(), replace))
                }
            }
            Find::Regex(re) => {
                if !re.is_match(hay) {
                    None
                } else {
                    Some(re.replace_all(hay, replace).into_owned())
                }
            }
        }
    }
}

/// A single match-and-replace rule.
#[derive(Debug, Clone)]
pub struct MatchReplaceRule {
    pub name: String,
    pub enabled: bool,
    /// Only apply when this CamioQL query matches the exchange. `None` = always.
    pub condition: Option<Query>,
    pub target: Target,
    pub find: Find,
    pub replace: String,
}

impl MatchReplaceRule {
    /// A literal-match rule. `condition` is optional CamioQL.
    pub fn literal(
        name: impl Into<String>,
        target: Target,
        find: impl Into<String>,
        replace: impl Into<String>,
        condition: Option<&str>,
    ) -> Result<Self, ParseError> {
        Ok(MatchReplaceRule {
            name: name.into(),
            enabled: true,
            condition: condition.map(Query::compile).transpose()?,
            target,
            find: Find::Literal(find.into()),
            replace: replace.into(),
        })
    }

    /// A regex-match rule. Fails if the pattern or the CamioQL condition is invalid.
    pub fn regex(
        name: impl Into<String>,
        target: Target,
        pattern: &str,
        replace: impl Into<String>,
        condition: Option<&str>,
    ) -> Result<Self, ParseError> {
        let re = Regex::new(pattern).map_err(|e| ParseError {
            message: format!("invalid match/replace regex: {e}"),
        })?;
        Ok(MatchReplaceRule {
            name: name.into(),
            enabled: true,
            condition: condition.map(Query::compile).transpose()?,
            target,
            find: Find::Regex(re),
            replace: replace.into(),
        })
    }

    /// Whether this rule's condition (if any) matches the exchange.
    pub fn applies(&self, ex: &HttpExchange) -> bool {
        self.enabled && self.condition.as_ref().is_none_or(|q| q.matches(ex))
    }

    /// Apply the rule to an exchange in place. Returns `true` if it changed
    /// anything. The condition is checked first.
    pub fn apply(&self, ex: &mut HttpExchange) -> bool {
        if !self.applies(ex) {
            return false;
        }
        match &self.target {
            Target::Method | Target::Url | Target::RequestHeader(_) | Target::RequestBody => {
                self.apply_request(&mut ex.request)
            }
            Target::ResponseReason | Target::ResponseHeader(_) | Target::ResponseBody => {
                match ex.response.as_mut() {
                    Some(resp) => self.apply_response(resp),
                    None => false,
                }
            }
        }
    }

    /// Apply a request-targeting rule to a bare request (used by the send path,
    /// where there is no full exchange yet). Ignores the CamioQL condition —
    /// callers that need it should gate with [`applies`](Self::applies).
    pub fn apply_request(&self, req: &mut HttpRequest) -> bool {
        match &self.target {
            Target::Method => rewrite_in_place(&mut req.method, &self.find, &self.replace),
            Target::Url => rewrite_in_place(&mut req.url, &self.find, &self.replace),
            Target::RequestHeader(name) => {
                rewrite_header(&mut req.headers, name, &self.find, &self.replace)
            }
            Target::RequestBody => rewrite_body(&mut req.body, &self.find, &self.replace),
            _ => false,
        }
    }

    fn apply_response(&self, resp: &mut HttpResponse) -> bool {
        match &self.target {
            Target::ResponseReason => match resp.reason.as_mut() {
                Some(r) => rewrite_in_place(r, &self.find, &self.replace),
                None => false,
            },
            Target::ResponseHeader(name) => {
                rewrite_header(&mut resp.headers, name, &self.find, &self.replace)
            }
            Target::ResponseBody => rewrite_body(&mut resp.body, &self.find, &self.replace),
            _ => false,
        }
    }
}

fn rewrite_in_place(s: &mut String, find: &Find, replace: &str) -> bool {
    match find.rewrite(s, replace) {
        Some(new) => {
            *s = new;
            true
        }
        None => false,
    }
}

/// Rewrite every value of a header matched case-insensitively by name,
/// preserving its original name casing and position.
fn rewrite_header(
    headers: &mut crate::model::HeaderList,
    name: &str,
    find: &Find,
    replace: &str,
) -> bool {
    let mut changed = false;
    for h in headers.0.iter_mut() {
        if h.name.eq_ignore_ascii_case(name) {
            if let Some(new) = find.rewrite(&h.value, replace) {
                h.value = new;
                changed = true;
            }
        }
    }
    changed
}

/// Rewrite a body only when it is valid UTF-8 (never corrupt binary evidence).
fn rewrite_body(body: &mut crate::model::Body, find: &Find, replace: &str) -> bool {
    let text = match std::str::from_utf8(body.as_bytes()) {
        Ok(t) => t,
        Err(_) => return false,
    };
    match find.rewrite(text, replace) {
        Some(new) => {
            *body = crate::model::Body::from_text(new);
            true
        }
        None => false,
    }
}

/// An ordered set of match-and-replace rules.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<MatchReplaceRule>,
}

impl RuleSet {
    pub fn new() -> Self {
        RuleSet::default()
    }

    pub fn with(mut self, rule: MatchReplaceRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn push(&mut self, rule: MatchReplaceRule) {
        self.rules.push(rule);
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Apply every enabled rule in order to an exchange; returns how many rules
    /// changed something.
    pub fn apply_all(&self, ex: &mut HttpExchange) -> usize {
        self.rules.iter().filter(|r| r.apply(ex)).count()
    }

    /// Apply every enabled request-targeting rule to a bare request, honouring
    /// each rule's CamioQL condition against a probe exchange built from the
    /// request. Returns how many rules changed something.
    pub fn apply_to_request(&self, req: &mut HttpRequest) -> usize {
        let mut count = 0;
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if let Some(q) = &rule.condition {
                let probe = HttpExchange::new(req.clone(), crate::model::Source::Replay);
                if !q.matches(&probe) {
                    continue;
                }
            }
            if rule.apply_request(req) {
                count += 1;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Body, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange() -> HttpExchange {
        let mut req = HttpRequest::get("https://shop.example.com/cart?id=7");
        req.headers.push("User-Agent", "curl/8.0");
        req.headers.push("Accept", "*/*");
        req.body = Body::from_text("name=original&id=7");
        let mut rh = crate::model::HeaderList::new();
        rh.push("Server", "nginx/1.20.1");
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: Some("OK".into()),
            headers: rh,
            body: Body::from_text("hello world"),
        };
        HttpExchange::new(req, Source::Browser).with_response(resp)
    }

    #[test]
    fn replaces_request_header_value_preserving_name() {
        let rule = MatchReplaceRule::literal(
            "spoof-ua",
            Target::RequestHeader("user-agent".into()),
            "curl/8.0",
            "Mozilla/5.0",
            None,
        )
        .unwrap();
        let mut ex = exchange();
        assert!(rule.apply(&mut ex));
        assert_eq!(ex.request.headers.get("User-Agent"), Some("Mozilla/5.0"));
        // Name casing preserved exactly.
        assert_eq!(ex.request.headers.0[0].name, "User-Agent");
    }

    #[test]
    fn replaces_in_url_and_body() {
        let url_rule = MatchReplaceRule::literal("id", Target::Url, "id=7", "id=8", None).unwrap();
        let body_rule =
            MatchReplaceRule::literal("name", Target::RequestBody, "original", "tampered", None)
                .unwrap();
        let mut ex = exchange();
        assert!(url_rule.apply(&mut ex));
        assert!(body_rule.apply(&mut ex));
        assert!(ex.request.url.contains("id=8"));
        assert_eq!(ex.request.body.as_text(), "name=tampered&id=7");
    }

    #[test]
    fn regex_with_capture_reference() {
        let rule = MatchReplaceRule::regex(
            "ver",
            Target::ResponseHeader("server".into()),
            r"nginx/[\d.]+",
            "nginx",
            None,
        )
        .unwrap();
        let mut ex = exchange();
        assert!(rule.apply(&mut ex));
        assert_eq!(
            ex.response.as_ref().unwrap().headers.get("Server"),
            Some("nginx")
        );
    }

    #[test]
    fn condition_gates_application() {
        // Only rewrite on a different host → must not fire here.
        let rule = MatchReplaceRule::literal(
            "cond",
            Target::Url,
            "cart",
            "basket",
            Some(r#"req.host.eq:"other.test""#),
        )
        .unwrap();
        let mut ex = exchange();
        assert!(!rule.apply(&mut ex));
        assert!(ex.request.url.contains("cart"));

        // Matching condition → fires.
        let rule2 = MatchReplaceRule::literal(
            "cond2",
            Target::Url,
            "cart",
            "basket",
            Some(r#"req.host.cont:"shop.example""#),
        )
        .unwrap();
        assert!(rule2.apply(&mut ex));
        assert!(ex.request.url.contains("basket"));
    }

    #[test]
    fn binary_body_is_not_corrupted() {
        let rule = MatchReplaceRule::literal("x", Target::RequestBody, "\u{0}", "X", None).unwrap();
        let mut ex = exchange();
        ex.request.body = Body::from_bytes(vec![0u8, 159, 146, 150]); // invalid utf-8
        assert!(!rule.apply(&mut ex));
        assert_eq!(ex.request.body.as_bytes(), &[0u8, 159, 146, 150]);
    }

    #[test]
    fn ruleset_applies_in_order_and_counts() {
        let set = RuleSet::new()
            .with(MatchReplaceRule::literal("a", Target::Url, "id=7", "id=9", None).unwrap())
            .with(
                MatchReplaceRule::literal(
                    "b",
                    Target::RequestHeader("accept".into()),
                    "*/*",
                    "application/json",
                    None,
                )
                .unwrap(),
            )
            .with(MatchReplaceRule::literal("noop", Target::Method, "ZZZ", "QQQ", None).unwrap());
        let mut ex = exchange();
        assert_eq!(set.apply_all(&mut ex), 2);
        assert!(ex.request.url.contains("id=9"));
        assert_eq!(ex.request.headers.get("Accept"), Some("application/json"));
    }

    #[test]
    fn apply_to_request_respects_condition() {
        let set = RuleSet::new().with(
            MatchReplaceRule::literal(
                "ua",
                Target::RequestHeader("user-agent".into()),
                "curl/8.0",
                "Camio/1.0",
                Some(r#"req.host.cont:"shop.example""#),
            )
            .unwrap(),
        );
        let mut req = HttpRequest::get("https://shop.example.com/cart?id=7");
        req.headers.push("User-Agent", "curl/8.0");
        assert_eq!(set.apply_to_request(&mut req), 1);
        assert_eq!(req.headers.get("User-Agent"), Some("Camio/1.0"));
    }
}
