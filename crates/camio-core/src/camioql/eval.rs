//! CamioQL evaluation: compile an [`Expr`] to a [`Query`] (regexes compiled
//! once), then test it against any [`QueryTarget`].

use super::ast::{Clause, Expr, Operator};
use super::parser::{parse, ParseError};
use regex::Regex;
use std::borrow::Cow;

/// Anything CamioQL can be evaluated against (an [`HttpExchange`], or a storage
/// row). Field paths arrive lowercased for the namespace but with header names
/// in their original case.
///
/// [`HttpExchange`]: crate::model::HttpExchange
pub trait QueryTarget {
    /// String value of a field, e.g. `["req","host"]` or `["resp","header","server"]`.
    fn get_str(&self, field: &[String]) -> Option<Cow<'_, str>>;
    /// Integer value of a field, e.g. `["resp","code"]`.
    fn get_int(&self, field: &[String]) -> Option<i64>;
    /// Whether a field is present at all (default: has a string or int value).
    fn field_exists(&self, field: &[String]) -> bool {
        self.get_int(field).is_some() || self.get_str(field).is_some()
    }
    /// The text searched by a bare free-text term (typically raw req + resp).
    fn freetext_haystack(&self) -> Cow<'_, str>;
}

/// A compiled, reusable CamioQL query.
#[derive(Debug, Clone)]
pub struct Query {
    root: Node,
    source: String,
    needs_body: bool,
}

impl Query {
    /// Parse and compile a CamioQL string.
    pub fn compile(input: &str) -> Result<Query, ParseError> {
        let expr = parse(input)?;
        Ok(Query {
            root: compile_expr(&expr)?,
            source: input.to_string(),
            needs_body: expr_needs_body(&expr),
        })
    }

    /// The original query text.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Whether evaluating this query inspects message bodies (a `body`/`raw`
    /// field, or a free-text/`preset` term). A storage backend uses this to
    /// avoid loading content-addressed body blobs for metadata-only queries
    /// (plan §5, history performance).
    pub fn needs_body(&self) -> bool {
        self.needs_body
    }

    /// Test the query against a target. Unresolved `preset:` references match
    /// nothing (resolve them before evaluation if needed).
    pub fn matches(&self, target: &dyn QueryTarget) -> bool {
        eval(&self.root, target)
    }
}

#[derive(Debug, Clone)]
enum Node {
    True,
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Not(Box<Node>),
    Clause {
        field: Vec<String>,
        test: Test,
    },
    /// Lower-cased needle, matched against the free-text haystack.
    FreeText(String),
    /// Unresolved saved-query reference.
    Preset,
}

#[derive(Debug, Clone)]
enum Cmp {
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Debug, Clone)]
enum Test {
    /// Case-insensitive contains (negated when bool is true).
    Contains(String, bool),
    /// Compiled `like`/`regex` pattern (negated when bool is true).
    Re(Regex, bool),
    /// Pure numeric comparison.
    Num(Cmp, i64),
    /// `eq`/`ne` where the value may be numeric (compare ints if the field is
    /// numeric and the value parses) or a case-sensitive string otherwise.
    EqMaybeNum {
        value: String,
        num: Option<i64>,
        negate: bool,
    },
    /// Field presence (negated when bool is true).
    Exists(bool),
    /// No explicit operator: numeric `eq` if possible, else case-insensitive
    /// contains.
    Default {
        contains_lc: String,
        num: Option<i64>,
    },
}

/// Whether evaluating `expr` requires message body bytes.
fn expr_needs_body(expr: &Expr) -> bool {
    match expr {
        Expr::True => false,
        Expr::And(a, b) | Expr::Or(a, b) => expr_needs_body(a) || expr_needs_body(b),
        Expr::Not(a) => expr_needs_body(a),
        // Free text searches the raw message; presets are unknown → be safe.
        Expr::FreeText(_) | Expr::Preset(_) => true,
        Expr::Clause(c) => c
            .field
            .iter()
            .any(|s| s.eq_ignore_ascii_case("body") || s.eq_ignore_ascii_case("raw")),
    }
}

fn compile_expr(expr: &Expr) -> Result<Node, ParseError> {
    Ok(match expr {
        Expr::True => Node::True,
        Expr::And(a, b) => Node::And(Box::new(compile_expr(a)?), Box::new(compile_expr(b)?)),
        Expr::Or(a, b) => Node::Or(Box::new(compile_expr(a)?), Box::new(compile_expr(b)?)),
        Expr::Not(a) => Node::Not(Box::new(compile_expr(a)?)),
        Expr::FreeText(s) => Node::FreeText(s.to_lowercase()),
        Expr::Preset(_) => Node::Preset,
        Expr::Clause(c) => compile_clause(c)?,
    })
}

fn compile_clause(c: &Clause) -> Result<Node, ParseError> {
    let num = c.value.trim().parse::<i64>().ok();
    let test = match c.op {
        None => Test::Default {
            contains_lc: c.value.to_lowercase(),
            num,
        },
        Some(Operator::Eq) => Test::EqMaybeNum {
            value: c.value.clone(),
            num,
            negate: false,
        },
        Some(Operator::Ne) => Test::EqMaybeNum {
            value: c.value.clone(),
            num,
            negate: true,
        },
        Some(Operator::Cont) => Test::Contains(c.value.to_lowercase(), false),
        Some(Operator::Ncont) => Test::Contains(c.value.to_lowercase(), true),
        Some(Operator::Like) => Test::Re(compile_regex(&like_to_regex(&c.value), c)?, false),
        Some(Operator::Nlike) => Test::Re(compile_regex(&like_to_regex(&c.value), c)?, true),
        Some(Operator::Regex) => Test::Re(compile_regex(&c.value, c)?, false),
        Some(Operator::Nregex) => Test::Re(compile_regex(&c.value, c)?, true),
        Some(Operator::Gt) => Test::Num(Cmp::Gt, require_num(num, c)?),
        Some(Operator::Gte) => Test::Num(Cmp::Gte, require_num(num, c)?),
        Some(Operator::Lt) => Test::Num(Cmp::Lt, require_num(num, c)?),
        Some(Operator::Lte) => Test::Num(Cmp::Lte, require_num(num, c)?),
        Some(Operator::Exists) => Test::Exists(false),
        Some(Operator::Nexists) => Test::Exists(true),
    };
    Ok(Node::Clause {
        field: c.field.clone(),
        test,
    })
}

fn require_num(num: Option<i64>, c: &Clause) -> Result<i64, ParseError> {
    num.ok_or_else(|| ParseError {
        message: format!(
            "operator on field `{}` needs a numeric value, got `{}`",
            c.field.join("."),
            c.value
        ),
    })
}

fn compile_regex(pattern: &str, c: &Clause) -> Result<Regex, ParseError> {
    Regex::new(pattern).map_err(|e| ParseError {
        message: format!("invalid pattern for `{}`: {e}", c.field.join(".")),
    })
}

/// Translate an SQL-style `like` pattern (`%` any run, `_` any char) into an
/// anchored, case-insensitive regex.
fn like_to_regex(pat: &str) -> String {
    let mut re = String::from("(?is)^");
    for ch in pat.chars() {
        match ch {
            '%' => re.push_str(".*"),
            '_' => re.push('.'),
            c => {
                if "\\.^$|?*+()[]{}".contains(c) {
                    re.push('\\');
                }
                re.push(c);
            }
        }
    }
    re.push('$');
    re
}

fn eval(node: &Node, t: &dyn QueryTarget) -> bool {
    match node {
        Node::True => true,
        Node::And(a, b) => eval(a, t) && eval(b, t),
        Node::Or(a, b) => eval(a, t) || eval(b, t),
        Node::Not(a) => !eval(a, t),
        Node::Preset => false,
        Node::FreeText(needle) => t
            .freetext_haystack()
            .to_lowercase()
            .contains(needle.as_str()),
        Node::Clause { field, test } => eval_clause(field, test, t),
    }
}

fn eval_clause(field: &[String], test: &Test, t: &dyn QueryTarget) -> bool {
    match test {
        Test::Exists(negate) => t.field_exists(field) ^ negate,

        Test::Contains(needle_lc, negate) => {
            let got = t.get_str(field);
            let found = got
                .as_deref()
                .map(|s| s.to_lowercase().contains(needle_lc.as_str()))
                .unwrap_or(false);
            found ^ negate
        }

        Test::Re(re, negate) => {
            let got = t.get_str(field);
            let found = got.as_deref().map(|s| re.is_match(s)).unwrap_or(false);
            found ^ negate
        }

        Test::Num(cmp, rhs) => match t.get_int(field) {
            Some(lhs) => match cmp {
                Cmp::Gt => lhs > *rhs,
                Cmp::Gte => lhs >= *rhs,
                Cmp::Lt => lhs < *rhs,
                Cmp::Lte => lhs <= *rhs,
            },
            None => false,
        },

        Test::EqMaybeNum { value, num, negate } => {
            // Numeric compare when the field is numeric and the value is a number.
            if let (Some(n), Some(lhs)) = (num, t.get_int(field)) {
                return (lhs == *n) ^ negate;
            }
            let eq = t.get_str(field).as_deref() == Some(value.as_str());
            eq ^ negate
        }

        Test::Default { contains_lc, num } => {
            if let (Some(n), Some(lhs)) = (num, t.get_int(field)) {
                return lhs == *n;
            }
            t.get_str(field)
                .map(|s| s.to_lowercase().contains(contains_lc.as_str()))
                .unwrap_or(false)
        }
    }
}

/// Convenience: compile `input` and test it against `target` in one call.
pub fn matches(input: &str, target: &dyn QueryTarget) -> Result<bool, ParseError> {
    Ok(Query::compile(input)?.matches(target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A tiny in-test target: string fields + int fields + haystack.
    struct Row {
        strs: HashMap<String, String>,
        ints: HashMap<String, i64>,
        hay: String,
    }
    impl Row {
        fn new() -> Self {
            Row {
                strs: HashMap::new(),
                ints: HashMap::new(),
                hay: String::new(),
            }
        }
        fn s(mut self, k: &str, v: &str) -> Self {
            self.strs.insert(k.into(), v.into());
            self.hay.push_str(v);
            self.hay.push(' ');
            self
        }
        fn i(mut self, k: &str, v: i64) -> Self {
            self.ints.insert(k.into(), v);
            self
        }
    }
    impl QueryTarget for Row {
        fn get_str(&self, field: &[String]) -> Option<Cow<'_, str>> {
            self.strs
                .get(&field.join("."))
                .map(|s| Cow::Borrowed(s.as_str()))
        }
        fn get_int(&self, field: &[String]) -> Option<i64> {
            self.ints.get(&field.join(".")).copied()
        }
        fn freetext_haystack(&self) -> Cow<'_, str> {
            Cow::Borrowed(&self.hay)
        }
    }

    fn m(q: &str, row: &Row) -> bool {
        Query::compile(q).unwrap().matches(row)
    }

    #[test]
    fn numeric_comparisons() {
        let row = Row::new().i("resp.code", 404);
        assert!(m("resp.code.gte:400", &row));
        assert!(m("resp.code.lt:500", &row));
        assert!(!m("resp.code.gt:404", &row));
        assert!(m("resp.code.eq:404", &row));
        assert!(m("resp.code:404", &row)); // default op = numeric eq
        assert!(!m("resp.code:200", &row));
    }

    #[test]
    fn string_contains_is_case_insensitive() {
        let row = Row::new().s("req.host", "API.Example.COM");
        assert!(m(r#"req.host.cont:"example""#, &row));
        assert!(m("req.host:example", &row)); // default op = contains
        assert!(!m(r#"req.host.cont:"nope""#, &row));
        assert!(m(r#"req.host.ncont:"nope""#, &row));
    }

    #[test]
    fn string_eq_is_case_sensitive() {
        let row = Row::new().s("req.method", "POST");
        assert!(m("req.method.eq:POST", &row));
        assert!(!m("req.method.eq:post", &row));
        assert!(m("req.method.ne:GET", &row));
    }

    #[test]
    fn like_and_regex() {
        let row = Row::new().s("req.path", "/api/v2/users");
        assert!(m(r#"req.path.like:"/api/%""#, &row));
        assert!(m(r#"req.path.like:"/API/%""#, &row)); // like is case-insensitive
        assert!(!m(r#"req.path.like:"/web/%""#, &row));
        assert!(m(r#"req.path.regex:"v\d+""#, &row));
        assert!(m(r#"req.path.nregex:"v99""#, &row));
    }

    #[test]
    fn exists() {
        let row = Row::new().s("resp.header.server", "nginx");
        assert!(m("resp.header.server.exists:x", &row));
        assert!(m("resp.header.missing.nexists:x", &row));
        assert!(!m("resp.header.missing.exists:x", &row));
    }

    #[test]
    fn boolean_logic_and_grouping() {
        let row = Row::new().s("req.method", "POST").i("resp.code", 500);
        assert!(m("req.method.eq:POST AND resp.code.gte:500", &row));
        assert!(m("req.method.eq:GET OR resp.code.eq:500", &row));
        assert!(!m("req.method.eq:GET AND resp.code.eq:500", &row));
        assert!(m(
            "(req.method.eq:GET OR req.method.eq:POST) AND resp.code.eq:500",
            &row
        ));
        assert!(m("NOT req.method.eq:GET", &row));
    }

    #[test]
    fn free_text_searches_haystack() {
        let row = Row::new().s("resp.body", "Internal Server Error");
        assert!(m("error", &row));
        assert!(m(r#""server error""#, &row));
        assert!(!m("teapot", &row));
    }

    #[test]
    fn empty_query_matches_all() {
        let row = Row::new();
        assert!(m("", &row));
    }

    #[test]
    fn numeric_operator_on_nonnumeric_value_fails_compile() {
        assert!(Query::compile("resp.code.gt:abc").is_err());
    }

    #[test]
    fn needs_body_flag_is_accurate() {
        assert!(!Query::compile("resp.code.gte:500").unwrap().needs_body());
        assert!(!Query::compile("req.host.cont:example")
            .unwrap()
            .needs_body());
        assert!(Query::compile(r#"resp.body.cont:"error""#)
            .unwrap()
            .needs_body());
        assert!(Query::compile(r#"req.raw.regex:"pass""#)
            .unwrap()
            .needs_body());
        assert!(Query::compile("admin").unwrap().needs_body()); // free text
        assert!(!Query::compile("").unwrap().needs_body());
    }
}
