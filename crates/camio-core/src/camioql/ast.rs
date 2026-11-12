//! CamioQL abstract syntax tree (plan §7: "one query language everywhere").

/// A comparison operator. The HTTPQL-compatible set (Caido parity) plus
/// existence checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    /// `eq` — equals (numeric if the field and value are numeric, else string).
    Eq,
    /// `ne` — not equals.
    Ne,
    /// `cont` — string contains (case-insensitive).
    Cont,
    /// `ncont` — does not contain.
    Ncont,
    /// `like` — SQL-style wildcard match (`%` any run, `_` any char).
    Like,
    /// `nlike` — negated `like`.
    Nlike,
    /// `regex` — regular-expression match.
    Regex,
    /// `nregex` — negated regex.
    Nregex,
    /// `gt` — greater than (numeric).
    Gt,
    /// `gte` — greater than or equal.
    Gte,
    /// `lt` — less than.
    Lt,
    /// `lte` — less than or equal.
    Lte,
    /// `exists` — the field is present.
    Exists,
    /// `nexists` — the field is absent.
    Nexists,
}

impl Operator {
    /// Parse an operator keyword (the last dotted segment of a clause key).
    pub fn from_token(s: &str) -> Option<Operator> {
        Some(match s {
            "eq" => Operator::Eq,
            "ne" => Operator::Ne,
            "cont" => Operator::Cont,
            "ncont" => Operator::Ncont,
            "like" => Operator::Like,
            "nlike" => Operator::Nlike,
            "regex" => Operator::Regex,
            "nregex" => Operator::Nregex,
            "gt" => Operator::Gt,
            "gte" => Operator::Gte,
            "lt" => Operator::Lt,
            "lte" => Operator::Lte,
            "exists" => Operator::Exists,
            "nexists" => Operator::Nexists,
            _ => return None,
        })
    }

    /// Operators that need no right-hand value.
    pub fn is_unary(self) -> bool {
        matches!(self, Operator::Exists | Operator::Nexists)
    }

    /// Operators that force numeric comparison.
    pub fn is_numeric(self) -> bool {
        matches!(
            self,
            Operator::Gt | Operator::Gte | Operator::Lt | Operator::Lte
        )
    }
}

/// A single field comparison, e.g. `resp.code.gte:400`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clause {
    /// The field path with the operator segment removed, e.g.
    /// `["resp", "code"]` or `["req", "header", "user-agent"]`.
    pub field: Vec<String>,
    /// The operator. `None` means "no explicit operator" — the evaluator picks
    /// `eq` for numeric fields/values and `cont` for strings (search-bar ergonomics).
    pub op: Option<Operator>,
    /// The right-hand value as written (unquoted). Interpreted per-operator.
    pub value: String,
}

/// A parsed CamioQL expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Always matches (empty query).
    True,
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Clause(Clause),
    /// Bare word/quoted string: contains-match against the raw request+response.
    FreeText(String),
    /// `preset:"name"` — reference to a saved query, resolved at evaluation.
    Preset(String),
}

impl Expr {
    pub fn and(a: Expr, b: Expr) -> Expr {
        Expr::And(Box::new(a), Box::new(b))
    }
    pub fn or(a: Expr, b: Expr) -> Expr {
        Expr::Or(Box::new(a), Box::new(b))
    }
    // A constructor named for the logical operator, matching `and`/`or`; not the
    // `std::ops::Not` trait.
    #[allow(clippy::should_implement_trait)]
    pub fn not(a: Expr) -> Expr {
        Expr::Not(Box::new(a))
    }
}
