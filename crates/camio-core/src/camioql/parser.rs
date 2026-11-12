//! CamioQL parser: tokens → [`Expr`].
//!
//! Grammar (OR binds loosest; adjacency is an implicit AND so a search bar can
//! accept `req.host.cont:ex admin`):
//!
//! ```text
//! query    := or_expr? EOF
//! or_expr  := and_expr (OR and_expr)*
//! and_expr := not_expr ((AND)? not_expr)*
//! not_expr := NOT not_expr | primary
//! primary  := '(' or_expr ')' | clause | freetext
//! clause   := WORD ':' value          (operator is the last '.'-segment of WORD)
//! value    := STR | WORD
//! freetext := WORD | STR              (when not followed by ':')
//! ```

use super::ast::{Clause, Expr, Operator};
use super::token::{lex, Token};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CamioQL parse error: {}", self.message)
    }
}

impl std::error::Error for ParseError {}

impl From<super::token::LexError> for ParseError {
    fn from(e: super::token::LexError) -> Self {
        ParseError {
            message: e.to_string(),
        }
    }
}

/// Parse a CamioQL string into an [`Expr`]. An empty/whitespace query is
/// [`Expr::True`] (matches everything).
pub fn parse(input: &str) -> Result<Expr, ParseError> {
    let tokens = lex(input)?;
    let mut p = Parser { tokens, pos: 0 };
    if p.peek().is_none() {
        return Ok(Expr::True);
    }
    let expr = p.or_expr()?;
    if let Some(tok) = p.peek() {
        return Err(ParseError {
            message: format!("unexpected trailing token `{tok}`"),
        });
    }
    Ok(expr)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, want: &Token) -> Result<(), ParseError> {
        match self.next() {
            Some(ref t) if t == want => Ok(()),
            Some(t) => Err(ParseError {
                message: format!("expected `{want}`, found `{t}`"),
            }),
            None => Err(ParseError {
                message: format!("expected `{want}`, found end of input"),
            }),
        }
    }

    fn or_expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.and_expr()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.next();
            let right = self.and_expr()?;
            left = Expr::or(left, right);
        }
        Ok(left)
    }

    fn and_expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.not_expr()?;
        loop {
            match self.peek() {
                Some(Token::And) => {
                    self.next();
                    let right = self.not_expr()?;
                    left = Expr::and(left, right);
                }
                // Implicit AND: another primary directly follows.
                Some(Token::Not) | Some(Token::LParen) | Some(Token::Word(_))
                | Some(Token::Str(_)) => {
                    let right = self.not_expr()?;
                    left = Expr::and(left, right);
                }
                _ => break,
            }
        }
        Ok(left)
    }

    fn not_expr(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.next();
            let inner = self.not_expr()?;
            return Ok(Expr::not(inner));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some(Token::LParen) => {
                self.next();
                let inner = self.or_expr()?;
                self.eat(&Token::RParen)?;
                Ok(inner)
            }
            Some(Token::Word(_)) => {
                let word = match self.next() {
                    Some(Token::Word(w)) => w,
                    _ => unreachable!(),
                };
                if matches!(self.peek(), Some(Token::Colon)) {
                    self.next(); // consume ':'
                    let value = self.value()?;
                    Ok(build_clause(&word, value))
                } else {
                    // Bare word → free-text contains match.
                    Ok(Expr::FreeText(word))
                }
            }
            Some(Token::Str(_)) => {
                let s = match self.next() {
                    Some(Token::Str(s)) => s,
                    _ => unreachable!(),
                };
                Ok(Expr::FreeText(s))
            }
            Some(tok) => Err(ParseError {
                message: format!("unexpected token `{tok}`"),
            }),
            None => Err(ParseError {
                message: "unexpected end of input".into(),
            }),
        }
    }

    fn value(&mut self) -> Result<String, ParseError> {
        match self.next() {
            Some(Token::Str(s)) => Ok(s),
            Some(Token::Word(w)) => Ok(w),
            Some(t) => Err(ParseError {
                message: format!("expected a value after `:`, found `{t}`"),
            }),
            None => Err(ParseError {
                message: "expected a value after `:`".into(),
            }),
        }
    }
}

/// Turn a clause key (`resp.code.gte`) + value into an [`Expr`]. If the last
/// dotted segment is a known operator it is used; otherwise the whole key is the
/// field and the operator is left `None` (evaluator picks by type). The special
/// field `preset` becomes an [`Expr::Preset`].
fn build_clause(key: &str, value: String) -> Expr {
    let mut segments: Vec<String> = key.split('.').map(|s| s.to_string()).collect();

    // `preset:"name"` reference.
    if segments.len() == 1 && segments[0].eq_ignore_ascii_case("preset") {
        return Expr::Preset(value);
    }

    let op = if segments.len() > 1 {
        Operator::from_token(segments.last().unwrap())
    } else {
        None
    };
    if op.is_some() {
        segments.pop(); // remove the operator segment from the field path
    }

    // Namespace segments are case-insensitive; header names keep their case.
    Expr::Clause(Clause {
        field: segments,
        op,
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::camioql::ast::{Clause, Operator};

    fn clause(field: &[&str], op: Option<Operator>, value: &str) -> Expr {
        Expr::Clause(Clause {
            field: field.iter().map(|s| s.to_string()).collect(),
            op,
            value: value.to_string(),
        })
    }

    #[test]
    fn empty_is_true() {
        assert_eq!(parse("").unwrap(), Expr::True);
        assert_eq!(parse("   ").unwrap(), Expr::True);
    }

    #[test]
    fn single_clause_splits_operator() {
        assert_eq!(
            parse(r#"resp.code.gte:400"#).unwrap(),
            clause(&["resp", "code"], Some(Operator::Gte), "400")
        );
    }

    #[test]
    fn clause_without_operator_keeps_full_field() {
        assert_eq!(
            parse(r#"resp.code:200"#).unwrap(),
            clause(&["resp", "code"], None, "200")
        );
    }

    #[test]
    fn header_name_with_hyphen_parses() {
        assert_eq!(
            parse(r#"req.header.user-agent.cont:"curl""#).unwrap(),
            clause(
                &["req", "header", "user-agent"],
                Some(Operator::Cont),
                "curl"
            )
        );
    }

    #[test]
    fn and_or_precedence() {
        // a OR b AND c  ==  a OR (b AND c)
        let e = parse("a OR b AND c").unwrap();
        assert_eq!(
            e,
            Expr::or(
                Expr::FreeText("a".into()),
                Expr::and(Expr::FreeText("b".into()), Expr::FreeText("c".into()))
            )
        );
    }

    #[test]
    fn implicit_and_between_adjacent_terms() {
        let e = parse("admin req.method.eq:POST").unwrap();
        assert_eq!(
            e,
            Expr::and(
                Expr::FreeText("admin".into()),
                clause(&["req", "method"], Some(Operator::Eq), "POST")
            )
        );
    }

    #[test]
    fn grouping_overrides_precedence() {
        let e = parse("(a OR b) AND c").unwrap();
        assert_eq!(
            e,
            Expr::and(
                Expr::or(Expr::FreeText("a".into()), Expr::FreeText("b".into())),
                Expr::FreeText("c".into())
            )
        );
    }

    #[test]
    fn not_and_preset() {
        assert_eq!(
            parse("NOT resp.code.eq:500").unwrap(),
            Expr::not(clause(&["resp", "code"], Some(Operator::Eq), "500"))
        );
        assert_eq!(
            parse(r#"preset:"my saved""#).unwrap(),
            Expr::Preset("my saved".into())
        );
    }

    #[test]
    fn unbalanced_paren_errors() {
        assert!(parse("(a OR b").is_err());
        assert!(parse("a)").is_err());
    }
}
