//! CamioQL lexer.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `:` (separates a clause key from its value)
    Colon,
    /// Logical AND (`AND`, `and`, `&&`).
    And,
    /// Logical OR (`OR`, `or`, `||`).
    Or,
    /// Logical NOT (`NOT`, `not`, `!`).
    Not,
    /// A quoted string literal (quotes stripped, escapes resolved).
    Str(String),
    /// An unquoted run: a clause key, a bare value, or free text.
    Word(String),
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::LParen => f.write_str("("),
            Token::RParen => f.write_str(")"),
            Token::Colon => f.write_str(":"),
            Token::And => f.write_str("AND"),
            Token::Or => f.write_str("OR"),
            Token::Not => f.write_str("NOT"),
            Token::Str(s) => write!(f, "\"{s}\""),
            Token::Word(s) => f.write_str(s),
        }
    }
}

/// A lexing error with the byte offset where it occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexError {
    pub pos: usize,
    pub message: String,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lex error at {}: {}", self.pos, self.message)
    }
}

/// Characters allowed, unquoted, in a clause key or bare value. Includes `.`
/// (path separator), `-` (header names), `/` `*` `%` `_` `+` `@` and more so
/// that values like `text/html`, `/api/v1`, or `2024-01-01` need no quotes.
fn is_word_char(c: char) -> bool {
    // Note: '!', '&', '|', '(', ')', ':', and quotes are deliberately excluded —
    // they are structural tokens. '-' and '.' are in because header names and
    // field paths use them; '/', '%', '*', '+' etc. let common values stay unquoted.
    c.is_alphanumeric()
        || matches!(
            c,
            '.' | '_' | '-' | '/' | '*' | '%' | '+' | '@' | '~' | '=' | '$' | '#'
        )
}

/// Tokenize a CamioQL string.
pub fn lex(input: &str) -> Result<Vec<Token>, LexError> {
    let mut out = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() => {
                i += 1;
            }
            '(' => {
                out.push(Token::LParen);
                i += 1;
            }
            ')' => {
                out.push(Token::RParen);
                i += 1;
            }
            ':' => {
                out.push(Token::Colon);
                i += 1;
            }
            '!' => {
                out.push(Token::Not);
                i += 1;
            }
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                out.push(Token::And);
                i += 2;
            }
            '|' if i + 1 < chars.len() && chars[i + 1] == '|' => {
                out.push(Token::Or);
                i += 2;
            }
            '"' | '\'' => {
                let quote = c;
                let start = i;
                i += 1;
                let mut s = String::new();
                loop {
                    if i >= chars.len() {
                        return Err(LexError {
                            pos: start,
                            message: "unterminated string literal".into(),
                        });
                    }
                    let ch = chars[i];
                    if ch == '\\' && i + 1 < chars.len() {
                        // Only these escapes are consumed; every other backslash
                        // is PRESERVED so regex patterns like "v\d+" survive the
                        // lexer intact (a `\<other>` keeps both characters).
                        let next = chars[i + 1];
                        match next {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            '\\' => s.push('\\'),
                            '"' => s.push('"'),
                            '\'' => s.push('\''),
                            other => {
                                s.push('\\');
                                s.push(other);
                            }
                        }
                        i += 2;
                        continue;
                    }
                    if ch == quote {
                        i += 1;
                        break;
                    }
                    s.push(ch);
                    i += 1;
                }
                out.push(Token::Str(s));
            }
            _ if is_word_char(c) => {
                let mut s = String::new();
                while i < chars.len() && is_word_char(chars[i]) {
                    s.push(chars[i]);
                    i += 1;
                }
                // Reserved words (case-insensitive) become logical operators, but
                // only in their bare form (a clause value is always quoted or a
                // distinct token, so `req.body.cont:and` must be quoted).
                match s.to_ascii_lowercase().as_str() {
                    "and" => out.push(Token::And),
                    "or" => out.push(Token::Or),
                    "not" => out.push(Token::Not),
                    _ => out.push(Token::Word(s)),
                }
            }
            other => {
                return Err(LexError {
                    pos: i,
                    message: format!("unexpected character {other:?}"),
                });
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexes_clause_and_logic() {
        let toks = lex(r#"req.ext.eq:".js" AND resp.code.gte:400"#).unwrap();
        assert_eq!(
            toks,
            vec![
                Token::Word("req.ext.eq".into()),
                Token::Colon,
                Token::Str(".js".into()),
                Token::And,
                Token::Word("resp.code.gte".into()),
                Token::Colon,
                Token::Word("400".into()),
            ]
        );
    }

    #[test]
    fn lexes_grouping_and_symbols() {
        let toks = lex("(a || b) && !c").unwrap();
        assert_eq!(
            toks,
            vec![
                Token::LParen,
                Token::Word("a".into()),
                Token::Or,
                Token::Word("b".into()),
                Token::RParen,
                Token::And,
                Token::Not,
                Token::Word("c".into()),
            ]
        );
    }

    #[test]
    fn string_escapes_resolve() {
        let toks = lex(r#""a\"b\\c""#).unwrap();
        assert_eq!(toks, vec![Token::Str("a\"b\\c".into())]);
    }

    #[test]
    fn unterminated_string_errors() {
        assert!(lex(r#""abc"#).is_err());
    }
}
