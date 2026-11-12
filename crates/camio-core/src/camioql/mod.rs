//! CamioQL — the one query language used everywhere in Camio (plan §7.1).
//!
//! HTTPQL-compatible (Caido parity) so existing muscle memory transfers: clauses
//! are `namespace.field.operator:value`, combined with `AND`/`OR`/`NOT` and
//! parentheses; a bare word or quoted string is a free-text search over the raw
//! request and response.
//!
//! ```
//! use camio_core::camioql::Query;
//! use camio_core::model::{HttpExchange, HttpRequest, Source};
//!
//! let ex = HttpExchange::new(HttpRequest::get("https://example.com/a.js"), Source::Browser);
//! let q = Query::compile(r#"req.ext.eq:".js" AND req.host.cont:"example""#).unwrap();
//! assert!(q.matches(&ex));
//! ```
//!
//! ## Fields
//!
//! | Namespace | Fields |
//! |---|---|
//! | `req` | `method` `url` `host` `port`(int) `scheme` `path` `query` `ext` `len`(int) `raw` `body` `version` `header.<name>` |
//! | `resp` | `code`(int) `len`(int) `raw` `body` `reason` `version` `roundtrip`(int) `header.<name>` |
//! | (top) | `source` `scope` `fingerprint` `id`(int) `created_at`(int) |
//!
//! ## Operators
//!
//! String: `eq` `ne` (case-sensitive) · `cont` `ncont` `like` `nlike` (case-insensitive)
//! · `regex` `nregex`. Numeric: `eq` `ne` `gt` `gte` `lt` `lte`. Presence: `exists` `nexists`.
//! With no operator, numeric fields use `eq` and string fields use `cont`.

mod ast;
mod eval;
mod parser;
mod token;

pub use ast::{Clause, Expr, Operator};
pub use eval::{matches, Query, QueryTarget};
pub use parser::{parse, ParseError};

use crate::model::HttpExchange;
use std::borrow::Cow;

/// Case-insensitive equality for a path segment against a known keyword.
fn seg_is(seg: &str, want: &str) -> bool {
    seg.eq_ignore_ascii_case(want)
}

impl QueryTarget for HttpExchange {
    fn get_str(&self, field: &[String]) -> Option<Cow<'_, str>> {
        let req = &self.request;
        match field.len() {
            1 => {
                let f = &field[0];
                if seg_is(f, "source") {
                    Some(Cow::Borrowed(self.source.as_str()))
                } else if seg_is(f, "scope") {
                    self.scope.map(|s| Cow::Borrowed(s.as_str()))
                } else if seg_is(f, "fingerprint") {
                    self.fingerprint_used.as_deref().map(Cow::Borrowed)
                } else {
                    None
                }
            }
            2 if seg_is(&field[0], "req") => {
                let f = &field[1];
                if seg_is(f, "method") {
                    Some(Cow::Borrowed(req.method.as_str()))
                } else if seg_is(f, "url") {
                    Some(Cow::Borrowed(req.url.as_str()))
                } else if seg_is(f, "host") {
                    req.host().map(Cow::Owned)
                } else if seg_is(f, "scheme") {
                    req.scheme().map(Cow::Owned)
                } else if seg_is(f, "path") {
                    Some(Cow::Owned(req.path()))
                } else if seg_is(f, "query") {
                    req.query().map(Cow::Owned)
                } else if seg_is(f, "ext") {
                    req.extension().map(Cow::Owned)
                } else if seg_is(f, "raw") {
                    Some(Cow::Owned(req.raw()))
                } else if seg_is(f, "body") {
                    Some(req.body.as_text())
                } else if seg_is(f, "version") {
                    Some(Cow::Borrowed(req.version.wire_token()))
                } else {
                    None
                }
            }
            2 if seg_is(&field[0], "resp") => {
                let resp = self.response.as_ref()?;
                let f = &field[1];
                if seg_is(f, "raw") {
                    Some(Cow::Owned(resp.raw()))
                } else if seg_is(f, "body") {
                    Some(resp.body.as_text())
                } else if seg_is(f, "reason") {
                    resp.reason.as_deref().map(Cow::Borrowed)
                } else if seg_is(f, "version") {
                    Some(Cow::Borrowed(resp.version.wire_token()))
                } else {
                    None
                }
            }
            _ if field.len() >= 3 && seg_is(&field[0], "req") && seg_is(&field[1], "header") => {
                let name = field[2..].join(".");
                req.headers.get(&name).map(Cow::Borrowed)
            }
            _ if field.len() >= 3 && seg_is(&field[0], "resp") && seg_is(&field[1], "header") => {
                let resp = self.response.as_ref()?;
                let name = field[2..].join(".");
                resp.headers.get(&name).map(Cow::Borrowed)
            }
            _ => None,
        }
    }

    fn get_int(&self, field: &[String]) -> Option<i64> {
        match field.len() {
            1 if seg_is(&field[0], "id") => Some(self.id.0),
            1 if seg_is(&field[0], "created_at") => Some(self.created_at_ms),
            2 if seg_is(&field[0], "req") => {
                let f = &field[1];
                if seg_is(f, "port") {
                    self.request.port().map(|p| p as i64)
                } else if seg_is(f, "len") {
                    Some(self.request.body.len() as i64)
                } else if seg_is(f, "created_at") {
                    Some(self.created_at_ms)
                } else {
                    None
                }
            }
            2 if seg_is(&field[0], "resp") => {
                let f = &field[1];
                if seg_is(f, "code") || seg_is(f, "status") {
                    self.response.as_ref().map(|r| r.status as i64)
                } else if seg_is(f, "len") {
                    self.response.as_ref().map(|r| r.body.len() as i64)
                } else if seg_is(f, "roundtrip") {
                    self.timings.map(|t| t.roundtrip_ms)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn freetext_haystack(&self) -> Cow<'_, str> {
        let mut s = self.request.raw();
        if let Some(resp) = &self.response {
            s.push('\n');
            s.push_str(&resp.raw());
        }
        Cow::Owned(s)
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::model::{Body, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange() -> HttpExchange {
        let mut req = HttpRequest::get("https://shop.example.com/api/cart.json?id=7");
        req.method = "POST".into();
        req.headers.push("User-Agent", "Mozilla/5.0");
        req.headers.push("Content-Type", "application/json");
        req.body = Body::from_text(r#"{"item":"book"}"#);

        let mut resp_headers = crate::model::HeaderList::new();
        resp_headers.push("Server", "nginx");
        resp_headers.push("Content-Type", "application/json");
        let resp = HttpResponse {
            status: 500,
            version: HttpVersion::H2,
            reason: Some("Internal Server Error".into()),
            headers: resp_headers,
            body: Body::from_text("stack trace: NullPointer"),
        };
        let mut ex = HttpExchange::new(req, Source::Replay).with_response(resp);
        ex.fingerprint_used = Some("win-firefox-158-balanced".into());
        ex.timings = Some(crate::model::Timings {
            started_at_ms: 1_700_000_000_000,
            roundtrip_ms: 0,
        });
        ex
    }

    fn m(q: &str) -> bool {
        Query::compile(q).unwrap().matches(&exchange())
    }

    #[test]
    fn request_fields() {
        assert!(m("req.method.eq:POST"));
        assert!(m(r#"req.host.eq:"shop.example.com""#));
        assert!(m("req.port.eq:443"));
        assert!(m(r#"req.ext.eq:".json""#));
        assert!(m(r#"req.path.cont:"/api/""#));
        assert!(m(r#"req.query.cont:"id=7""#));
        assert!(m(r#"req.body.cont:"book""#));
    }

    #[test]
    fn response_fields() {
        assert!(m("resp.code.eq:500"));
        assert!(m("resp.code.gte:500"));
        assert!(m(r#"resp.reason.cont:"server error""#));
        assert!(m(r#"resp.body.cont:"nullpointer""#));
        assert!(m("resp.roundtrip.lt:1"));
    }

    #[test]
    fn headers_case_insensitive_lookup() {
        assert!(m(r#"req.header.user-agent.cont:"mozilla""#));
        assert!(m(r#"req.header.USER-AGENT.cont:"mozilla""#));
        assert!(m(r#"resp.header.server.eq:nginx"#));
        assert!(m("resp.header.x-missing.nexists:x"));
    }

    #[test]
    fn top_level_fields() {
        assert!(m("source.eq:replay"));
        assert!(m(r#"fingerprint.cont:"balanced""#));
    }

    #[test]
    fn combined_realistic_query() {
        assert!(m(
            r#"req.method.eq:POST AND resp.code.gte:500 AND req.host.cont:"example""#
        ));
        assert!(!m(r#"req.method.eq:GET OR resp.code.lt:400"#));
    }
}
