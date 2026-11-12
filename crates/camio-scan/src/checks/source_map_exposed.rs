//! Source-map-exposure check (plan §8 "Scan & crawl").
//!
//! A shipped JavaScript source map reconstructs the original, unminified source —
//! comments, internal paths and occasionally secrets. This fires when a response
//! advertises a source map via the `SourceMap`/`X-SourceMap` header or an inline
//! `//# sourceMappingURL=` (or legacy `//@`) comment. Severity [`Severity::Low`],
//! [`Confidence::Firm`] (the signal is explicit).

use crate::checks::finding;
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Flags responses that advertise a JavaScript source map.
pub struct SourceMapExposed;

impl PassiveCheck for SourceMapExposed {
    fn id(&self) -> &'static str {
        "source-map-exposed"
    }

    fn title(&self) -> &'static str {
        "Source map exposed"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };

        let header =
            resp.headers.get("X-SourceMap").is_some() || resp.headers.get("SourceMap").is_some();
        let body = resp.body.as_text();
        let inline =
            body.contains("//# sourceMappingURL=") || body.contains("//@ sourceMappingURL=");

        if !(header || inline) {
            return Vec::new();
        }

        vec![finding(
            "Source map exposed",
            Severity::Low,
            Confidence::Firm,
            "The response advertises a JavaScript source map (via a `SourceMap`/`X-SourceMap` header or a `//# sourceMappingURL=` comment). Source maps reconstruct the original, unminified source — including comments, internal file paths and sometimes secrets. Do not serve source maps in production, or restrict them to authenticated internal users.",
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(headers: &[(&str, &str)], body: &str) -> HttpExchange {
        let mut h = HeaderList::new();
        for (n, v) in headers {
            h.push(*n, *v);
        }
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(body),
        };
        HttpExchange::new(HttpRequest::get("https://x.test/app.js"), Source::Scanner)
            .with_response(resp)
    }

    #[test]
    fn flags_sourcemap_header() {
        let ex = exchange(&[("SourceMap", "/static/app.js.map")], "console.log(1);");
        let f = SourceMapExposed.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Source map exposed");
        assert_eq!(f[0].severity, Severity::Low);
        assert_eq!(f[0].confidence, Confidence::Firm);
    }

    #[test]
    fn flags_x_sourcemap_header() {
        let ex = exchange(&[("X-SourceMap", "/static/app.js.map")], "console.log(1);");
        assert_eq!(SourceMapExposed.check(&ex).len(), 1);
    }

    #[test]
    fn flags_inline_source_mapping_comment() {
        let ex = exchange(
            &[("Content-Type", "application/javascript")],
            "!function(){}();\n//# sourceMappingURL=app.min.js.map",
        );
        assert_eq!(SourceMapExposed.check(&ex).len(), 1);
    }

    #[test]
    fn plain_script_without_map_does_not_fire() {
        let ex = exchange(
            &[("Content-Type", "application/javascript")],
            "function add(a, b) { return a + b; }",
        );
        assert!(SourceMapExposed.check(&ex).is_empty());
    }

    #[test]
    fn no_response_no_findings() {
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/app.js"), Source::Scanner);
        assert!(SourceMapExposed.check(&ex).is_empty());
    }
}
