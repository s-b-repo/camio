//! Directory-listing / autoindex check (plan §8 "Scan & crawl").
//!
//! An exposed directory index leaks the file layout and often source, backups or
//! config. We match the autoindex markers emitted by common servers in the
//! response body.

use crate::checks::finding;
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// Flags responses whose body looks like a server-generated directory index.
pub struct DirectoryListing;

/// Lower-cased body markers of a directory index: Apache/nginx autoindex emit
/// `Index of /…`; Python's `http.server` emits `Directory listing for …`.
const MARKERS: &[&str] = &["index of /", "directory listing for"];

impl PassiveCheck for DirectoryListing {
    fn id(&self) -> &'static str {
        "directory-listing"
    }

    fn title(&self) -> &'static str {
        "Directory listing enabled"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        let body = resp.body.as_text();
        let lower = body.to_ascii_lowercase();
        if MARKERS.iter().any(|m| lower.contains(m)) {
            return vec![finding(
                "Directory listing enabled",
                Severity::Low,
                Confidence::Firm,
                "The response is a server-generated directory index, which exposes the file layout and may reveal source, backups or configuration files. Disable autoindex (e.g. Apache `Options -Indexes`) for this path.",
                ex.id,
            )];
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(body: &str) -> HttpExchange {
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text(body),
        };
        HttpExchange::new(HttpRequest::get("https://x.test/files/"), Source::Scanner)
            .with_response(resp)
    }

    #[test]
    fn flags_apache_style_index() {
        let ex = exchange("<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1></body></html>");
        let f = DirectoryListing.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Directory listing enabled");
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn flags_python_http_server_listing() {
        let ex = exchange("<title>Directory listing for /uploads/</title>");
        assert_eq!(DirectoryListing.check(&ex).len(), 1);
    }

    #[test]
    fn marker_match_is_case_insensitive() {
        let ex = exchange("<H1>INDEX OF /etc</H1>");
        assert_eq!(DirectoryListing.check(&ex).len(), 1);
    }

    #[test]
    fn ordinary_page_does_not_fire() {
        let ex = exchange(
            "<html><body><h1>Welcome</h1><p>Our index of products is below.</p></body></html>",
        );
        // "index of products" has no trailing slash, so the "index of /" marker
        // does not match.
        assert!(DirectoryListing.check(&ex).is_empty());
    }

    #[test]
    fn no_response_no_findings() {
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/files/"), Source::Scanner);
        assert!(DirectoryListing.check(&ex).is_empty());
    }
}
