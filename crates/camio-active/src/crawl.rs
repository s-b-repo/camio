//! A bounded, same-origin crawler (plan §8 "Scan & crawl", §10 discovery).
//!
//! Camio's site map is built from captured history; this adds *active* discovery:
//! starting from a seed URL, fetch pages through the injected [`Sender`] (so
//! scope, policy, rate, and budget are enforced in one place, exactly as the
//! active checks are), extract same-origin links, and follow them breadth-first
//! up to a page budget. Link extraction is a pure function, tested on its own;
//! the crawl loop never touches the network itself.

use crate::Sender;
use camio_core::{ExchangeId, HttpRequest};
use std::collections::{HashSet, VecDeque};
use url::Url;

/// Options bounding a crawl.
pub struct CrawlOptions {
    /// Maximum pages to fetch (hard budget).
    pub max_pages: usize,
    /// Only enqueue links on the seed's host (recommended).
    pub same_origin_only: bool,
}

impl Default for CrawlOptions {
    fn default() -> Self {
        CrawlOptions {
            max_pages: 50,
            same_origin_only: true,
        }
    }
}

/// The outcome of a crawl.
#[derive(Debug, Default)]
pub struct CrawlResult {
    /// Exchange IDs of pages that were fetched (and stored by the sender).
    pub fetched: Vec<ExchangeId>,
    /// Every URL discovered (whether or not it was fetched), sorted + unique.
    pub discovered: Vec<String>,
    /// URLs that were enqueued but skipped (refused by the sender / out of scope).
    pub skipped: usize,
}

/// Crawl from `seed`, fetching through `send`, bounded by `opts`.
///
/// The [`Sender`] gates scope/policy/budget and persists each exchange; a `None`
/// from it means "refused" and the page is simply not followed. Only in-scope,
/// same-origin (by default), not-yet-seen links are enqueued.
pub fn crawl(seed: &str, send: &Sender, opts: &CrawlOptions) -> CrawlResult {
    let mut result = CrawlResult::default();
    // A canonical seed so origin comparison sees scheme + port too.
    let seed_origin = Url::parse(seed)
        .map(|u| {
            let mut s = format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""));
            if let Some(port) = u.port_or_known_default() {
                s.push_str(&format!(":{port}"));
            }
            s
        })
        .unwrap_or_else(|_| seed.to_string());

    let mut frontier: VecDeque<String> = VecDeque::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut discovered: HashSet<String> = HashSet::new();

    frontier.push_back(seed.to_string());
    discovered.insert(seed.to_string());

    while let Some(url) = frontier.pop_front() {
        if result.fetched.len() >= opts.max_pages {
            break;
        }
        if !seen.insert(url.clone()) {
            continue;
        }

        match send(HttpRequest::get(&url)) {
            Some(exchange) => {
                result.fetched.push(exchange.id);
                if let Some(resp) = &exchange.response {
                    let body = resp.body.as_text();
                    for link in extract_links(&body, &url) {
                        if discovered.insert(link.clone()) {
                            // record every discovery
                        }
                        if opts.same_origin_only && !same_origin(&link, &seed_origin) {
                            continue;
                        }
                        if !seen.contains(&link) {
                            frontier.push_back(link);
                        }
                    }
                }
            }
            None => result.skipped += 1,
        }
    }

    result.discovered = {
        let mut v: Vec<String> = discovered.into_iter().collect();
        v.sort();
        v
    };
    result
}

/// Whether `url`'s host matches `host` (when both are known).
/// Same *origin* — scheme, host, and effective port — not merely the same host.
/// A page seeded at `https://app.test/` must not silently enqueue
/// `http://app.test/` (a downgrade) or `https://app.test:8443/` (a different
/// service), which a host-only comparison allows and the `--cross-origin` flag
/// then claims the operator approved.
fn same_origin(url: &str, seed: &str) -> bool {
    let Ok(candidate) = Url::parse(url) else {
        return false;
    };
    let Ok(seed) = Url::parse(seed) else {
        return false;
    };
    candidate.scheme().eq_ignore_ascii_case(seed.scheme())
        && candidate
            .host_str()
            .zip(seed.host_str())
            .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
        && candidate.port_or_known_default() == seed.port_or_known_default()
}

/// Extract absolute http(s) links from an HTML body, resolved against `base`.
///
/// Reads `href`, `src`, and `action` attribute values (quoted or unquoted),
/// resolves each against the base URL, drops non-http(s) schemes
/// (`javascript:`, `mailto:`, `data:`, fragments), and returns a sorted unique
/// list. Deliberately hand-rolled (plan §14 "prefer std / hand-rolling") and
/// tolerant: it never fails, it just returns what it can find.
pub fn extract_links(html: &str, base: &str) -> Vec<String> {
    let Ok(base_url) = Url::parse(base) else {
        return Vec::new();
    };
    let mut out: HashSet<String> = HashSet::new();

    for attr in ["href", "src", "action"] {
        let needle_eq = format!("{attr}=");
        let mut rest = html;
        while let Some(pos) = find_attr(rest, attr) {
            rest = &rest[pos + needle_eq.len()..];
            if let Some(value) = read_attr_value(rest) {
                if let Some(abs) = resolve(&base_url, &value) {
                    out.insert(abs);
                }
            }
        }
    }

    let mut v: Vec<String> = out.into_iter().collect();
    v.sort();
    v
}

/// Find `attr=` as a whole attribute (preceded by whitespace or `<`/`"`/`'`),
/// returning the byte offset of the attribute name, so `data-href=` is ignored.
fn find_attr(haystack: &str, attr: &str) -> Option<usize> {
    let pat = format!("{attr}=");
    let mut from = 0;
    while let Some(rel) = haystack[from..].find(&pat) {
        let idx = from + rel;
        let ok = idx == 0
            || haystack[..idx]
                .chars()
                .next_back()
                .map(|c| c.is_ascii_whitespace() || c == '<')
                .unwrap_or(true);
        if ok {
            return Some(idx);
        }
        from = idx + pat.len();
    }
    None
}

/// Read the attribute value starting right after `attr=`: a `"..."`, `'...'`, or
/// an unquoted run up to whitespace or `>`.
fn read_attr_value(after_eq: &str) -> Option<String> {
    let s = after_eq.trim_start();
    let mut chars = s.char_indices();
    let (_, first) = chars.next()?;
    match first {
        '"' | '\'' => {
            let quote = first;
            let start = quote.len_utf8();
            let end = s[start..].find(quote)?;
            Some(s[start..start + end].to_string())
        }
        _ => {
            let end = s
                .find(|c: char| c.is_ascii_whitespace() || c == '>')
                .unwrap_or(s.len());
            let v = s[..end].trim_end_matches('/');
            if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            }
        }
    }
}

/// Resolve a possibly-relative value against the base, keeping only http(s).
fn resolve(base: &Url, value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() || v.starts_with('#') {
        return None;
    }
    let lower = v.to_ascii_lowercase();
    for bad in ["javascript:", "mailto:", "data:", "tel:", "about:"] {
        if lower.starts_with(bad) {
            return None;
        }
    }
    let joined = base.join(v).ok()?;
    if joined.scheme() == "http" || joined.scheme() == "https" {
        let mut u = joined;
        u.set_fragment(None);
        Some(u.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpExchange, HttpResponse, HttpVersion, Source};
    use std::cell::RefCell;

    #[test]
    fn extracts_and_resolves_links() {
        let html = r##"
            <a href="/about">About</a>
            <a href='sub/page.html'>Sub</a>
            <link href="https://cdn.example.com/x.css">
            <script src="//other.test/a.js"></script>
            <form action="/submit?q=1">...</form>
            <a href="javascript:void(0)">no</a>
            <a href="#frag">frag</a>
            <a data-href="/trap">data-href ignored</a>
        "##;
        let links = extract_links(html, "https://ex.test/dir/");
        assert!(links.contains(&"https://ex.test/about".to_string()));
        assert!(links.contains(&"https://ex.test/dir/sub/page.html".to_string()));
        assert!(links.contains(&"https://cdn.example.com/x.css".to_string()));
        assert!(links.contains(&"https://other.test/a.js".to_string()));
        assert!(links.contains(&"https://ex.test/submit?q=1".to_string()));
        // javascript:, fragment, and data-href are excluded.
        assert!(!links.iter().any(|l| l.contains("javascript")));
        assert!(!links.iter().any(|l| l.contains("trap")));
    }

    #[test]
    fn crawl_follows_same_origin_links_within_budget() {
        // A tiny two-page site: / links to /next and to an external site.
        let send = |req: HttpRequest| -> Option<HttpExchange> {
            let body = match req.url.as_str() {
                "https://site.test/" => "<a href='/next'>n</a><a href='https://evil.test/x'>e</a>",
                "https://site.test/next" => "<a href='/'>home</a>",
                _ => "",
            };
            let resp = HttpResponse {
                status: 200,
                version: HttpVersion::Http11,
                reason: None,
                headers: HeaderList::new(),
                body: Body::from_text(body),
            };
            let mut ex = HttpExchange::new(req, Source::Crawler).with_response(resp);
            ex.id = ExchangeId(1);
            Some(ex)
        };
        let send: &Sender = &send;
        let res = crawl("https://site.test/", send, &CrawlOptions::default());
        // Fetched / and /next (same origin), not the external evil.test.
        assert_eq!(res.fetched.len(), 2);
        assert!(res.discovered.iter().any(|u| u == "https://site.test/next"));
        assert!(res.discovered.iter().any(|u| u == "https://evil.test/x"));
    }

    #[test]
    fn crawl_respects_page_budget() {
        // Every page links to a fresh new page; budget caps the fetch count.
        let counter = RefCell::new(0u32);
        let send = |req: HttpRequest| -> Option<HttpExchange> {
            *counter.borrow_mut() += 1;
            let n: u32 = req
                .url
                .rsplit('/')
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let body = format!("<a href='/{}'>next</a>", n + 1);
            let resp = HttpResponse {
                status: 200,
                version: HttpVersion::Http11,
                reason: None,
                headers: HeaderList::new(),
                body: Body::from_text(body),
            };
            Some(HttpExchange::new(req, Source::Crawler).with_response(resp))
        };
        let send: &Sender = &send;
        let opts = CrawlOptions {
            max_pages: 3,
            same_origin_only: true,
        };
        let res = crawl("https://h.test/0", send, &opts);
        assert_eq!(res.fetched.len(), 3);
        assert_eq!(*counter.borrow(), 3);
    }

    #[test]
    fn refused_sender_is_counted_not_followed() {
        let send = |_req: HttpRequest| -> Option<HttpExchange> { None };
        let send: &Sender = &send;
        let res = crawl("https://x.test/", send, &CrawlOptions::default());
        assert_eq!(res.fetched.len(), 0);
        assert_eq!(res.skipped, 1);
    }
}

#[cfg(test)]
mod origin_tests {
    use super::*;

    #[test]
    fn scheme_and_port_differences_are_cross_origin() {
        let seed = "https://app.test";
        assert!(same_origin("https://app.test/a", seed));
        assert!(same_origin("https://app.test:443/a", seed));
        // A scheme downgrade to the same host is NOT the same origin.
        assert!(!same_origin("http://app.test/a", seed));
        // A different service port is NOT the same origin.
        assert!(!same_origin("https://app.test:8443/a", seed));
    }

    #[test]
    fn explicit_nondefault_ports_match() {
        let seed = "http://app.test:8080";
        assert!(same_origin("http://app.test:8080/x", seed));
        assert!(!same_origin("http://app.test/x", seed));
        assert!(!same_origin("http://app.test:9090/x", seed));
    }

    #[test]
    fn host_case_is_ignored_but_host_name_is_not() {
        assert!(same_origin("https://APP.test/a", "https://app.test"));
        assert!(!same_origin("https://other.test/a", "https://app.test"));
        assert!(!same_origin("not a url", "https://app.test"));
    }
}
