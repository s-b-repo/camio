//! Site map tree (plan §7.2 "Discover — Target/site map tree").
//!
//! Builds a host → path tree from captured [`HttpExchange`]s so a tester can see
//! the discovered attack surface at a glance. Pure and allocation-light: it reads
//! only request metadata (never bodies), so it is cheap to rebuild over a large
//! history (plan §5).
//!
//! Hosts are keyed by their full origin (`scheme://host[:port]`) so `http` and
//! `https`, or two ports on one host, do not collapse together. Each node records
//! the exchange ids, methods, and response statuses seen at that path, which the
//! UI/CLI renders inline.

use crate::model::HttpExchange;
use std::collections::{BTreeMap, BTreeSet};

/// Maximum path depth the tree will descend. Deeper paths (only seen with
/// pathological or hostile input, e.g. a crafted import with tens of thousands
/// of `/` segments) are recorded at this depth rather than built into an
/// arbitrarily deep tree — which would let [`SiteMap::render_tree`]/`url_count`
/// recurse without bound and overflow the stack. Real paths are far shallower.
const MAX_DEPTH: usize = 256;

/// A node in the site tree: one path segment and its children.
#[derive(Debug, Clone, Default)]
pub struct SiteNode {
    /// Child segments, ordered lexicographically for stable rendering.
    pub children: BTreeMap<String, SiteNode>,
    /// Exchange ids whose path ends at this node.
    pub exchange_ids: Vec<i64>,
    /// HTTP methods observed terminating at this node.
    pub methods: BTreeSet<String>,
    /// Response status codes observed terminating at this node.
    pub statuses: BTreeSet<u16>,
}

impl SiteNode {
    fn child_mut(&mut self, segment: &str) -> &mut SiteNode {
        self.children.entry(segment.to_string()).or_default()
    }
}

/// A site map: origins → their path trees.
#[derive(Debug, Clone, Default)]
pub struct SiteMap {
    /// Origin (`scheme://host[:port]`) → root node.
    pub origins: BTreeMap<String, SiteNode>,
}

impl SiteMap {
    /// Build a site map from a set of exchanges.
    pub fn build(exchanges: &[HttpExchange]) -> SiteMap {
        let mut map = SiteMap::default();
        for ex in exchanges {
            map.add(ex);
        }
        map
    }

    /// Fold one exchange into the map.
    pub fn add(&mut self, ex: &HttpExchange) {
        let req = &ex.request;
        let Some(host) = req.host() else { return };
        let scheme = req.scheme().unwrap_or_else(|| "http".to_string());
        let origin = match req.port() {
            Some(p) if !is_default_port(&scheme, p) => format!("{scheme}://{host}:{p}"),
            _ => format!("{scheme}://{host}"),
        };

        let root = self.origins.entry(origin).or_default();
        let path = req.path();
        let mut node = &mut *root;
        // Bounded descent (see MAX_DEPTH): keeps the tree shallow enough that the
        // recursive renderer/counter cannot overflow the stack on hostile input.
        for segment in path.split('/').filter(|s| !s.is_empty()).take(MAX_DEPTH) {
            node = node.child_mut(segment);
        }
        // Terminal node for this path: record metadata.
        node.exchange_ids.push(ex.id.0);
        node.methods.insert(req.method.clone());
        if let Some(resp) = &ex.response {
            node.statuses.insert(resp.status);
        }
    }

    /// Number of distinct origins.
    pub fn origin_count(&self) -> usize {
        self.origins.len()
    }

    /// Number of distinct URLs (nodes that terminate at least one exchange).
    pub fn url_count(&self) -> usize {
        self.origins.values().map(count_urls).sum()
    }

    /// Render the tree as indented text for the CLI / a text report.
    pub fn render_tree(&self) -> String {
        let mut out = String::new();
        for (origin, root) in &self.origins {
            out.push_str(origin);
            out.push('\n');
            render_node(root, 1, &mut out);
        }
        out
    }
}

fn is_default_port(scheme: &str, port: u16) -> bool {
    matches!((scheme, port), ("http", 80) | ("https", 443))
}

fn count_urls(node: &SiteNode) -> usize {
    let here = usize::from(!node.exchange_ids.is_empty());
    here + node.children.values().map(count_urls).sum::<usize>()
}

fn render_node(node: &SiteNode, depth: usize, out: &mut String) {
    for (segment, child) in &node.children {
        for _ in 0..depth {
            out.push_str("  ");
        }
        out.push('/');
        out.push_str(segment);
        if !child.exchange_ids.is_empty() {
            let methods: Vec<&str> = child.methods.iter().map(|s| s.as_str()).collect();
            let statuses: Vec<String> = child.statuses.iter().map(|s| s.to_string()).collect();
            out.push_str("  [");
            out.push_str(&methods.join(","));
            if !statuses.is_empty() {
                out.push_str(" -> ");
                out.push_str(&statuses.join(","));
            }
            out.push(']');
        }
        out.push('\n');
        render_node(child, depth + 1, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Body, HttpRequest, HttpResponse, HttpVersion, Source};

    fn ex(id: i64, url: &str, method: &str, status: u16) -> HttpExchange {
        let mut req = HttpRequest::get(url);
        req.method = method.to_string();
        let resp = HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers: crate::model::HeaderList::new(),
            body: Body::empty(),
        };
        let mut e = HttpExchange::new(req, Source::Browser).with_response(resp);
        e.id = crate::model::ExchangeId(id);
        e
    }

    #[test]
    fn groups_by_origin_and_counts_urls() {
        let map = SiteMap::build(&[
            ex(1, "https://a.test/api/users", "GET", 200),
            ex(2, "https://a.test/api/users", "POST", 201),
            ex(3, "https://a.test/api/orders", "GET", 200),
            ex(4, "http://a.test/health", "GET", 200), // different scheme = different origin
        ]);
        assert_eq!(map.origin_count(), 2);
        // /api/users and /api/orders on https, /health on http = 3 distinct URLs.
        assert_eq!(map.url_count(), 3);
    }

    #[test]
    fn records_methods_and_statuses_at_leaf() {
        let map = SiteMap::build(&[
            ex(1, "https://a.test/api/users", "GET", 200),
            ex(2, "https://a.test/api/users", "POST", 201),
        ]);
        let https = &map.origins["https://a.test"];
        let users = &https.children["api"].children["users"];
        assert_eq!(users.exchange_ids, vec![1, 2]);
        assert!(users.methods.contains("GET") && users.methods.contains("POST"));
        assert!(users.statuses.contains(&200) && users.statuses.contains(&201));
    }

    #[test]
    fn non_default_port_is_a_distinct_origin() {
        let map = SiteMap::build(&[
            ex(1, "https://a.test/", "GET", 200),
            ex(2, "https://a.test:8443/", "GET", 200),
        ]);
        assert_eq!(map.origin_count(), 2);
        assert!(map.origins.contains_key("https://a.test"));
        assert!(map.origins.contains_key("https://a.test:8443"));
    }

    #[test]
    fn pathological_deep_path_is_bounded_and_does_not_overflow() {
        // Tens of thousands of segments (as a crafted import could produce) must
        // not build an unbounded tree or overflow the recursive renderer/counter.
        let deep = format!("https://a.test/{}", "x/".repeat(50_000));
        let map = SiteMap::build(&[ex(1, &deep, "GET", 200)]);
        assert_eq!(map.url_count(), 1);
        // render_tree must complete without a stack overflow.
        assert!(map.render_tree().contains("https://a.test"));
    }

    #[test]
    fn render_tree_shows_paths() {
        let map = SiteMap::build(&[ex(1, "https://a.test/api/users", "GET", 200)]);
        let tree = map.render_tree();
        assert!(tree.contains("https://a.test"));
        assert!(tree.contains("/api"));
        assert!(tree.contains("/users"));
        assert!(tree.contains("GET"));
    }
}
