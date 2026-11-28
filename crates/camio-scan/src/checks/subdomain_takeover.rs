//! Subdomain-takeover detection (inspired by `subjack` /
//! `can-i-take-over-xyz`) — passive detection of dangling third-party
//! resources (plan §8 "Scan & crawl").
//!
//! A subdomain whose DNS still points (via CNAME) at a third-party service that
//! no longer serves it — an unclaimed GitHub Pages site, a deleted Heroku app,
//! a removed S3 bucket — can be *claimed by an attacker*, who then controls
//! content on that hostname (cookies, OAuth redirects, phishing with a trusted
//! name). The tell is the provider's generic "not found" page.
//!
//! This check reads the captured response body/headers for those provider
//! fingerprints. It is **passive** and therefore reports a *candidate*:
//! confirming a real takeover needs the CNAME to be verified as dangling and
//! the resource to be actually claimable, which the finding tells the operator
//! to do. Confidence is deliberately [`Confidence::Tentative`].

use crate::checks::finding;
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, HttpResponse, Severity};

/// A takeover fingerprint: the service and the generic page it serves when the
/// backing resource is unclaimed.
struct TakeoverSig {
    service: &'static str,
    /// Distinctive substrings of the provider's "not found / unclaimed" page.
    body: &'static [&'static str],
    /// `Server`-header hint that strengthens the match (optional).
    server: Option<&'static str>,
}

/// The fingerprint table, curated from `can-i-take-over-xyz`'s confirmed-
/// vulnerable services (the ones whose edge serves a stable, claimable error).
static SIGS: &[TakeoverSig] = &[
    TakeoverSig {
        service: "GitHub Pages",
        body: &["There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file"],
        server: Some("GitHub.com"),
    },
    TakeoverSig {
        service: "Amazon S3",
        body: &["The specified bucket does not exist", "NoSuchBucket"],
        server: Some("AmazonS3"),
    },
    TakeoverSig {
        service: "Heroku",
        body: &["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        server: None,
    },
    TakeoverSig {
        service: "Shopify",
        body: &["Sorry, this shop is currently unavailable", "Only one step left!"],
        server: None,
    },
    TakeoverSig {
        service: "Fastly",
        body: &["Fastly error: unknown domain"],
        server: None,
    },
    TakeoverSig {
        service: "Bitbucket",
        body: &["Repository not found", "The page you have requested does not exist"],
        server: None,
    },
    TakeoverSig {
        service: "Ghost",
        body: &["The thing you were looking for is no longer here, or never was"],
        server: None,
    },
    TakeoverSig {
        service: "Tumblr",
        body: &["Whatever you were looking for doesn't currently exist at this address"],
        server: None,
    },
    TakeoverSig {
        service: "Surge.sh",
        body: &["project not found"],
        server: Some("SurgeCDN"),
    },
    TakeoverSig {
        service: "Pantheon",
        body: &["The gods are wise, but do not know of the site which you seek"],
        server: None,
    },
    TakeoverSig {
        service: "Zendesk",
        body: &["Help Center Closed"],
        server: None,
    },
    TakeoverSig {
        service: "Readme.io",
        body: &["Project doesnt exist... yet!"],
        server: None,
    },
    TakeoverSig {
        service: "Unbounce",
        body: &["The requested URL was not found on this server", "The requested URL / was not found"],
        server: None,
    },
    TakeoverSig {
        service: "Cargo Collective",
        body: &["<title>404 &mdash; File not found</title>", "If you're moving your domain away from Cargo"],
        server: None,
    },
];

/// Returns the service name for a dangling-resource fingerprint in the response,
/// or `None`. A body match is required; a matching `Server` header is corroborating.
pub fn detect(resp: &HttpResponse) -> Option<&'static str> {
    let body = resp.body.as_text();
    if body.is_empty() {
        return None;
    }
    let server = resp.headers.get("Server").map(|s| s.to_ascii_lowercase());
    for sig in SIGS {
        let body_hit = sig.body.iter().any(|needle| body.contains(needle));
        if !body_hit {
            continue;
        }
        // If the signature names a Server header, require it to be consistent
        // when a Server header is present at all (reduces false positives from a
        // page that merely quotes the error string).
        if let (Some(expected), Some(actual)) = (sig.server, server.as_deref()) {
            if !actual.contains(&expected.to_ascii_lowercase()) {
                continue;
            }
        }
        return Some(sig.service);
    }
    None
}

/// Passive subdomain-takeover candidate detector.
pub struct SubdomainTakeover;

impl PassiveCheck for SubdomainTakeover {
    fn id(&self) -> &'static str {
        "subdomain-takeover"
    }

    fn title(&self) -> &'static str {
        "Possible subdomain takeover"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        let Some(service) = detect(resp) else {
            return Vec::new();
        };
        let host = ex.request.host().unwrap_or_else(|| "this host".to_string());
        vec![finding(
            "Possible subdomain takeover",
            Severity::Medium,
            Confidence::Tentative,
            format!(
                "`{host}` returns the unclaimed-resource page of **{service}**, a service known to be vulnerable to takeover. If this host's DNS still points (CNAME) at {service} but the resource is unclaimed, an attacker could claim it and control content on `{host}` (cookies, OAuth redirects, trusted-name phishing).\n\nVerify before reporting: (1) `dig CNAME {host}` points at {service}; (2) the backing resource is actually unclaimed/claimable. This was detected passively from the response body; it is a candidate, not a confirmed takeover."
            ),
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn resp(server: Option<&str>, body: &str) -> HttpResponse {
        let mut h = HeaderList::new();
        h.push("Content-Type", "text/html");
        if let Some(s) = server {
            h.push("Server", s);
        }
        HttpResponse {
            status: 404,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(body),
        }
    }

    #[test]
    fn detects_github_pages_takeover() {
        let r = resp(Some("GitHub.com"), "<html><body>There isn't a GitHub Pages site here.</body></html>");
        assert_eq!(detect(&r), Some("GitHub Pages"));
    }

    #[test]
    fn detects_s3_bucket_takeover() {
        let r = resp(Some("AmazonS3"), "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>");
        assert_eq!(detect(&r), Some("Amazon S3"));
    }

    #[test]
    fn detects_heroku_without_server_header() {
        let r = resp(None, "<html>No such app</html>");
        assert_eq!(detect(&r), Some("Heroku"));
    }

    #[test]
    fn server_mismatch_suppresses_false_positive() {
        // A page that quotes the GitHub string but is served by nginx (not
        // GitHub.com) must not fire.
        let r = resp(Some("nginx"), "There isn't a GitHub Pages site here.");
        assert_eq!(detect(&r), None);
    }

    #[test]
    fn ordinary_404_detects_nothing() {
        let r = resp(Some("nginx"), "<h1>404 Not Found</h1>");
        assert_eq!(detect(&r), None);
    }

    #[test]
    fn check_emits_medium_tentative_with_host_and_guidance() {
        let r = resp(None, "No such app");
        let ex = HttpExchange::new(
            HttpRequest::get("https://dangling.example.test/"),
            Source::Scanner,
        )
        .with_response(r);
        let f = SubdomainTakeover.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].confidence, Confidence::Tentative);
        assert!(f[0].detail.contains("Heroku"));
        assert!(f[0].detail.contains("dangling.example.test"));
        assert!(f[0].detail.contains("dig CNAME"));
    }
}
