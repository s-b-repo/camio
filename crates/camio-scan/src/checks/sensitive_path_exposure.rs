//! Sensitive-file/-directory exposure check (plan §8 "Scan & crawl").
//!
//! Version-control directories (`.git`, `.svn`), credential and config files
//! (`.env`, `.htpasswd`, `.aws`, `wp-config.php`), SSH material (`.ssh/`) and
//! backups must never be reachable from the web root. This fires when the request
//! path matches one of those patterns **and** the server actually served it
//! (`2xx`) — a path match alone, with no response or a `404`, is not evidence the
//! file was exposed. Severity [`Severity::Medium`], [`Confidence::Firm`].

use crate::checks::{finding, is_2xx};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};
use regex::Regex;
use std::sync::OnceLock;

/// Flags requests to sensitive files/directories that were served with a 2xx.
pub struct SensitivePathExposure;

/// Sensitive path patterns (VCS dirs, dotfiles, backups, well-known secrets).
/// A compile failure degrades the check to "no finding".
fn sensitive_path_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)/\.(git|svn|env|htpasswd|aws)(/|$)|/\.git/|/backup|/\.env|/wp-config\.php|/\.ssh/",
        )
        .ok()
    })
    .as_ref()
}

impl PassiveCheck for SensitivePathExposure {
    fn id(&self) -> &'static str {
        "sensitive-path-exposure"
    }

    fn title(&self) -> &'static str {
        "Sensitive file or directory exposed"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let path = ex.request.path();
        let Some(re) = sensitive_path_re() else {
            return Vec::new();
        };
        if !re.is_match(&path) {
            return Vec::new();
        }
        // Only a 2xx means the file/dir was actually served.
        let served = ex.response.as_ref().map(is_2xx).unwrap_or(false);
        if !served {
            return Vec::new();
        }

        vec![finding(
            "Sensitive file or directory exposed",
            Severity::Medium,
            Confidence::Firm,
            format!(
                "The request targets a sensitive path (`{path}`) and the server returned a 2xx response, so a version-control directory, credential/config file or backup was actually served. Block access to dotfiles, VCS directories and backups at the web server, and remove them from the web root."
            ),
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(url: &str, status: u16) -> HttpExchange {
        let resp = HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text("data"),
        };
        HttpExchange::new(HttpRequest::get(url), Source::Scanner).with_response(resp)
    }

    #[test]
    fn flags_served_git_directory() {
        let ex = exchange("https://x.test/.git/config", 200);
        let f = SensitivePathExposure.check(&ex);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Sensitive file or directory exposed");
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].confidence, Confidence::Firm);
    }

    #[test]
    fn flags_various_served_sensitive_paths() {
        for url in [
            "https://x.test/.env",
            "https://x.test/.aws/credentials",
            "https://x.test/.ssh/id_rsa",
            "https://x.test/wp-config.php",
            "https://x.test/backup/db.sql",
            "https://x.test/.svn/entries",
        ] {
            assert_eq!(
                SensitivePathExposure.check(&exchange(url, 200)).len(),
                1,
                "{url}"
            );
        }
    }

    #[test]
    fn sensitive_path_not_served_does_not_fire() {
        // The path matches, but a 404 means it was not exposed.
        let ex = exchange("https://x.test/.git/config", 404);
        assert!(SensitivePathExposure.check(&ex).is_empty());
    }

    #[test]
    fn ordinary_path_does_not_fire() {
        let ex = exchange("https://x.test/index.html", 200);
        assert!(SensitivePathExposure.check(&ex).is_empty());
    }

    #[test]
    fn sensitive_path_without_response_does_not_fire() {
        let ex = HttpExchange::new(
            HttpRequest::get("https://x.test/.git/config"),
            Source::Scanner,
        );
        assert!(SensitivePathExposure.check(&ex).is_empty());
    }
}
