//! Load the pre-built, on-disk Camio payload database (`payloads/DB/base/*.txt`)
//! at runtime. This is the "pre-built, sorted, organized, transparent" catalog:
//! the plain-text files under `payloads/DB/base/` are the source of truth, and
//! `payloads/DB/payloads.sqlite` is the pre-built artifact generated from them
//! by `scripts/build-payload-db.py`.
//!
//! The loader here reads the plain-text files — not the SQLite file — so Camio
//! stays a pure-Rust workspace with no SQLite dependency in `camio-automate`.
//! `camio-store` already carries rusqlite for history; callers that want to
//! query the SQLite catalog can do so directly.
//!
//! Signatures (short, distinctive substrings for the passive input-echo check)
//! are derived from every loaded payload and cached in the returned
//! [`PayloadDb`].

use crate::payloads::PayloadSet;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// A loaded payload catalog. Keys are category names (file stem), values are
/// the parsed [`PayloadSet`]s preserving source order.
#[derive(Debug, Clone, Default)]
pub struct PayloadDb {
    pub categories: BTreeMap<String, PayloadSet>,
    /// Signatures used by the passive input-echo check. Short, distinctive
    /// substrings drawn from the loaded payloads.
    pub signatures: Vec<Signature>,
}

/// A single detection signature — a short distinctive substring that, if seen
/// in a response body, suggests one of the loaded payload categories is
/// reaching a sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub category: String,
    pub needle: String,
}

/// Default directories to try, in priority order. The resolver stops at the
/// first one that contains readable `*.txt` files.
pub fn default_search_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(env) = std::env::var("CAMIO_PAYLOADS_DIR") {
        out.push(PathBuf::from(env));
    }
    out.push(PathBuf::from("payloads/DB/base"));
    out.push(PathBuf::from("./payloads/DB/base"));
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            out.push(parent.join("payloads/DB/base"));
            if let Some(gp) = parent.parent() {
                out.push(gp.join("payloads/DB/base"));
            }
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        out.push(PathBuf::from(home).join(".local/share/camio/payloads/DB/base"));
    }
    out
}

/// Load the payload catalog from the first readable path in
/// [`default_search_paths`]. Returns an empty [`PayloadDb`] if nothing resolves
/// — the caller can still proceed with the small built-in packs.
pub fn load_default() -> PayloadDb {
    for path in default_search_paths() {
        if path.is_dir() {
            if let Ok(db) = load_from_dir(&path) {
                if !db.categories.is_empty() {
                    return db;
                }
            }
        }
    }
    PayloadDb::default()
}

/// Load every `*.txt` file in `dir`. File stem becomes the category name;
/// comments (`#`) and blank lines are skipped by [`PayloadSet::from_lines`].
pub fn load_from_dir(dir: &Path) -> std::io::Result<PayloadDb> {
    let mut categories: BTreeMap<String, PayloadSet> = BTreeMap::new();
    let mut signatures: Vec<Signature> = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("txt") {
            continue;
        }
        let name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let text = fs::read_to_string(&path)?;
        let set = PayloadSet::from_lines(&name, &text);
        for payload in &set.payloads {
            if let Some(needle) = distinctive_substring(payload) {
                let sig = Signature {
                    category: name.clone(),
                    needle,
                };
                if !signatures.contains(&sig) {
                    signatures.push(sig);
                }
            }
        }
        categories.insert(name, set);
    }

    Ok(PayloadDb {
        categories,
        signatures,
    })
}

/// Return a short, distinctive substring suitable as a reflection signature,
/// or `None` if the payload is too short / too generic to be informative.
///
/// A good needle is one unlikely to appear in a response by coincidence — so
/// this function rejects purely-alphanumeric-and-common-punctuation strings
/// and prefers the first distinctive run of punctuation-laden characters.
fn distinctive_substring(payload: &str) -> Option<String> {
    let trimmed = payload.trim();
    if trimmed.len() < 6 {
        return None;
    }
    // Drop payloads that are pure header lines ("Name: value") or pure path-
    // like strings — they'd fire on benign content.
    if trimmed.contains(": ")
        && trimmed
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase())
        && !trimmed.contains('<')
        && !trimmed.contains('{')
        && !trimmed.contains('\'')
    {
        return None;
    }
    // A good needle has at least one "weird" character (punctuation that's
    // rare in normal content) OR a cluster of several non-alphanumeric chars.
    const WEIRD: &[char] = &[
        '<', '>', '{', '}', '`', '\\', '$', '|', ';', '%', '\0', '\n', '=', '"', '\'',
    ];
    let weird_in = |s: &str| s.chars().any(|c| WEIRD.contains(&c));
    let punct_count = |s: &str| {
        s.chars()
            .filter(|c| !c.is_alphanumeric() && !c.is_whitespace())
            .count()
    };

    // 1. Prefer the whole trimmed payload (capped at 48 chars) if it carries
    //    a weird character or a punctuation cluster.
    if weird_in(trimmed) || punct_count(trimmed) >= 2 {
        let candidate: String = trimmed.chars().take(48).collect();
        if candidate.len() >= 6 {
            return Some(candidate);
        }
    }

    // 2. Otherwise fall back to the longest whitespace-split run that carries
    //    at least one weird character.
    let mut best = String::new();
    for run in trimmed.split_whitespace() {
        if run.len() < 6 || !weird_in(run) {
            continue;
        }
        let candidate: String = run.chars().take(48).collect();
        if candidate.len() > best.len() {
            best = candidate;
        }
    }
    if best.is_empty() {
        None
    } else {
        Some(best)
    }
}

/// Scan a response body for any loaded signature. Returns the signatures
/// matched, in first-seen order, deduplicated by category.
pub fn scan_for_signatures<'a>(db: &'a PayloadDb, body: &str) -> Vec<&'a Signature> {
    let mut out: Vec<&Signature> = Vec::new();
    let mut seen_cats: Vec<&str> = Vec::new();
    for sig in &db.signatures {
        if body.contains(sig.needle.as_str()) && !seen_cats.contains(&sig.category.as_str()) {
            seen_cats.push(sig.category.as_str());
            out.push(sig);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir() -> tempdir::TempDir {
        tempdir::TempDir::new("camio-payloads").expect("tmpdir")
    }

    // The crate doesn't take tempdir as a dep; we just use std::env::temp_dir.
    mod tempdir {
        use std::path::PathBuf;
        pub struct TempDir(PathBuf);
        impl TempDir {
            pub fn new(prefix: &str) -> Result<Self, std::io::Error> {
                let p = std::env::temp_dir().join(format!(
                    "{prefix}-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0)
                ));
                std::fs::create_dir_all(&p)?;
                Ok(TempDir(p))
            }
            pub fn path(&self) -> &std::path::Path {
                &self.0
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn load_from_dir_reads_each_txt_file() {
        let dir = tmpdir();
        let mut f = std::fs::File::create(dir.path().join("xss.txt")).unwrap();
        writeln!(
            f,
            "# category: xss\n<script>alert(1)</script>\n<img src=x onerror=alert(1)>"
        )
        .unwrap();
        let mut g = std::fs::File::create(dir.path().join("sqli.txt")).unwrap();
        writeln!(g, "# category: sqli\n' OR '1'='1\n'; DROP TABLE users--").unwrap();

        let db = load_from_dir(dir.path()).unwrap();
        assert_eq!(db.categories.len(), 2);
        assert!(db.categories.contains_key("xss"));
        assert!(db.categories.contains_key("sqli"));
        assert!(!db.signatures.is_empty());
    }

    #[test]
    fn distinctive_substring_prefers_weird_chars() {
        assert!(distinctive_substring("hello world").is_none());
        assert!(distinctive_substring("abc").is_none());
        let s = distinctive_substring("<script>alert(1)</script>").unwrap();
        assert!(s.contains('<'));
    }

    #[test]
    fn distinctive_substring_rejects_header_lines() {
        assert!(distinctive_substring("Host: evil.test").is_none());
        assert!(distinctive_substring("Content-Length: 0").is_none());
    }

    #[test]
    fn scan_for_signatures_matches_in_body() {
        let dir = tmpdir();
        let mut f = std::fs::File::create(dir.path().join("sqli.txt")).unwrap();
        writeln!(f, "# category: sqli\n' OR '1'='1").unwrap();
        let db = load_from_dir(dir.path()).unwrap();
        let hits = scan_for_signatures(&db, "Response: ' OR '1'='1 was echoed");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].category, "sqli");
    }

    #[test]
    fn scan_dedup_by_category() {
        let dir = tmpdir();
        let mut f = std::fs::File::create(dir.path().join("xss.txt")).unwrap();
        writeln!(
            f,
            "# category: xss\n<script>alert(1)</script>\n<img src=x onerror=alert(1)>"
        )
        .unwrap();
        let db = load_from_dir(dir.path()).unwrap();
        let hits = scan_for_signatures(
            &db,
            "<script>alert(1)</script> and <img src=x onerror=alert(1)>",
        );
        assert_eq!(hits.len(), 1, "same category deduplicated");
        assert_eq!(hits[0].category, "xss");
    }

    #[test]
    fn load_default_empty_when_no_dir() {
        // With no payloads/DB/base near the temp CWD, load_default returns
        // whatever's reachable — but it must not panic.
        let _db = load_default();
    }
}
