//! Wappalyzer-schema technology fingerprint engine (ported from Wappalyzer's
//! `technologies.json` format) — the accuracy upgrade behind
//! [`super::tech_fingerprint`].
//!
//! Where the old check used a flat substring table, this engine is **regex- and
//! data-driven** in Wappalyzer's exact schema, so it supports:
//!   * version extraction (`pattern\;version:\1` capture templates),
//!   * per-pattern confidence (`pattern\;confidence:N`),
//!   * `implies` relationships (detecting Next.js implies React + Node.js),
//!   * categories, resolved from the embedded category map.
//!
//! The built-in ruleset ships as [`DEFAULT_DB_JSON`] (`fingerprints.json`,
//! Camio-authored, Wappalyzer-format). Because the loader also accepts a **raw
//! upstream Wappalyzer technologies map**, an operator can point Camio at the
//! real database ([`TechDb::from_json`]) to widen coverage without code changes.
//!
//! Pure and offline: it only reads an already-captured response.

use camio_core::HttpResponse;
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// The embedded, Camio-authored fingerprint database (Wappalyzer schema).
pub const DEFAULT_DB_JSON: &str = include_str!("fingerprints.json");

/// A Wappalyzer pattern string is `regex` optionally followed by `\;key:value`
/// modifiers (`confidence:N`, `version:TEMPLATE`). One compiled instance.
#[derive(Debug)]
struct Pattern {
    re: Regex,
    /// Version template, e.g. `\1` or `ASP.NET MVC \1`; `\N` is replaced by the
    /// Nth capture group of a match. `None` when the pattern carries no version.
    version: Option<String>,
    /// 0..=100; defaults to 100.
    confidence: u8,
}

impl Pattern {
    /// Parse one Wappalyzer pattern string. Returns `None` if the regex part
    /// cannot compile (that single pattern is dropped, never a panic).
    fn parse(spec: &str) -> Option<Pattern> {
        let mut parts = spec.split("\\;");
        let raw = parts.next().unwrap_or("");
        // Case-insensitive matching improves real-world hit-rate (Wappalyzer
        // ports commonly do this) without breaking version captures.
        let re = Regex::new(&format!("(?i){raw}")).ok()?;
        let mut version = None;
        let mut confidence = 100u8;
        for modi in parts {
            if let Some(v) = modi.strip_prefix("version:") {
                version = Some(v.to_string());
            } else if let Some(c) = modi.strip_prefix("confidence:") {
                confidence = c.parse().unwrap_or(100);
            }
        }
        Some(Pattern { re, version, confidence })
    }

    /// Test `haystack`; on a match return `(confidence, extracted_version)`.
    fn test(&self, haystack: &str) -> Option<(u8, Option<String>)> {
        let caps = self.re.captures(haystack)?;
        let version = self.version.as_ref().and_then(|tmpl| render_version(tmpl, &caps));
        Some((self.confidence, version))
    }
}

/// Substitute `\1`..`\9` in a version template with capture groups. Returns
/// `None` when the result is empty (no usable version).
fn render_version(tmpl: &str, caps: &regex::Captures) -> Option<String> {
    let mut out = String::new();
    let bytes = tmpl.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let n = (bytes[i + 1] - b'0') as usize;
            if let Some(m) = caps.get(n) {
                out.push_str(m.as_str());
            }
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    let trimmed = out.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// One technology's compiled rule.
#[derive(Debug)]
struct Rule {
    name: String,
    categories: Vec<String>,
    headers: Vec<(String, Pattern)>,
    cookies: Vec<(String, Pattern)>,
    meta: Vec<(String, Pattern)>,
    html: Vec<Pattern>,
    script_src: Vec<Pattern>,
    implies: Vec<String>,
}

/// A detected technology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedTech {
    pub name: String,
    pub categories: Vec<String>,
    /// Extracted version, if any pattern carried a version capture that matched.
    pub version: Option<String>,
    /// Aggregate confidence 1..=100.
    pub confidence: u8,
    /// `true` when added via an `implies` edge (not matched directly).
    pub implied: bool,
}

/// A compiled technology database.
pub struct TechDb {
    rules: Vec<Rule>,
    /// Category id → name.
    categories: BTreeMap<u32, String>,
}

// --- Deserialization of the Wappalyzer schema -------------------------------

#[derive(Deserialize)]
#[serde(untagged)]
enum StrOrVec {
    One(String),
    Many(Vec<String>),
}

impl StrOrVec {
    fn into_vec(self) -> Vec<String> {
        match self {
            StrOrVec::One(s) => vec![s],
            StrOrVec::Many(v) => v,
        }
    }
}

#[derive(Deserialize, Default)]
struct RawTech {
    #[serde(default)]
    cats: Vec<u32>,
    #[serde(default)]
    headers: BTreeMap<String, StrOrVec>,
    #[serde(default)]
    cookies: BTreeMap<String, StrOrVec>,
    #[serde(default)]
    meta: BTreeMap<String, StrOrVec>,
    #[serde(default)]
    html: Option<StrOrVec>,
    #[serde(default, rename = "scriptSrc")]
    script_src: Option<StrOrVec>,
    #[serde(default)]
    implies: Option<StrOrVec>,
}

impl TechDb {
    /// The process-wide default database, compiled from [`DEFAULT_DB_JSON`] once.
    pub fn default_db() -> &'static TechDb {
        static DB: OnceLock<TechDb> = OnceLock::new();
        DB.get_or_init(|| TechDb::from_json(DEFAULT_DB_JSON).unwrap_or_else(|_| TechDb::empty()))
    }

    fn empty() -> TechDb {
        TechDb { rules: Vec::new(), categories: BTreeMap::new() }
    }

    /// Compile a database from a JSON string in Wappalyzer schema. Accepts both
    /// Camio's wrapper (`{categories, technologies}`) and a raw upstream
    /// `technologies.json` (the technologies map at the top level).
    pub fn from_json(json: &str) -> Result<TechDb, String> {
        let root: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("tech db: {e}"))?;

        // Category map (optional).
        let mut categories = BTreeMap::new();
        if let Some(cats) = root.get("categories").and_then(|c| c.as_object()) {
            for (k, v) in cats {
                if let (Ok(id), Some(name)) = (k.parse::<u32>(), v.as_str()) {
                    categories.insert(id, name.to_string());
                }
            }
        }

        // Technologies: wrapper `.technologies`, or the whole object.
        let tech_val = root.get("technologies").unwrap_or(&root);
        let raw: BTreeMap<String, RawTech> =
            serde_json::from_value(tech_val.clone()).map_err(|e| format!("tech db techs: {e}"))?;

        let mut rules = Vec::with_capacity(raw.len());
        for (name, t) in raw {
            if name.starts_with('_') {
                continue; // skip `_comment` etc.
            }
            let category_names = t
                .cats
                .iter()
                .map(|id| categories.get(id).cloned().unwrap_or_else(|| format!("cat:{id}")))
                .collect();
            let compile_map = |m: BTreeMap<String, StrOrVec>| -> Vec<(String, Pattern)> {
                m.into_iter()
                    .flat_map(|(k, v)| {
                        v.into_vec()
                            .into_iter()
                            .filter_map(move |s| Pattern::parse(&s).map(|p| (k.clone(), p)))
                            .collect::<Vec<_>>()
                    })
                    .collect()
            };
            let compile_list = |v: Option<StrOrVec>| -> Vec<Pattern> {
                v.map(StrOrVec::into_vec)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|s| Pattern::parse(&s))
                    .collect()
            };
            rules.push(Rule {
                name,
                categories: category_names,
                headers: compile_map(t.headers),
                cookies: compile_map(t.cookies),
                meta: compile_map(t.meta),
                html: compile_list(t.html),
                script_src: compile_list(t.script_src),
                implies: t.implies.map(StrOrVec::into_vec).unwrap_or_default(),
            });
        }
        Ok(TechDb { rules, categories: categories.clone() })
    }

    /// Number of technology rules loaded.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Detect every technology whose fingerprint appears in `resp`, resolving
    /// `implies` edges. Results are sorted: directly-detected first (by name),
    /// then implied.
    pub fn detect(&self, resp: &HttpResponse) -> Vec<DetectedTech> {
        let cookies: Vec<&str> = resp.headers.get_all("Set-Cookie").collect();
        let body: String = if is_texty(resp) {
            resp.body.as_text().into_owned()
        } else {
            String::new()
        };
        let script_srcs = extract_script_srcs(&body);
        let metas = extract_metas(&body);

        // name -> (confidence, version)
        let mut hits: BTreeMap<String, (u8, Option<String>)> = BTreeMap::new();

        for rule in &self.rules {
            let mut best: Option<(u8, Option<String>)> = None;
            let bump = |best: &mut Option<(u8, Option<String>)>, r: (u8, Option<String>)| {
                match best {
                    Some((c, v)) => {
                        *c = (*c).max(r.0);
                        if v.is_none() {
                            *v = r.1;
                        }
                    }
                    None => *best = Some(r),
                }
            };

            for (name, pat) in &rule.headers {
                for val in resp.headers.get_all(name) {
                    if let Some(r) = pat.test(val) {
                        bump(&mut best, r);
                    }
                }
            }
            for (cname, pat) in &rule.cookies {
                for raw in &cookies {
                    let (ck, cv) = raw.split_once('=').unwrap_or((raw, ""));
                    if ck.trim().eq_ignore_ascii_case(cname) {
                        // An empty value regex means "cookie present is enough".
                        if let Some(r) = pat.test(cv) {
                            bump(&mut best, r);
                        }
                    }
                }
            }
            for (mname, pat) in &rule.meta {
                if let Some(content) = metas.get(&mname.to_ascii_lowercase()) {
                    if let Some(r) = pat.test(content) {
                        bump(&mut best, r);
                    }
                }
            }
            if !body.is_empty() {
                for pat in &rule.html {
                    if let Some(r) = pat.test(&body) {
                        bump(&mut best, r);
                    }
                }
            }
            for pat in &rule.script_src {
                for src in &script_srcs {
                    if let Some(r) = pat.test(src) {
                        bump(&mut best, r);
                    }
                }
            }

            if let Some(r) = best {
                hits.insert(rule.name.clone(), r);
            }
        }

        // Resolve implies transitively (bounded).
        let direct: Vec<String> = hits.keys().cloned().collect();
        let mut queue = direct.clone();
        let mut implied: BTreeMap<String, ()> = BTreeMap::new();
        let rule_by_name = |n: &str| self.rules.iter().find(|r| r.name == n);
        while let Some(name) = queue.pop() {
            if let Some(rule) = rule_by_name(&name) {
                for imp in &rule.implies {
                    if !hits.contains_key(imp) && !implied.contains_key(imp) {
                        implied.insert(imp.clone(), ());
                        queue.push(imp.clone());
                    }
                }
            }
        }

        let cat_of = |n: &str| rule_by_name(n).map(|r| r.categories.clone()).unwrap_or_default();

        let mut out: Vec<DetectedTech> = Vec::new();
        for (name, (conf, version)) in &hits {
            out.push(DetectedTech {
                name: name.clone(),
                categories: cat_of(name),
                version: version.clone(),
                confidence: (*conf).max(1),
                implied: false,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        let mut implied_vec: Vec<DetectedTech> = implied
            .keys()
            .map(|name| DetectedTech {
                name: name.clone(),
                categories: cat_of(name),
                version: None,
                confidence: 50,
                implied: true,
            })
            .collect();
        implied_vec.sort_by(|a, b| a.name.cmp(&b.name));
        out.extend(implied_vec);
        out
    }

    /// The category-id → name map (for callers that render categories).
    pub fn categories(&self) -> &BTreeMap<u32, String> {
        &self.categories
    }
}

fn is_texty(resp: &HttpResponse) -> bool {
    resp.headers
        .get("Content-Type")
        .map(|ct| {
            let ct = ct.to_ascii_lowercase();
            ct.starts_with("text/") || ct.contains("html") || ct.contains("xml") || ct.contains("json")
        })
        .unwrap_or(false)
}

/// Extract `src` values of `<script>` tags from an HTML body.
fn extract_script_srcs(body: &str) -> Vec<String> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let re = RE
        .get_or_init(|| Regex::new(r#"(?is)<script\b[^>]*\bsrc\s*=\s*["']?([^"'> ]+)"#).ok())
        .as_ref();
    match re {
        Some(re) => re
            .captures_iter(body)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect(),
        None => Vec::new(),
    }
}

/// Extract `<meta name=.. content=..>` pairs, keyed by lowercase meta name.
fn extract_metas(body: &str) -> BTreeMap<String, String> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let re = RE
        .get_or_init(|| {
            Regex::new(
                r#"(?is)<meta\b[^>]*?\bname\s*=\s*["']?([a-z0-9:-]+)["']?[^>]*?\bcontent\s*=\s*["']([^"']*)["']"#,
            )
            .ok()
        })
        .as_ref();
    let mut out = BTreeMap::new();
    if let Some(re) = re {
        for c in re.captures_iter(body) {
            if let (Some(n), Some(v)) = (c.get(1), c.get(2)) {
                out.entry(n.as_str().to_ascii_lowercase())
                    .or_insert_with(|| v.as_str().to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpResponse, HttpVersion};

    fn resp(headers: &[(&str, &str)], body: &str) -> HttpResponse {
        let mut h = HeaderList::new();
        h.push("Content-Type", "text/html");
        for (k, v) in headers {
            h.push(*k, *v);
        }
        HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(body),
        }
    }

    #[test]
    fn default_db_compiles_with_many_rules() {
        let db = TechDb::default_db();
        assert!(db.len() >= 40, "expected a sizable ruleset, got {}", db.len());
        assert!(!db.categories().is_empty());
    }

    #[test]
    fn detects_nginx_with_version() {
        let db = TechDb::default_db();
        let hits = db.detect(&resp(&[("Server", "nginx/1.25.3")], ""));
        let nginx = hits.iter().find(|t| t.name == "Nginx").expect("nginx");
        assert_eq!(nginx.version.as_deref(), Some("1.25.3"));
        assert!(nginx.categories.iter().any(|c| c == "Web Server"));
    }

    #[test]
    fn next_js_implies_react_and_node() {
        let db = TechDb::default_db();
        let hits = db.detect(&resp(&[("X-Powered-By", "Next.js 14.1.0")], ""));
        let next = hits.iter().find(|t| t.name == "Next.js").expect("next.js");
        assert_eq!(next.version.as_deref(), Some("14.1.0"));
        assert!(!next.implied);
        // React + Node.js come in via implies.
        let react = hits.iter().find(|t| t.name == "React").expect("react implied");
        assert!(react.implied);
        assert!(hits.iter().any(|t| t.name == "Node.js" && t.implied));
    }

    #[test]
    fn detects_wordpress_from_meta_generator_with_version() {
        let db = TechDb::default_db();
        let body = r#"<meta name="generator" content="WordPress 6.4.2" />"#;
        let hits = db.detect(&resp(&[], body));
        let wp = hits.iter().find(|t| t.name == "WordPress").expect("wordpress");
        assert_eq!(wp.version.as_deref(), Some("6.4.2"));
        // WordPress implies PHP + MySQL.
        assert!(hits.iter().any(|t| t.name == "PHP" && t.implied));
    }

    #[test]
    fn detects_jquery_version_from_script_src() {
        let db = TechDb::default_db();
        let body = r#"<script src="/assets/jquery-3.6.0.min.js"></script>"#;
        let hits = db.detect(&resp(&[], body));
        let jq = hits.iter().find(|t| t.name == "jQuery").expect("jquery");
        assert_eq!(jq.version.as_deref(), Some("3.6.0"));
    }

    #[test]
    fn version_template_renders_capture_groups() {
        let caps = Regex::new(r"v(\d+)\.(\d+)").unwrap().captures("v3.6").unwrap();
        assert_eq!(render_version(r"\1.\2", &caps).as_deref(), Some("3.6"));
        assert_eq!(render_version(r"MVC \1", &caps).as_deref(), Some("MVC 3"));
    }

    #[test]
    fn clean_response_detects_nothing() {
        let db = TechDb::default_db();
        assert!(db.detect(&resp(&[("Server", "unknown-xyz")], "<html></html>")).is_empty());
    }

    #[test]
    fn can_load_a_raw_wappalyzer_map() {
        // A raw upstream-style map (no wrapper) must also compile.
        let json = r#"{ "Acme": { "cats": [22], "headers": { "Server": "acme/([\\d.]+)\\;version:\\1" } } }"#;
        let db = TechDb::from_json(json).unwrap();
        assert_eq!(db.len(), 1);
        let hits = db.detect(&resp(&[("Server", "acme/2.0")], ""));
        assert_eq!(hits[0].name, "Acme");
        assert_eq!(hits[0].version.as_deref(), Some("2.0"));
    }
}
