//! Software Bill of Materials generation (plan §F26 packaging/SBOM).
//!
//! Emits a CycloneDX 1.5 JSON SBOM of the workspace's resolved dependency graph.
//! The source of truth is `Cargo.lock`, embedded at compile time so `camio sbom`
//! always describes *this* build (a `--lock` override regenerates for any other
//! lockfile). The lockfile is parsed by hand — its format is canonical and
//! line-oriented (cargo always writes one quoted `key = "value"` per line), so a
//! full TOML dependency is not warranted (plan §14 "prefer std / hand-rolling").
//!
//! Scope and honesty: a lockfile carries each crate's name, version, source, and
//! registry checksum — enough for a precise component inventory with package URLs
//! and SHA-256 hashes. It does **not** carry license text; a license inventory
//! needs `cargo metadata` at build time and is left to the release pipeline. The
//! SBOM says so in its metadata rather than inventing license fields.

use serde_json::{json, Value};

/// The workspace lockfile, embedded so the SBOM matches the compiled binary.
pub const EMBEDDED_LOCK: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));

/// One resolved package from the lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    /// `None` for a workspace-local (path) crate; `Some` for registry/git.
    pub source: Option<String>,
    /// Registry checksum (SHA-256 of the `.crate`), when present.
    pub checksum: Option<String>,
}

impl Package {
    /// Package URL (purl) for this crate, e.g. `pkg:cargo/serde@1.0.0`.
    pub fn purl(&self) -> String {
        format!("pkg:cargo/{}@{}", self.name, self.version)
    }

    /// Whether this is a workspace-local crate (no registry/git source).
    pub fn is_local(&self) -> bool {
        self.source.is_none()
    }
}

/// Extract the string value of a canonical `key = "value"` lockfile line, if the
/// (unindented) line declares exactly that key.
fn scalar<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?.strip_prefix(" = ")?;
    rest.strip_prefix('"')?.strip_suffix('"')
}

/// Parse a `Cargo.lock` into its packages, in file order. Tolerant: unknown keys
/// and the multi-line `dependencies = [ … ]` arrays are ignored, and a block
/// without a name is skipped rather than erroring.
pub fn parse_lock(text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut cur: Option<Package> = None;
    for line in text.lines() {
        if line == "[[package]]" {
            if let Some(p) = cur.take() {
                if !p.name.is_empty() {
                    out.push(p);
                }
            }
            cur = Some(Package {
                name: String::new(),
                version: String::new(),
                source: None,
                checksum: None,
            });
            continue;
        }
        let Some(pkg) = cur.as_mut() else { continue };
        if let Some(v) = scalar(line, "name") {
            pkg.name = v.to_string();
        } else if let Some(v) = scalar(line, "version") {
            pkg.version = v.to_string();
        } else if let Some(v) = scalar(line, "source") {
            pkg.source = Some(v.to_string());
        } else if let Some(v) = scalar(line, "checksum") {
            pkg.checksum = Some(v.to_string());
        }
    }
    if let Some(p) = cur.take() {
        if !p.name.is_empty() {
            out.push(p);
        }
    }
    out
}

/// Build a CycloneDX 1.5 document for `packages`, naming `root_name`/`root_version`
/// as the subject component. Workspace-local crates and the root itself are kept
/// as components too (they are part of the delivered artifact), each with a purl;
/// registry crates additionally carry their SHA-256 hash.
pub fn cyclonedx(packages: &[Package], root_name: &str, root_version: &str) -> Value {
    let components: Vec<Value> = packages
        .iter()
        .filter(|p| !(p.name == root_name && p.version == root_version))
        .map(|p| {
            let mut c = json!({
                "type": "library",
                "name": p.name,
                "version": p.version,
                "purl": p.purl(),
                "scope": "required",
            });
            if let Some(sum) = &p.checksum {
                c["hashes"] = json!([{ "alg": "SHA-256", "content": sum }]);
            }
            if p.is_local() {
                // A path crate from this workspace, not a published dependency.
                c["properties"] = json!([{ "name": "cdx:cargo:source", "value": "workspace" }]);
            }
            c
        })
        .collect();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": root_name,
                "version": root_version,
                "purl": format!("pkg:cargo/{root_name}@{root_version}"),
            },
            "tools": [{ "vendor": "Cyber Sec", "name": "camio", "version": root_version }],
            "properties": [{
                "name": "camio:sbom:note",
                "value": "Components and hashes are from Cargo.lock; license inventory requires cargo metadata and is produced by the release pipeline, not this lockfile-only SBOM."
            }],
        },
        "components": components,
    })
}

/// Generate the CycloneDX SBOM for the given lockfile text (or the embedded one).
pub fn generate(lock_text: &str, root_name: &str, root_version: &str) -> Value {
    cyclonedx(&parse_lock(lock_text), root_name, root_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "camio-cli"
version = "0.4.1"
dependencies = [
 "anyhow",
 "serde",
]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef"
"#;

    #[test]
    fn parses_packages_with_and_without_source() {
        let pkgs = parse_lock(SAMPLE);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "camio-cli");
        assert!(pkgs[0].is_local(), "workspace crate has no registry source");
        assert_eq!(pkgs[1].name, "serde");
        assert_eq!(pkgs[1].version, "1.0.200");
        assert_eq!(pkgs[1].checksum.as_deref(), Some("deadbeef"));
        assert_eq!(pkgs[1].purl(), "pkg:cargo/serde@1.0.200");
    }

    #[test]
    fn cyclonedx_is_well_formed_and_excludes_the_root() {
        let doc = generate(SAMPLE, "camio-cli", "0.4.1");
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.5");
        assert_eq!(doc["metadata"]["component"]["name"], "camio-cli");
        let comps = doc["components"].as_array().unwrap();
        // The root crate is the subject, not a component of itself.
        assert!(!comps.iter().any(|c| c["name"] == "camio-cli"));
        let serde = comps.iter().find(|c| c["name"] == "serde").unwrap();
        assert_eq!(serde["purl"], "pkg:cargo/serde@1.0.200");
        assert_eq!(serde["hashes"][0]["alg"], "SHA-256");
        assert_eq!(serde["hashes"][0]["content"], "deadbeef");
    }

    #[test]
    fn the_embedded_lockfile_parses_into_many_packages() {
        // The real workspace lock must parse (guards the include_str path and the
        // parser against the actual file, not just the sample).
        let pkgs = parse_lock(EMBEDDED_LOCK);
        assert!(pkgs.len() > 100, "parsed only {} packages", pkgs.len());
        assert!(pkgs.iter().any(|p| p.name == "camio-cli"));
        // Every parsed package has a non-empty name and version.
        assert!(pkgs.iter().all(|p| !p.name.is_empty() && !p.version.is_empty()));
    }
}
