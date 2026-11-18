use super::{inventory, now_ms, sha256_hex, Store};
use anyhow::{ensure, Result};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
const MAX_LINE: usize = 1024 * 1024;

pub(super) const SCHEMA: &str = r#"
CREATE TABLE evidence_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    format TEXT NOT NULL,
    version TEXT,
    sha256 TEXT NOT NULL,
    raw TEXT NOT NULL,
    imported_at_ms INTEGER NOT NULL,
    records INTEGER NOT NULL,
    skipped INTEGER NOT NULL,
    UNIQUE(format, sha256)
);
CREATE TABLE observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id INTEGER NOT NULL REFERENCES evidence_artifacts(id) ON DELETE CASCADE,
    line INTEGER NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX observations_by_artifact ON observations(artifact_id, id DESC);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    Httpx,
    Nuclei,
    Raw,
}

impl ArtifactFormat {
    pub const ALL: [Self; 3] = [Self::Httpx, Self::Nuclei, Self::Raw];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Httpx => "httpx",
            Self::Nuclei => "nuclei",
            Self::Raw => "raw",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Httpx => "ProjectDiscovery httpx JSONL",
            Self::Nuclei => "Nuclei JSONL",
            Self::Raw => "Raw evidence (text)",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactSummary {
    pub id: i64,
    pub format: String,
    pub version: Option<String>,
    pub sha256: String,
    pub imported_at_ms: i64,
    pub records: usize,
    pub skipped: usize,
}

#[derive(Debug, Serialize)]
pub struct ArtifactImport {
    pub format: ArtifactFormat,
    pub sha256: String,
    pub artifact_id: Option<i64>,
    pub existing: bool,
    pub records: usize,
    pub skipped: usize,
    pub warnings: Vec<String>,
    pub sample: Vec<Observation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub line: usize,
    pub location: String,
    pub title: Option<String>,
    pub outcome: String,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub server: Option<String>,
    pub technologies: Vec<String>,
    pub template: Option<String>,
    pub matcher: Option<String>,
    pub severity: Option<String>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservationPage {
    pub observations: Vec<Observation>,
    pub next_before: Option<i64>,
}

impl Store {
    /// Preview or store an already collected artifact. Parsing never calls a
    /// subprocess or fetches a location from the artifact.
    pub fn import_artifact(
        &mut self,
        format: ArtifactFormat,
        raw: &str,
        version: Option<&str>,
        save: bool,
    ) -> Result<ArtifactImport> {
        ensure!(
            !raw.trim().is_empty() && raw.len() <= ARTIFACT_BYTES,
            "select text evidence of up to 4 MiB"
        );
        let version = version.map(str::trim).filter(|v| !v.is_empty());
        ensure!(
            !matches!(version, Some(v) if v.len() > 120 || v.contains(char::is_control)),
            "tool versions support up to 120 bytes"
        );
        let mut observations = Vec::new();
        let mut warnings = Vec::new();
        let mut skipped = 0;
        if format != ArtifactFormat::Raw {
            for (offset, line) in raw.trim_start_matches('\u{feff}').lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let number = offset + 1;
                let parsed = if line.len() > MAX_LINE {
                    Err("record exceeds the 1 MiB line limit")
                } else {
                    serde_json::from_str::<Value>(line)
                        .map_err(|_| "invalid JSON")
                        .and_then(|value| parse_observation(format, number, &value))
                };
                match parsed {
                    Ok(record) => observations.push(record),
                    Err(reason) => {
                        skipped += 1;
                        if warnings.len() < 30 {
                            warnings.push(format!("Line {number}: {reason}"));
                        }
                    }
                }
            }
        }
        let sha256 = sha256_hex(raw.as_bytes());
        let mut artifact_id = None;
        let mut existing = false;
        if save {
            let tx = self.conn.transaction()?;
            let imported_at = now_ms();
            let changed = tx.execute(
                "INSERT INTO evidence_artifacts (format, version, sha256, raw, imported_at_ms, records, skipped)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(format, sha256) DO NOTHING",
                params![format.as_str(), version, sha256, raw, imported_at, observations.len() as i64, skipped as i64],
            )?;
            let id: i64 = tx.query_row(
                "SELECT id FROM evidence_artifacts WHERE format = ?1 AND sha256 = ?2",
                params![format.as_str(), sha256],
                |row| row.get(0),
            )?;
            existing = changed == 0;
            if !existing {
                let mut stmt = tx.prepare(
                    "INSERT INTO observations (artifact_id, line, data_json) VALUES (?1, ?2, ?3)",
                )?;
                for observation in &observations {
                    stmt.execute(params![
                        id,
                        observation.line as i64,
                        serde_json::to_string(observation)?
                    ])?;
                    inventory::index_observation(
                        &tx,
                        tx.last_insert_rowid(),
                        &observation.location,
                        format.as_str(),
                        imported_at,
                    )?;
                }
            }
            tx.commit()?;
            artifact_id = Some(id);
        }
        Ok(ArtifactImport {
            format,
            sha256,
            artifact_id,
            existing,
            records: observations.len(),
            skipped,
            warnings,
            sample: observations.into_iter().take(10).collect(),
        })
    }

    pub fn artifacts(&self, before: Option<i64>) -> Result<Vec<ArtifactSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, format, version, sha256, imported_at_ms, records, skipped
             FROM evidence_artifacts WHERE id < ?1 ORDER BY id DESC LIMIT 50",
        )?;
        let rows = stmt.query_map([before.unwrap_or(i64::MAX)], |row| {
            Ok(ArtifactSummary {
                id: row.get(0)?,
                format: row.get(1)?,
                version: row.get(2)?,
                sha256: row.get(3)?,
                imported_at_ms: row.get(4)?,
                records: row.get::<_, i64>(5)? as usize,
                skipped: row.get::<_, i64>(6)? as usize,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn artifact_text(&self, id: i64) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT raw FROM evidence_artifacts WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn observations(&self, artifact: i64, before: Option<i64>) -> Result<ObservationPage> {
        let mut stmt = self.conn.prepare(
            "SELECT id, data_json FROM observations WHERE artifact_id = ?1 AND id < ?2 ORDER BY id DESC LIMIT 51",
        )?;
        let mut rows = stmt.query(params![artifact, before.unwrap_or(i64::MAX)])?;
        let mut observations = Vec::new();
        let mut cursor = None;
        while let Some(row) = rows.next()? {
            if observations.len() == 50 {
                return Ok(ObservationPage {
                    observations,
                    next_before: cursor,
                });
            }
            let data: String = row.get(1)?;
            observations.push(serde_json::from_str(&data)?);
            cursor = Some(row.get(0)?);
        }
        Ok(ObservationPage {
            observations,
            next_before: None,
        })
    }
}

fn parse_observation(
    format: ArtifactFormat,
    line: usize,
    data: &Value,
) -> Result<Observation, &'static str> {
    let locations: &[&str] = match format {
        ArtifactFormat::Httpx => &["url", "input"],
        ArtifactFormat::Nuclei => &["matched-at", "url", "host"],
        ArtifactFormat::Raw => return Err("opaque evidence has no structured observations"),
    };
    let location = locations
        .iter()
        .filter_map(|k| data.get(k).and_then(Value::as_str))
        .find_map(observed_url)
        .ok_or("record has no HTTP or HTTPS URL")?;
    let mut observation = Observation {
        line,
        location,
        title: None,
        outcome: String::new(),
        status: None,
        content_type: None,
        content_length: None,
        server: None,
        technologies: Vec::new(),
        template: None,
        matcher: None,
        severity: None,
        timestamp: field(data, "timestamp"),
    };
    match format {
        ArtifactFormat::Httpx => {
            observation.title = field(data, "title");
            observation.status = number(data, "status_code", "status-code")
                .and_then(|x| u16::try_from(x).ok())
                .filter(|x| (100..=599).contains(x));
            observation.content_type =
                field(data, "content_type").or_else(|| field(data, "content-type"));
            observation.content_length = number(data, "content_length", "content-length");
            observation.server = field(data, "webserver");
            observation.technologies = data["tech"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .take(24)
                .map(display_text)
                .collect();
            observation.outcome = if data["failed"].as_bool() == Some(true) {
                "probe failed"
            } else {
                "probe result"
            }
            .into();
        }
        ArtifactFormat::Nuclei => {
            observation.template = Some(field(data, "template-id").ok_or("missing template ID")?);
            observation.matcher = field(data, "matcher-name");
            observation.title = field(&data["info"], "name");
            observation.severity = field(&data["info"], "severity")
                .map(|value| value.to_ascii_lowercase())
                .filter(|value| {
                    matches!(
                        value.as_str(),
                        "info" | "low" | "medium" | "high" | "critical" | "unknown"
                    )
                });
            observation.outcome = match data["matcher-status"].as_bool() {
                _ if data["error"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty()) =>
                {
                    "tool error"
                }
                Some(false) => "no match",
                _ => "unverified observation",
            }
            .into();
        }
        ArtifactFormat::Raw => unreachable!("raw reports are never parsed"),
    }
    Ok(observation)
}

fn observed_url(value: &str) -> Option<String> {
    if value.len() > 8192 {
        return None;
    }
    let mut url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") || !url.has_host() {
        return None;
    }
    url.set_username("").ok()?;
    url.set_password(None).ok()?;
    url.set_query(None);
    url.set_fragment(None);
    Some(url.into())
}

fn field(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)?
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .map(display_text)
}

fn number(value: &Value, current: &str, legacy: &str) -> Option<u64> {
    value[current].as_u64().or_else(|| value[legacy].as_u64())
}

fn display_text(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_control())
        .take(240)
        .collect()
}
