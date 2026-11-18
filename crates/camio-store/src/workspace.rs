use super::report::{safe_rule, ReportEntry};
use super::{now_ms, FindingReport, Store};
use anyhow::{ensure, Result};
use camio_core::{ExchangeId, Finding, FindingId, Project, ProjectId, Query};
use rusqlite::{params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

pub(super) const SCHEMA: &str = r#"
CREATE TABLE workspace (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    name TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE saved_queries (
    name TEXT PRIMARY KEY,
    expression TEXT NOT NULL
);
CREATE TABLE saved_exchanges (
    exchange_id INTEGER PRIMARY KEY REFERENCES exchanges(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    note TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE finding_reviews (
    finding_id INTEGER PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('open','confirmed','resolved','dismissed')),
    note TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE passive_keys (
    key TEXT PRIMARY KEY,
    finding_id INTEGER UNIQUE NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    rule TEXT NOT NULL,
    last_seen_at_ms INTEGER NOT NULL
);
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSummary {
    pub project: Project,
    pub exchanges: i64,
    pub findings: i64,
    pub open_findings: i64,
    pub artifacts: i64,
    pub saved_exchanges: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SavedQuery {
    pub name: String,
    pub expression: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SavedExchange {
    pub id: ExchangeId,
    pub label: String,
    pub note: String,
    pub method: String,
    pub url: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    #[default]
    Open,
    Confirmed,
    Resolved,
    Dismissed,
}

impl ReviewState {
    pub const ALL: [Self; 4] = [Self::Open, Self::Confirmed, Self::Resolved, Self::Dismissed];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Confirmed => "confirmed",
            Self::Resolved => "resolved",
            Self::Dismissed => "dismissed",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindingReview {
    #[serde(flatten)]
    pub finding: Finding,
    pub state: ReviewState,
    pub note: String,
    pub rule: Option<String>,
    pub last_seen_at_ms: i64,
}

const FINDINGS: &str = "
    SELECT f.id, f.data_json, r.state, r.note, k.rule, COALESCE(k.last_seen_at_ms, f.created_at_ms)
    FROM findings f LEFT JOIN finding_reviews r ON r.finding_id = f.id
    LEFT JOIN passive_keys k ON k.finding_id = f.id";
const SEVERITY_ORDER: &str = "
    ORDER BY CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4
             WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC, f.id DESC";

impl Store {
    pub fn workspace(&self) -> Result<WorkspaceSummary> {
        Ok(self.conn.query_row(
            "SELECT COALESCE((SELECT name FROM workspace WHERE id = 1), 'Local workspace'),
                   COALESCE((SELECT created_at_ms FROM workspace WHERE id = 1), 0),
                   (SELECT count(*) FROM exchanges), (SELECT count(*) FROM findings),
                   (SELECT count(*) FROM findings f LEFT JOIN finding_reviews r ON r.finding_id = f.id
                    WHERE r.state IS NULL OR r.state = 'open'),
                   (SELECT count(*) FROM evidence_artifacts), (SELECT count(*) FROM saved_exchanges)",
            [],
            |row| Ok(WorkspaceSummary {
                project: Project {
                    id: ProjectId(1),
                    name: row.get(0)?,
                    profile: None,
                    created_at_ms: row.get(1)?,
                },
                exchanges: row.get(2)?,
                findings: row.get(3)?,
                open_findings: row.get(4)?,
                artifacts: row.get(5)?,
                saved_exchanges: row.get(6)?,
            }),
        )?)
    }

    pub fn rename_workspace(&self, name: &str) -> Result<()> {
        let name = name.trim();
        ensure!(
            !name.is_empty() && name.len() <= 120 && !name.contains(char::is_control),
            "enter a workspace name of up to 120 bytes"
        );
        self.conn.execute(
            "INSERT INTO workspace (id, name, created_at_ms) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name",
            params![name, now_ms()],
        )?;
        Ok(())
    }

    pub fn save_query(&self, name: &str, expression: &str) -> Result<()> {
        let name = name.trim();
        let expression = expression.trim();
        ensure!(
            !name.is_empty() && name.len() <= 100 && !name.contains(char::is_control),
            "enter a query name of up to 100 bytes"
        );
        ensure!(
            !expression.is_empty() && expression.len() <= 1024,
            "enter a CamioQL filter of up to 1024 bytes"
        );
        Query::compile(expression)?;
        let changed = self.conn.execute(
            "INSERT INTO saved_queries (name, expression)
             SELECT ?1, ?2 WHERE (SELECT count(*) FROM saved_queries) < 200
                OR EXISTS (SELECT 1 FROM saved_queries WHERE name = ?1)
             ON CONFLICT(name) DO UPDATE SET expression = excluded.expression",
            params![name, expression],
        )?;
        ensure!(
            changed == 1,
            "remove a saved query to make room for another"
        );
        Ok(())
    }

    pub fn saved_queries(&self) -> Result<Vec<SavedQuery>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, expression FROM saved_queries ORDER BY name COLLATE NOCASE")?;
        let rows = stmt.query_map([], |row| {
            Ok(SavedQuery {
                name: row.get(0)?,
                expression: row.get(1)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn delete_query(&self, name: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM saved_queries WHERE name = ?1", [name])?;
        Ok(())
    }

    pub fn save_exchange(&self, id: ExchangeId, label: &str, note: &str) -> Result<()> {
        ensure!(
            label.len() <= 120 && note.len() <= 4096,
            "labels support 120 bytes and notes support 4096 bytes"
        );
        let changed = self.conn.execute(
            "INSERT INTO saved_exchanges (exchange_id, label, note, updated_at_ms)
             SELECT id, ?2, ?3, ?4 FROM exchanges WHERE id = ?1
             ON CONFLICT(exchange_id) DO UPDATE SET label = excluded.label, note = excluded.note,
                                                    updated_at_ms = excluded.updated_at_ms",
            params![id.0, label.trim(), note.trim(), now_ms()],
        )?;
        ensure!(changed == 1, "exchange was not found");
        Ok(())
    }

    pub fn saved_exchanges(&self, offset: usize) -> Result<Vec<SavedExchange>> {
        let mut stmt = self.conn.prepare(
            "SELECT e.id, s.label, s.note, e.method, e.url FROM saved_exchanges s
             JOIN exchanges e ON e.id = s.exchange_id
             ORDER BY s.updated_at_ms DESC, e.id DESC LIMIT 100 OFFSET ?1",
        )?;
        let rows = stmt.query_map([offset as i64], |row| {
            Ok(SavedExchange {
                id: ExchangeId(row.get(0)?),
                label: row.get(1)?,
                note: row.get(2)?,
                method: row.get(3)?,
                url: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn saved_exchange(&self, id: ExchangeId) -> Result<Option<SavedExchange>> {
        Ok(self
            .conn
            .query_row(
                "SELECT s.label, s.note, e.method, e.url FROM saved_exchanges s
             JOIN exchanges e ON e.id = s.exchange_id WHERE e.id = ?1",
                [id.0],
                |row| {
                    Ok(SavedExchange {
                        id,
                        label: row.get(0)?,
                        note: row.get(1)?,
                        method: row.get(2)?,
                        url: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn delete_saved_exchange(&self, id: ExchangeId) -> Result<()> {
        self.conn
            .execute("DELETE FROM saved_exchanges WHERE exchange_id = ?1", [id.0])?;
        Ok(())
    }

    pub fn finding_reviews(
        &self,
        state: Option<ReviewState>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<FindingReview>> {
        let sql = format!("{FINDINGS} WHERE ?1 IS NULL OR COALESCE(r.state, 'open') = ?1 {SEVERITY_ORDER} LIMIT ?2 OFFSET ?3");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query(params![
            state.map(ReviewState::as_str),
            limit.min(200) as i64,
            offset as i64
        ])?;
        let mut output = Vec::new();
        while let Some(row) = rows.next()? {
            output.push(read_finding(row)?);
        }
        Ok(output)
    }

    pub fn finding_review(&self, id: FindingId) -> Result<Option<FindingReview>> {
        let sql = format!("{FINDINGS} WHERE f.id = ?1");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([id.0])?;
        rows.next()?.map(read_finding).transpose()
    }

    pub fn update_finding_review(
        &self,
        id: FindingId,
        state: ReviewState,
        note: &str,
    ) -> Result<()> {
        let note = note.trim();
        ensure!(note.len() <= 4096, "notes support up to 4096 bytes");
        ensure!(
            state != ReviewState::Dismissed || !note.is_empty(),
            "add a reason before dismissing this finding"
        );
        let changed = self.conn.execute(
            "INSERT INTO finding_reviews (finding_id, state, note, updated_at_ms)
             SELECT id, ?2, ?3, ?4 FROM findings WHERE id = ?1
             ON CONFLICT(finding_id) DO UPDATE SET state = excluded.state, note = excluded.note,
                                                   updated_at_ms = excluded.updated_at_ms",
            params![id.0, state.as_str(), note, now_ms()],
        )?;
        ensure!(changed == 1, "finding was not found");
        Ok(())
    }

    pub fn finding_report(&self, state: Option<ReviewState>) -> Result<FindingReport> {
        // Project only fields allowed in the report, preserving stable ordering.
        let sql = format!(
            "SELECT f.id, f.severity, f.confidence, COALESCE(r.state, 'open'), k.rule,
                    COALESCE(json_extract(f.data_json, '$.evidence'), '[]')
             FROM findings f LEFT JOIN finding_reviews r ON r.finding_id = f.id
             LEFT JOIN passive_keys k ON k.finding_id = f.id
             WHERE ?1 IS NULL OR COALESCE(r.state, 'open') = ?1 {SEVERITY_ORDER} LIMIT 10001"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([state.map(ReviewState::as_str)])?;
        let mut findings = Vec::new();
        while let Some(row) = rows.next()? {
            ensure!(
                findings.len() < 10_000,
                "the report exceeds 10,000 findings; select a review status"
            );
            let severity: String = row.get(1)?;
            let confidence: String = row.get(2)?;
            let state: String = row.get(3)?;
            let evidence: String = row.get(5)?;
            findings.push(ReportEntry {
                id: Some(FindingId(row.get(0)?)),
                rule: safe_rule(row.get(4)?),
                severity: serde_json::from_value(serde_json::Value::String(severity))?,
                confidence: serde_json::from_value(serde_json::Value::String(confidence))?,
                state: Some(serde_json::from_value(serde_json::Value::String(state))?),
                evidence: serde_json::from_str(&evidence)?,
            });
        }
        Ok(FindingReport {
            schema_version: 1,
            run: None,
            findings,
        })
    }

    /// Create a consistent SQLite snapshot of a workspace, including committed
    /// changes in its WAL. The destination must be a new file.
    pub fn backup_to(&self, destination: &std::path::Path) -> Result<()> {
        ensure!(!destination.try_exists()?, "choose a new backup path");
        let path = destination
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("backup path must be valid UTF-8"))?;
        self.conn.execute("VACUUM INTO ?1", [path])?;
        Ok(())
    }
}

fn read_finding(row: &Row<'_>) -> Result<FindingReview> {
    let data: String = row.get(1)?;
    let mut finding: Finding = serde_json::from_str(&data)?;
    finding.id = FindingId(row.get(0)?);
    let state: Option<String> = row.get(2)?;
    let state = state
        .map(|s| serde_json::from_value(serde_json::Value::String(s)))
        .transpose()?
        .unwrap_or_default();
    Ok(FindingReview {
        finding,
        state,
        note: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
        rule: row.get(4)?,
        last_seen_at_ms: row.get(5)?,
    })
}
