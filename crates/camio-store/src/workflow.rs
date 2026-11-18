use super::{now_ms, Store};
use anyhow::{ensure, Context, Result};
use camio_core::Query;
use rusqlite::{params, OptionalExtension, Row, TransactionBehavior};
use serde::{Deserialize, Serialize};

pub const MAX_REVIEW_EXCHANGES: usize = 1000;

pub(super) const SCHEMA: &str = r#"
CREATE TABLE review_workflows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);
CREATE TABLE review_workflow_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id INTEGER NOT NULL REFERENCES review_workflows(id),
    version INTEGER NOT NULL CHECK (version > 0),
    plan_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    UNIQUE(workflow_id, version)
);
ALTER TABLE review_tasks ADD COLUMN workflow_revision INTEGER REFERENCES review_workflow_versions(id);
"#;

/// The editable document for a review of locally stored HTTP exchanges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPlan {
    pub schema_version: u8,
    pub query: String,
    pub limit: usize,
    pub save: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_ids: Option<Vec<String>>,
}

impl ReviewPlan {
    pub fn new(query: &str, limit: usize, save: bool) -> Self {
        Self {
            schema_version: 1,
            query: query.trim().into(),
            limit,
            save,
            check_ids: None,
        }
    }

    pub fn compile(&self) -> Result<Query> {
        match (self.schema_version, &self.check_ids) {
            (1, None) => {}
            (2, Some(checks)) => {
                ensure!(
                    (1..=128).contains(&checks.len()),
                    "select at least one passive check"
                );
                ensure!(
                    checks.iter().all(|id| (1..=80).contains(&id.len())
                        && id.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                        })),
                    "passive check IDs must use lowercase letters, numbers, or hyphens"
                );
                let unique: std::collections::BTreeSet<_> = checks.iter().collect();
                ensure!(
                    unique.len() == checks.len(),
                    "passive check IDs must be unique"
                );
            }
            _ => anyhow::bail!(
                "use schema version 1 for all passive checks or version 2 with check_ids"
            ),
        }
        ensure!(
            self.query.len() <= 1024,
            "CamioQL filters support up to 1024 bytes"
        );
        ensure!(
            (1..=MAX_REVIEW_EXCHANGES).contains(&self.limit),
            "enter an exchange limit from 1 to {MAX_REVIEW_EXCHANGES}"
        );
        Query::compile(self.query.trim()).context("invalid CamioQL")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowVersion {
    pub id: i64,
    pub name: String,
    pub version: i64,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewWorkflow {
    #[serde(flatten)]
    pub revision: WorkflowVersion,
    pub plan: ReviewPlan,
    #[serde(skip)]
    pub(super) revision_id: i64,
}

const SELECT: &str = "SELECT w.id, w.name, v.version, v.created_at_ms, v.plan_json, v.id
    FROM review_workflows w JOIN review_workflow_versions v ON v.workflow_id = w.id";

impl Store {
    /// Save an immutable version under a named workflow. Retrying the same
    /// document returns its current version without adding another entry.
    pub fn save_review_workflow(
        &mut self,
        name: &str,
        plan: &ReviewPlan,
    ) -> Result<ReviewWorkflow> {
        let name = name.trim();
        ensure!(
            !name.is_empty() && name.len() <= 100 && !name.contains(char::is_control),
            "enter a workflow name of up to 100 bytes"
        );
        plan.compile()?;
        let mut plan = plan.clone();
        plan.query = plan.query.trim().to_owned();
        if let Some(checks) = plan.check_ids.as_mut() {
            checks.sort();
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        tx.execute(
            "INSERT INTO review_workflows(name)
             SELECT ?1 WHERE (SELECT count(*) FROM review_workflows) < 200
             ON CONFLICT(name) DO NOTHING",
            [name],
        )?;
        let id: i64 = tx
            .query_row(
                "SELECT id FROM review_workflows WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()?
            .context("this workspace already has 200 saved workflows")?;
        let previous = get_workflow(&tx, id, None)?;
        if let Some(workflow) = &previous {
            if workflow.plan == plan {
                tx.commit()?;
                return Ok(workflow.clone());
            }
        }
        let version = previous.map_or(1, |workflow| workflow.revision.version + 1);
        let created_at_ms = now_ms();
        tx.execute(
            "INSERT INTO review_workflow_versions(workflow_id, version, plan_json, created_at_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![id, version, serde_json::to_string(&plan)?, created_at_ms],
        )?;
        let revision_id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(ReviewWorkflow {
            revision: WorkflowVersion {
                id,
                name: name.into(),
                version,
                created_at_ms,
            },
            plan,
            revision_id,
        })
    }

    pub fn review_workflows(&self) -> Result<Vec<ReviewWorkflow>> {
        let sql = format!("{SELECT} WHERE v.version = (
            SELECT max(latest.version) FROM review_workflow_versions latest WHERE latest.workflow_id = w.id
        ) ORDER BY w.name COLLATE NOCASE, w.id");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        let mut workflows = Vec::new();
        while let Some(row) = rows.next()? {
            workflows.push(read_workflow(row)?);
        }
        Ok(workflows)
    }

    pub fn review_workflow(&self, id: i64, version: Option<i64>) -> Result<Option<ReviewWorkflow>> {
        get_workflow(&self.conn, id, version)
    }

    pub fn review_workflow_versions(&self, id: i64) -> Result<Vec<WorkflowVersion>> {
        let mut stmt = self.conn.prepare(
            "SELECT w.id, w.name, v.version, v.created_at_ms FROM review_workflows w
             JOIN review_workflow_versions v ON v.workflow_id = w.id WHERE w.id = ?1
             ORDER BY v.version DESC LIMIT 100",
        )?;
        let rows = stmt.query_map([id], read_version)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

fn get_workflow(
    conn: &rusqlite::Connection,
    id: i64,
    version: Option<i64>,
) -> Result<Option<ReviewWorkflow>> {
    let sql = format!("{SELECT} WHERE w.id = ?1 AND (?2 IS NULL OR v.version = ?2) ORDER BY v.version DESC LIMIT 1");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params![id, version])?;
    rows.next()?.map(read_workflow).transpose()
}

fn read_version(row: &Row<'_>) -> rusqlite::Result<WorkflowVersion> {
    Ok(WorkflowVersion {
        id: row.get(0)?,
        name: row.get(1)?,
        version: row.get(2)?,
        created_at_ms: row.get(3)?,
    })
}

fn read_workflow(row: &Row<'_>) -> Result<ReviewWorkflow> {
    let document: String = row.get(4)?;
    Ok(ReviewWorkflow {
        revision: read_version(row)?,
        plan: serde_json::from_str(&document)?,
        revision_id: row.get(5)?,
    })
}
