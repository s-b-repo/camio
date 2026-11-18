use super::{now_ms, sha256_hex, ReviewArchive, Store, WorkflowVersion, MAX_REVIEW_EXCHANGES};
use anyhow::{ensure, Context, Result};
use camio_core::{ExchangeId, Finding, FindingId, Query, Task, TaskId, TaskState};
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use serde::{Deserialize, Serialize};

const STALE_AFTER_MS: i64 = 120_000;
pub(super) const SCHEMA: &str = r#"
CREATE TABLE review_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    state TEXT NOT NULL CHECK (state IN ('pending','running','cancelled','failed','completed','interrupted')),
    query TEXT NOT NULL,
    scan_limit INTEGER NOT NULL,
    save INTEGER NOT NULL CHECK (save IN (0, 1)),
    snapshot INTEGER,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    examined INTEGER NOT NULL DEFAULT 0,
    scanned INTEGER NOT NULL DEFAULT 0,
    skipped_large INTEGER NOT NULL DEFAULT 0,
    omitted INTEGER NOT NULL DEFAULT 0,
    findings INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE UNIQUE INDEX one_running_review ON review_tasks ((1)) WHERE state IN ('pending', 'running');
CREATE TABLE review_results (
    task_id INTEGER NOT NULL REFERENCES review_tasks(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    severity INTEGER NOT NULL,
    data_json TEXT NOT NULL,
    PRIMARY KEY (task_id, key)
);
CREATE INDEX review_results_by_severity ON review_results(task_id, severity DESC, key);
"#;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReviewCounts {
    pub examined: usize,
    pub scanned: usize,
    pub skipped_large: usize,
    pub omitted: usize,
    pub findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewTask {
    #[serde(flatten)]
    pub task: Task,
    pub query: String,
    pub limit: usize,
    pub save: bool,
    pub snapshot: Option<ExchangeId>,
    pub updated_at_ms: i64,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<WorkflowVersion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<ReviewArchive>,
    #[serde(flatten)]
    pub counts: ReviewCounts,
}

pub struct ReviewCandidate {
    pub rule: &'static str,
    pub host: String,
    pub finding: Finding,
}

const SELECT: &str = "SELECT t.id, t.state, t.query, t.scan_limit, t.save, t.snapshot, t.created_at_ms, t.updated_at_ms,
    t.examined, t.scanned, t.skipped_large, t.omitted, t.findings, t.error, w.id, w.name, v.version, v.created_at_ms,
    t.archive_name, c.format, c.sha256, c.imported, COALESCE(c.warning_count, 0), c.warnings_json, t.capture_reused, c.first_exchange
    FROM review_tasks t LEFT JOIN review_workflow_versions v ON v.id = t.workflow_revision
    LEFT JOIN review_workflows w ON w.id = v.workflow_id
    LEFT JOIN review_captures c ON c.id = t.capture_id";

impl Store {
    pub fn queue_review(&self, query: &str, limit: usize, save: bool) -> Result<TaskId> {
        self.enqueue_review(query, limit, save, None, None)
    }

    pub fn queue_saved_review(
        &self,
        workflow: i64,
        version: Option<i64>,
    ) -> Result<(TaskId, Query)> {
        self.enqueue_saved_review(workflow, version, None)
    }

    pub fn queue_archive_review(
        &self,
        workflow: i64,
        version: Option<i64>,
        name: &str,
    ) -> Result<(TaskId, Query)> {
        let name = name.trim();
        ensure!(
            !name.is_empty() && name.len() <= 512 && !name.contains(char::is_control),
            "enter an archive name of up to 512 bytes"
        );
        self.enqueue_saved_review(workflow, version, Some(name))
    }

    fn enqueue_saved_review(
        &self,
        workflow: i64,
        version: Option<i64>,
        archive: Option<&str>,
    ) -> Result<(TaskId, Query)> {
        let workflow = self
            .review_workflow(workflow, version)?
            .context("workflow version was not found")?;
        let query = workflow.plan.compile()?;
        let id = self.enqueue_review(
            query.source(),
            workflow.plan.limit,
            workflow.plan.save,
            Some(workflow.revision_id),
            archive,
        )?;
        Ok((id, query))
    }

    fn enqueue_review(
        &self,
        query: &str,
        limit: usize,
        save: bool,
        revision: Option<i64>,
        archive: Option<&str>,
    ) -> Result<TaskId> {
        ensure!(
            (1..=MAX_REVIEW_EXCHANGES).contains(&limit),
            "invalid review limit"
        );
        self.reconcile_reviews()?;
        let now = now_ms();
        let rows = self.conn.execute(
            "INSERT INTO review_tasks (state, query, scan_limit, save, snapshot, created_at_ms, updated_at_ms, workflow_revision, archive_name)
             VALUES ('pending', ?1, ?2, ?3, CASE WHEN ?6 IS NULL THEN (SELECT max(id) FROM exchanges) END, ?4, ?4, ?5, ?6)
             ON CONFLICT DO NOTHING", params![query, limit as i64, save, now, revision, archive],
        )?;
        ensure!(
            rows == 1,
            "a passive review is already running for this workspace"
        );
        Ok(TaskId(self.conn.last_insert_rowid()))
    }

    fn reconcile_reviews(&self) -> Result<()> {
        let cutoff = now_ms() - STALE_AFTER_MS;
        let stale: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM review_tasks WHERE state IN ('pending', 'running') AND updated_at_ms < ?1)",
            [cutoff], |row| row.get(0),
        )?;
        if stale {
            self.conn.execute(
                "UPDATE review_tasks SET state = 'interrupted', updated_at_ms = ?2,
                 error = 'The review worker stopped updating. Saved results are available.'
                 WHERE state IN ('pending', 'running') AND updated_at_ms < ?1",
                params![cutoff, now_ms()],
            )?;
        }
        Ok(())
    }

    pub fn start_review(&self, id: TaskId) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE review_tasks SET state = 'running', updated_at_ms = ?2 WHERE id = ?1 AND state = 'pending'",
            params![id.0, now_ms()],
        )? == 1)
    }

    pub fn cancel_review(&self, id: TaskId) -> Result<bool> {
        self.end_review(id, "cancelled", None)
    }

    pub fn fail_review(&self, id: TaskId, error: &str) -> Result<bool> {
        self.end_review(id, "failed", Some(error))
    }

    pub fn finish_review(&self, id: TaskId) -> Result<bool> {
        self.end_review(id, "completed", None)
    }

    fn end_review(&self, id: TaskId, state: &str, error: Option<&str>) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE review_tasks SET state = ?2, error = ?3, updated_at_ms = ?4
             WHERE id = ?1 AND (state = 'running' OR (state = 'pending' AND ?2 != 'completed'))",
            params![id.0, state, error, now_ms()],
        )? == 1)
    }

    pub fn review_task(&self, id: TaskId) -> Result<Option<ReviewTask>> {
        self.reconcile_reviews()?;
        let mut stmt = self.conn.prepare(&format!("{SELECT} WHERE t.id = ?1"))?;
        let mut rows = stmt.query([id.0])?;
        rows.next()?.map(read_review).transpose()
    }

    pub fn review_tasks(&self) -> Result<Vec<ReviewTask>> {
        self.reconcile_reviews()?;
        let mut stmt = self
            .conn
            .prepare(&format!("{SELECT} ORDER BY t.id DESC LIMIT 30"))?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(read_review(row)?);
        }
        Ok(out)
    }

    pub fn review_results(&self, id: TaskId, offset: usize) -> Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare(
            "SELECT data_json FROM review_results WHERE task_id = ?1
             ORDER BY severity DESC, key LIMIT 50 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![id.0, offset as i64], |row| row.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }

    /// Update counters and publish evidence in the same transaction. A cancelled
    /// review can never add results after its state changes to cancelled.
    pub fn commit_review(
        &mut self,
        id: TaskId,
        counts: &ReviewCounts,
        candidates: &[ReviewCandidate],
        save: bool,
    ) -> Result<bool> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let running: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM review_tasks WHERE id = ?1 AND state = 'running')",
            [id.0],
            |row| row.get(0),
        )?;
        if !running {
            return Ok(false);
        }

        for candidate in candidates {
            let identity =
                serde_json::to_vec(&(candidate.rule, &candidate.host, &candidate.finding.title))?;
            let key = sha256_hex(&identity);
            let mut finding = candidate.finding.clone();
            if save {
                finding.id = persist_finding(&tx, &key, candidate.rule, &finding)?;
            }
            let previous = tx
                .query_row(
                    "SELECT data_json FROM review_results WHERE task_id = ?1 AND key = ?2",
                    params![id.0, key],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(previous) = previous {
                let mut aggregate: Finding = serde_json::from_str(&previous)?;
                merge_evidence(&mut aggregate, &finding);
                finding = aggregate;
            }
            tx.execute(
                "INSERT INTO review_results (task_id, key, severity, data_json, rule) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(task_id, key) DO UPDATE SET severity = excluded.severity, data_json = excluded.data_json, rule = excluded.rule",
                params![id.0, key, finding.severity as u8, serde_json::to_string(&finding)?, candidate.rule],
            )?;
        }

        tx.execute(
            "UPDATE review_tasks SET updated_at_ms = ?2, examined = ?3, scanned = ?4, skipped_large = ?5,
             omitted = ?6, findings = (SELECT count(*) FROM review_results WHERE task_id = ?1) WHERE id = ?1",
            params![id.0, now_ms(), counts.examined as i64, counts.scanned as i64,
                    counts.skipped_large as i64, counts.omitted as i64],
        )?;
        tx.commit()?;
        Ok(true)
    }
}

fn read_review(row: &Row<'_>) -> Result<ReviewTask> {
    let state: String = row.get(1)?;
    let workflow = if let Some(id) = row.get::<_, Option<i64>>(14)? {
        Some(WorkflowVersion {
            id,
            name: row.get(15)?,
            version: row.get(16)?,
            created_at_ms: row.get(17)?,
        })
    } else {
        None
    };
    let archive = if let Some(name) = row.get::<_, Option<String>>(18)? {
        let warnings: Option<String> = row.get(23)?;
        Some(ReviewArchive {
            name,
            format: row.get(19)?,
            sha256: row.get(20)?,
            imported: row.get::<_, Option<i64>>(21)?.map(|value| value as usize),
            warning_count: row.get::<_, i64>(22)? as usize,
            warnings: warnings
                .map(|value| serde_json::from_str(&value))
                .transpose()?
                .unwrap_or_default(),
            reused: row.get(24)?,
            first_exchange: row.get::<_, Option<i64>>(25)?.map(ExchangeId),
        })
    } else {
        None
    };
    Ok(ReviewTask {
        task: Task {
            id: TaskId(row.get(0)?),
            kind: "passive_review".into(),
            state: serde_json::from_value::<TaskState>(serde_json::Value::String(state))?,
            requests_sent: 0,
            request_budget: Some(0),
            created_at_ms: row.get(6)?,
        },
        query: row.get(2)?,
        limit: row.get::<_, i64>(3)? as usize,
        save: row.get(4)?,
        snapshot: row.get::<_, Option<i64>>(5)?.map(ExchangeId),
        updated_at_ms: row.get(7)?,
        error: row.get(13)?,
        workflow,
        archive,
        counts: ReviewCounts {
            examined: row.get::<_, i64>(8)? as usize,
            scanned: row.get::<_, i64>(9)? as usize,
            skipped_large: row.get::<_, i64>(10)? as usize,
            omitted: row.get::<_, i64>(11)? as usize,
            findings: row.get::<_, i64>(12)? as usize,
        },
    })
}

fn persist_finding(
    conn: &Connection,
    key: &str,
    rule: &str,
    finding: &Finding,
) -> Result<FindingId> {
    let old = conn.query_row(
        "SELECT f.id, f.data_json FROM passive_keys k JOIN findings f ON f.id = k.finding_id WHERE k.key = ?1",
        [key], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    ).optional()?;
    let now = now_ms();
    match old {
        None => {
            let id = Store::write_finding(conn, finding)?;
            conn.execute(
                "INSERT INTO passive_keys (key, finding_id, rule, last_seen_at_ms) VALUES (?1, ?2, ?3, ?4)",
                params![key, id.0, rule, now],
            )?;
            Ok(id)
        }
        Some((id, data)) => {
            let mut old: Finding = serde_json::from_str(&data)?;
            merge_evidence(&mut old, finding);
            let severity = serde_json::to_string(&old.severity)?;
            let confidence = serde_json::to_string(&old.confidence)?;
            conn.execute(
                "UPDATE findings SET data_json = ?2, severity = ?3, confidence = ?4 WHERE id = ?1",
                params![
                    id,
                    serde_json::to_string(&old)?,
                    severity.trim_matches('"'),
                    confidence.trim_matches('"')
                ],
            )?;
            conn.execute(
                "UPDATE passive_keys SET last_seen_at_ms = ?2 WHERE key = ?1",
                params![key, now],
            )?;
            Ok(FindingId(id))
        }
    }
}

fn merge_evidence(target: &mut Finding, fresh: &Finding) {
    if fresh.severity > target.severity {
        target.severity = fresh.severity;
        target.confidence = fresh.confidence;
        target.detail.clone_from(&fresh.detail);
    }
    for id in &fresh.evidence {
        if !target.evidence.contains(id) {
            target.evidence.push(*id);
        }
    }
}
