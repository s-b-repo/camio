//! Durable background-task records (plan §4.2 / §F03).
//!
//! The in-process [`TaskManager`](camio_tasks::TaskManager) owns running work;
//! this module makes that work *survive a restart*: every state change is upserted
//! into the `task_record` table, and on the next open anything still
//! non-terminal is reconciled to [`TaskState::Interrupted`] rather than being
//! silently forgotten or blindly replayed. A task therefore either completes,
//! fails, is cancelled, or is explicitly marked interrupted after a restart —
//! never lost.

use camio_core::TaskState;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Durable schema for task records (additive migration v7→v8).
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS task_record (
    id              INTEGER PRIMARY KEY,
    kind            TEXT NOT NULL,
    state           TEXT NOT NULL,
    progress_done   INTEGER NOT NULL,
    progress_total  INTEGER,
    message         TEXT NOT NULL,
    result          TEXT,
    error           TEXT,
    outcome         TEXT,
    created_at_ms   INTEGER NOT NULL,
    updated_at_ms   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_record_state ON task_record(state);
";

/// One durable task record (a superset snapshot of the runtime record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRow {
    pub id: i64,
    pub kind: String,
    pub state: TaskState,
    pub progress_done: u64,
    pub progress_total: Option<u64>,
    pub message: String,
    pub result: Option<String>,
    pub error: Option<String>,
    /// The distinct terminal reason, spelled as in `TaskOutcome::as_str`.
    pub outcome: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl TaskRow {
    /// Whether this row is terminal.
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

/// Insert or update a task record.
pub fn save(conn: &Connection, row: &TaskRow) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO task_record (id, kind, state, progress_done, progress_total,
                                  message, result, error, outcome, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(id) DO UPDATE SET
            kind = excluded.kind,
            state = excluded.state,
            progress_done = excluded.progress_done,
            progress_total = excluded.progress_total,
            message = excluded.message,
            result = excluded.result,
            error = excluded.error,
            outcome = excluded.outcome,
            updated_at_ms = excluded.updated_at_ms",
        params![
            row.id,
            row.kind,
            row.state.as_str(),
            i64::try_from(row.progress_done).unwrap_or(i64::MAX),
            row.progress_total
                .map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
            row.message,
            row.result,
            row.error,
            row.outcome,
            row.created_at_ms,
            row.updated_at_ms,
        ],
    )?;
    Ok(())
}

/// Read one record.
pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<TaskRow>> {
    conn.query_row(
        "SELECT id, kind, state, progress_done, progress_total, message, result, error,
                outcome, created_at_ms, updated_at_ms
         FROM task_record WHERE id = ?1",
        params![id],
        row,
    )
    .optional()
}

/// Read up to `limit` records, newest first. The limit is bounded: SQLite
/// treats a negative LIMIT as unbounded, which is never what a caller means.
pub fn list(conn: &Connection, limit: i64) -> rusqlite::Result<Vec<TaskRow>> {
    let limit = limit.clamp(0, 10_000);
    let mut stmt = conn.prepare(
        "SELECT id, kind, state, progress_done, progress_total, message, result, error,
                outcome, created_at_ms, updated_at_ms
         FROM task_record ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit], row)?;
    rows.collect()
}

/// Mark every non-terminal record interrupted (plan §4.2 restart
/// reconciliation). Returns how many records were reconciled.
pub fn reconcile_interrupted(conn: &Connection, at_ms: i64) -> rusqlite::Result<usize> {
    let n = conn.execute(
        "UPDATE task_record
            SET state = 'interrupted',
                outcome = COALESCE(outcome, 'interrupted-after-restart'),
                updated_at_ms = ?1
          WHERE state NOT IN ('completed', 'cancelled', 'failed', 'interrupted')",
        params![at_ms],
    )?;
    Ok(n)
}

/// Map a result row to a [`TaskRow`], refusing unknown states.
fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TaskRow> {
    let state: String = r.get(2)?;
    let state = TaskState::parse(&state).unwrap_or(TaskState::Failed);
    Ok(TaskRow {
        id: r.get(0)?,
        kind: r.get(1)?,
        state,
        progress_done: r.get::<_, i64>(3)?.max(0) as u64,
        progress_total: r.get::<_, Option<i64>>(4)?.map(|v| v.max(0) as u64),
        message: r.get(5)?,
        result: r.get(6)?,
        error: r.get(7)?,
        outcome: r.get(8)?,
        created_at_ms: r.get(9)?,
        updated_at_ms: r.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    fn row(id: i64, state: TaskState) -> TaskRow {
        TaskRow {
            id,
            kind: "scan".into(),
            state,
            progress_done: 3,
            progress_total: Some(10),
            message: "halfway".into(),
            result: None,
            error: None,
            outcome: None,
            created_at_ms: 1,
            updated_at_ms: 2,
        }
    }

    #[test]
    fn saves_and_reads_back() {
        let store = Store::open_in_memory().unwrap();
        store.save_task(&row(7, TaskState::Running)).unwrap();
        let got = store.task(7).unwrap().unwrap();
        assert_eq!(got.state, TaskState::Running);
        assert_eq!(got.progress_total, Some(10));
        assert_eq!(got.message, "halfway");
    }

    #[test]
    fn upsert_updates_state() {
        let store = Store::open_in_memory().unwrap();
        store.save_task(&row(7, TaskState::Running)).unwrap();
        let mut done = row(7, TaskState::Completed);
        done.result = Some("all done".into());
        done.outcome = Some("success".into());
        store.save_task(&done).unwrap();
        let got = store.task(7).unwrap().unwrap();
        assert_eq!(got.state, TaskState::Completed);
        assert_eq!(got.result.as_deref(), Some("all done"));
        assert_eq!(got.outcome.as_deref(), Some("success"));
    }

    #[test]
    fn reconcile_marks_non_terminal_interrupted() {
        let store = Store::open_in_memory().unwrap();
        store.save_task(&row(1, TaskState::Running)).unwrap();
        store.save_task(&row(2, TaskState::Queued)).unwrap();
        store.save_task(&row(3, TaskState::Paused)).unwrap();
        store.save_task(&row(4, TaskState::Completed)).unwrap();
        store.save_task(&row(5, TaskState::Cancelled)).unwrap();
        store.reconcile_interrupted_tasks().unwrap();
        let all = store.tasks(100).unwrap();
        let by_id: std::collections::HashMap<i64, TaskState> =
            all.into_iter().map(|r| (r.id, r.state)).collect();
        assert_eq!(by_id[&1], TaskState::Interrupted);
        assert_eq!(by_id[&2], TaskState::Interrupted);
        assert_eq!(by_id[&3], TaskState::Interrupted);
        // Terminal states are untouched by reconciliation.
        assert_eq!(by_id[&4], TaskState::Completed);
        assert_eq!(by_id[&5], TaskState::Cancelled);
    }

    #[test]
    fn list_is_newest_first() {
        let store = Store::open_in_memory().unwrap();
        store.save_task(&row(1, TaskState::Completed)).unwrap();
        store.save_task(&row(2, TaskState::Completed)).unwrap();
        store.save_task(&row(3, TaskState::Running)).unwrap();
        let rows = store.tasks(2).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, 3);
        assert_eq!(rows[1].id, 2);
    }
}
