//! Durable, append-only audit log (plan §F02).
//!
//! Every gated action — a send, an active scan, a DAST sweep, a proxy forward, a
//! destructive store operation — records *one* row here at the moment the policy
//! decision is made: who asked, what class of action it was, what it targeted,
//! and whether it was allowed, confirmed, or refused. The table is append-only in
//! use (no update path; the only deletion is an explicit retention prune), so the
//! trail survives restarts and is a decision record, not a side effect of uptime.
//!
//! The log is deliberately *coarse* and free of payload bodies: it answers "what
//! did this tool decide to do, and when" for review and incident reconstruction,
//! not "what bytes crossed the wire" (that is the exchange history's job). Keeping
//! bodies out of it means the audit trail itself never becomes a place secrets
//! accumulate.

use rusqlite::{params, Connection};

/// Append-only audit schema (additive migration v9→v10).
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms         INTEGER NOT NULL,
    actor         TEXT NOT NULL,
    action_class  TEXT NOT NULL,
    action        TEXT NOT NULL,
    target        TEXT,
    decision      TEXT NOT NULL,
    detail        TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at_ms);
CREATE INDEX IF NOT EXISTS idx_audit_class ON audit_log(action_class);
";

/// A new audit entry to append. `at_ms` is stamped by the store at write time, so
/// a caller only describes *what happened*, never when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAudit {
    /// Which surface initiated the action: `cli`, `web`, `mcp`, `proxy`, …
    pub actor: String,
    /// The policy class, spelled as the policy engine spells it: `PASSIVE`,
    /// `ACTIVE`, `DESTRUCTIVE`.
    pub action_class: String,
    /// The concrete operation: `send`, `active_scan`, `dast`, `proxy_forward`, …
    pub action: String,
    /// What it targeted (host, URL, resource), if any.
    pub target: Option<String>,
    /// The outcome of the gate: `allowed`, `confirmed`, `denied`,
    /// `out_of_scope`, `blocked`, …
    pub decision: String,
    /// Optional free-text or compact JSON detail. Never request/response bodies.
    pub detail: Option<String>,
}

impl NewAudit {
    /// Start an entry from the four required fields.
    pub fn new(
        actor: impl Into<String>,
        action_class: impl Into<String>,
        action: impl Into<String>,
        decision: impl Into<String>,
    ) -> Self {
        Self {
            actor: actor.into(),
            action_class: action_class.into(),
            action: action.into(),
            target: None,
            decision: decision.into(),
            detail: None,
        }
    }

    /// Attach the target of the action (chainable).
    #[must_use]
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Attach a detail string (chainable).
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// A stored audit row (what `new` became plus its id and timestamp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub id: i64,
    pub at_ms: i64,
    pub actor: String,
    pub action_class: String,
    pub action: String,
    pub target: Option<String>,
    pub decision: String,
    pub detail: Option<String>,
}

/// Append one entry, stamping it `at_ms`. Returns the new row id.
pub fn append(conn: &Connection, at_ms: i64, entry: &NewAudit) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO audit_log (at_ms, actor, action_class, action, target, decision, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            at_ms,
            entry.actor,
            entry.action_class,
            entry.action,
            entry.target,
            entry.decision,
            entry.detail,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Read up to `limit` entries, newest first. A negative limit would mean
/// "unbounded" to SQLite, which no caller means, so it is clamped.
pub fn list(conn: &Connection, limit: i64) -> rusqlite::Result<Vec<AuditRecord>> {
    let limit = limit.clamp(0, 100_000);
    let mut stmt = conn.prepare(
        "SELECT id, at_ms, actor, action_class, action, target, decision, detail
         FROM audit_log ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit], row)?;
    rows.collect()
}

/// Read entries whose class matches `class`, newest first.
pub fn list_by_class(
    conn: &Connection,
    class: &str,
    limit: i64,
) -> rusqlite::Result<Vec<AuditRecord>> {
    let limit = limit.clamp(0, 100_000);
    let mut stmt = conn.prepare(
        "SELECT id, at_ms, actor, action_class, action, target, decision, detail
         FROM audit_log WHERE action_class = ?1 ORDER BY id DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![class, limit], row)?;
    rows.collect()
}

/// Total number of entries retained.
pub fn count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
}

/// Prune under a retention policy (keep at most `max_count` newest, drop anything
/// older than `max_age_ms`). An audit log is retained by *decision*, not by
/// uptime, so pruning is explicit — never automatic. Returns rows removed.
pub fn prune(
    conn: &Connection,
    now_ms: i64,
    max_count: usize,
    max_age_ms: i64,
) -> rusqlite::Result<usize> {
    let oldest = now_ms - max_age_ms.max(0);
    let by_age = conn.execute("DELETE FROM audit_log WHERE at_ms < ?1", params![oldest])?;
    let by_count = conn.execute(
        "DELETE FROM audit_log WHERE id NOT IN (
             SELECT id FROM audit_log ORDER BY id DESC LIMIT ?1
         )",
        params![max_count as i64],
    )?;
    Ok(by_age + by_count)
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRecord> {
    Ok(AuditRecord {
        id: r.get(0)?,
        at_ms: r.get(1)?,
        actor: r.get(2)?,
        action_class: r.get(3)?,
        action: r.get(4)?,
        target: r.get(5)?,
        decision: r.get(6)?,
        detail: r.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    #[test]
    fn appends_and_reads_newest_first() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_audit(&NewAudit::new("cli", "ACTIVE", "send", "allowed").target("a.test"))
            .unwrap();
        store
            .record_audit(
                &NewAudit::new("cli", "ACTIVE", "active_scan", "out_of_scope")
                    .target("b.test")
                    .detail("not in scope"),
            )
            .unwrap();
        let rows = store.audit_log(10).unwrap();
        assert_eq!(rows.len(), 2);
        // Newest first.
        assert_eq!(rows[0].action, "active_scan");
        assert_eq!(rows[0].decision, "out_of_scope");
        assert_eq!(rows[0].detail.as_deref(), Some("not in scope"));
        assert_eq!(rows[1].action, "send");
        assert!(rows[0].at_ms >= rows[1].at_ms);
        // Ids are monotonic.
        assert!(rows[0].id > rows[1].id);
    }

    #[test]
    fn filters_by_class() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_audit(&NewAudit::new("web", "PASSIVE", "passive_scan", "allowed"))
            .unwrap();
        store
            .record_audit(&NewAudit::new("cli", "DESTRUCTIVE", "purge", "confirmed"))
            .unwrap();
        let destructive = store.audit_log_by_class("DESTRUCTIVE", 10).unwrap();
        assert_eq!(destructive.len(), 1);
        assert_eq!(destructive[0].action, "purge");
        assert_eq!(store.audit_log_count().unwrap(), 2);
    }

    #[test]
    fn prune_keeps_newest_and_drops_old() {
        let store = Store::open_in_memory().unwrap();
        // Three entries; keep at most 2 newest.
        for _ in 0..3 {
            store
                .record_audit(&NewAudit::new("cli", "ACTIVE", "send", "allowed"))
                .unwrap();
        }
        let removed = store.prune_audit_log(2, i64::MAX).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(store.audit_log_count().unwrap(), 2);
    }

    #[test]
    fn a_fresh_store_has_the_audit_table() {
        // Opening a brand-new in-memory store must create the table via the
        // ordinary migration path, not only an already-migrated one.
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.audit_log_count().unwrap(), 0);
    }
}
