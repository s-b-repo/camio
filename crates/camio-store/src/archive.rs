use super::{now_ms, sha256_hex, Store, ARTIFACT_BYTES};
use anyhow::{ensure, Result};
use camio_core::{ExchangeId, HttpExchange, TaskId};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

pub(super) const SCHEMA: &str = r#"
CREATE TABLE review_captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL UNIQUE,
    format TEXT NOT NULL CHECK (format IN ('har', 'burp-xml')),
    imported INTEGER NOT NULL,
    warning_count INTEGER NOT NULL,
    warnings_json TEXT NOT NULL,
    first_exchange INTEGER,
    last_exchange INTEGER
);
ALTER TABLE review_tasks ADD COLUMN archive_name TEXT;
ALTER TABLE review_tasks ADD COLUMN capture_id INTEGER REFERENCES review_captures(id);
ALTER TABLE review_tasks ADD COLUMN capture_reused INTEGER NOT NULL DEFAULT 0 CHECK (capture_reused IN (0, 1));
ALTER TABLE review_results ADD COLUMN rule TEXT;
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewArchive {
    pub name: String,
    pub format: Option<String>,
    pub sha256: Option<String>,
    pub imported: Option<usize>,
    pub warning_count: usize,
    pub warnings: Vec<String>,
    pub reused: bool,
    #[serde(skip)]
    pub first_exchange: Option<ExchangeId>,
}

impl Store {
    /// Link a capture to an active review. The input bytes supply the hash;
    /// the normalized exchanges and their exact bounds are committed together.
    pub fn commit_review_archive(
        &mut self,
        id: TaskId,
        data: &[u8],
        format: &str,
        exchanges: &[HttpExchange],
        warnings: &[String],
    ) -> Result<bool> {
        ensure!(
            (1..=ARTIFACT_BYTES).contains(&data.len()),
            "capture archives support up to 4 MiB"
        );
        let digest = sha256_hex(data);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let awaiting_archive: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM review_tasks WHERE id = ?1 AND state = 'running'
                           AND archive_name IS NOT NULL AND capture_id IS NULL)",
            [id.0],
            |row| row.get(0),
        )?;
        if !awaiting_archive {
            return Ok(false);
        }

        let existing = tx
            .query_row(
                "SELECT id, last_exchange FROM review_captures WHERE sha256 = ?1",
                [&digest],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()?;
        let reused = existing.is_some();
        let (capture, last) = match existing {
            Some(record) => record,
            None => {
                let mut first = None;
                let mut last = None;
                for exchange in exchanges {
                    let id = Self::write_exchange(&tx, exchange)?.0;
                    first.get_or_insert(id);
                    last = Some(id);
                }
                tx.execute(
                    "INSERT INTO review_captures(sha256, format, imported, warning_count, warnings_json, first_exchange, last_exchange)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![digest, format, exchanges.len() as i64, warnings.len() as i64,
                        serde_json::to_string(&warnings[..warnings.len().min(30)])?, first, last],
                )?;
                (tx.last_insert_rowid(), last)
            }
        };

        tx.execute(
            "UPDATE review_tasks SET capture_id = ?2, snapshot = ?3, capture_reused = ?4, updated_at_ms = ?5 WHERE id = ?1",
            params![id.0, capture, last, reused, now_ms()],
        )?;
        tx.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReviewPlan;
    use camio_core::{HttpRequest, Source};

    #[test]
    fn cancelling_before_publication_keeps_archive_out_of_history() {
        let mut store = Store::open_in_memory().unwrap();
        let workflow = store
            .save_review_workflow("Capture", &ReviewPlan::new("", 10, true))
            .unwrap();
        let (id, _) = store
            .queue_archive_review(workflow.revision.id, Some(1), "capture.har")
            .unwrap();
        assert!(store.start_review(id).unwrap());
        assert!(store.cancel_review(id).unwrap());
        let exchange = HttpExchange::new(
            HttpRequest::get("https://capture.test/review"),
            Source::Import,
        );
        assert!(!store
            .commit_review_archive(id, b"archive data", "har", &[exchange], &[])
            .unwrap());
        assert_eq!(store.count().unwrap(), 0);
        assert!(store
            .review_task(id)
            .unwrap()
            .unwrap()
            .archive
            .unwrap()
            .sha256
            .is_none());
    }
}
