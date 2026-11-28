//! `camio-store` — indexed history with content-addressed bodies (plan §13 item 7).
//!
//! Camio must keep the request log responsive at 1,000,000+ exchanges without
//! holding them all in RAM (plan §5). This crate stores exchange *metadata* in
//! an indexed SQLite table and message *bodies* as content-addressed blobs
//! (sha-256), deduplicated across the whole store, so repeated payloads and
//! identical responses cost one copy.
//!
//! History is filtered with the same [`Query`](camio_core::Query) language as
//! the rest of Camio. Metadata-only queries skip loading body blobs entirely
//! (via [`Query::needs_body`](camio_core::Query::needs_body)).
//!
//! Evidence is never silently rewritten: the full structured exchange is stored
//! as JSON (bodies elided to their sha) and reconstructed byte-for-byte on read.

use anyhow::{ensure, Context, Result};
use camio_core::{Body, ExchangeId, Finding, FindingId, HttpExchange, Query};
use rusqlite::{params, Connection, OptionalExtension};

/// The triage lifecycle state of a finding (plan §F14). A finding with no stored
/// status is [`FindingStatus::Open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatus {
    Open,
    Confirmed,
    FalsePositive,
    Fixed,
    Ignored,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingStatus::Open => "open",
            FindingStatus::Confirmed => "confirmed",
            FindingStatus::FalsePositive => "false_positive",
            FindingStatus::Fixed => "fixed",
            FindingStatus::Ignored => "ignored",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "open" => Some(FindingStatus::Open),
            "confirmed" => Some(FindingStatus::Confirmed),
            "false_positive" | "fp" => Some(FindingStatus::FalsePositive),
            "fixed" => Some(FindingStatus::Fixed),
            "ignored" => Some(FindingStatus::Ignored),
            _ => None,
        }
    }
}
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod archive;
mod audit;
mod bundle;
mod collection;
mod evidence;
mod history;
mod inventory;
mod report;
mod review;
mod tasks;
mod workflow;
mod workspace;

pub use archive::ReviewArchive;
pub use audit::{AuditRecord, NewAudit};
pub use bundle::{ReviewEvidenceBundle, MAX_BUNDLE_BYTES};
pub use collection::{Collection, CollectionItem, ItemKind};
pub use evidence::{
    ArtifactFormat, ArtifactImport, ArtifactSummary, Observation, ObservationPage, ARTIFACT_BYTES,
};
pub use history::{ExchangePreview, HistoryPage, HistoryRow, INSPECT_BYTES, REVIEW_BODY_LIMIT};
pub use inventory::{
    Asset, AssetInventory, AssetNote, Endpoint, EndpointEvidence, InventoryEvidence, InventoryPage,
};
pub use report::{FindingReport, ReportFormat};
pub use review::{ReviewCandidate, ReviewCounts, ReviewTask};
pub use tasks::TaskRow;
pub use workflow::{ReviewPlan, ReviewWorkflow, WorkflowVersion, MAX_REVIEW_EXCHANGES};
pub use workspace::{FindingReview, ReviewState, SavedExchange, SavedQuery, WorkspaceSummary};

/// Maximum rows a metadata query scans before giving up: a generous window
/// that keeps a query matching nothing from walking a multi-million-row table
/// in Rust, while the SQL prefilter keeps real result sets far below it.
const MAX_SCAN_WINDOW: usize = 100_000;

/// Hard ceiling on how many rows one paged query may return.
///
/// `query_exchanges` has no `LIMIT` of its own — it walks the table and keeps
/// what matches — so an unbounded caller turns one request into a full-table
/// materialisation, bodies included. Callers pass a user-supplied limit, so
/// the store refuses "give me everything" outright instead of trusting the
/// caller to clamp.
pub const MAX_PAGE_LIMIT: usize = 20_000;

/// Clamp a caller-supplied row limit into `[1, MAX_PAGE_LIMIT]`.
///
/// The raw value comes from JSON and may be absent, zero, absurdly large, or
/// wider than a `usize` on a 32-bit target (where an `as usize` cast silently
/// truncates). All of those are answerable with a sane bound; none should
/// panic or truncate.
pub fn bounded_limit(raw: Option<u64>, default: usize) -> usize {
    let default = (default.clamp(1, MAX_PAGE_LIMIT)) as u64;
    raw.unwrap_or(default).clamp(1, MAX_PAGE_LIMIT as u64) as usize
}

const SCHEMA_VERSION: i64 = 12;

/// Triage lifecycle for a finding (plan §F14). Additive: the `findings` rows are
/// untouched; a finding with no row here is treated as `open`.
const FINDING_STATUS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS finding_status (
    finding_id    INTEGER PRIMARY KEY,
    status        TEXT NOT NULL,
    note          TEXT,
    updated_at_ms INTEGER NOT NULL
);
";

/// Saved CamioQL searches (plan §F07).
const SAVED_SEARCH_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS saved_search (
    name          TEXT PRIMARY KEY,
    query         TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
";

/// Named baselines (plan §F09 compare-to-baseline): a stable name pointing at a
/// stored exchange that later sends are diffed against. Just a pointer — the
/// referenced exchange is the source of truth, so re-pointing a baseline is one
/// upsert and deleting one never removes history.
const BASELINE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS baseline (
    name          TEXT PRIMARY KEY,
    exchange_id   INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL
);
";

/// Organizer labels on exchanges (plan §F18).
const EXCHANGE_LABEL_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS exchange_label (
    exchange_id   INTEGER NOT NULL,
    label         TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (exchange_id, label)
);
CREATE INDEX IF NOT EXISTS idx_exchange_label_label ON exchange_label(label);
";

/// Durable OAST interactions (plan §F15): retained under a policy, not by
/// process uptime, so callbacks survive restarts and prunes are decisions.
const OAST_INTERACTION_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS oast_interactions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    token          TEXT,
    method         TEXT NOT NULL,
    target         TEXT NOT NULL,
    host           TEXT,
    source         TEXT NOT NULL,
    received_at_ms INTEGER NOT NULL,
    body_summary   TEXT
);
CREATE INDEX IF NOT EXISTS idx_oast_token ON oast_interactions(token);
CREATE INDEX IF NOT EXISTS idx_oast_received ON oast_interactions(received_at_ms);
";

/// One stored OAST interaction (plan §F15). Kept in the store so the
/// dependency stays one-directional (camio-oast depends on camio-store).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OastRow {
    pub id: i64,
    pub token: Option<String>,
    pub method: String,
    pub target: String,
    pub host: Option<String>,
    pub source: String,
    pub received_at_ms: i64,
    pub body_summary: Option<String>,
}

fn oast_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<OastRow> {
    Ok(OastRow {
        id: r.get(0)?,
        token: r.get(1)?,
        method: r.get(2)?,
        target: r.get(3)?,
        host: r.get(4)?,
        source: r.get(5)?,
        received_at_ms: r.get(6)?,
        body_summary: r.get(7)?,
    })
}

/// The embedded store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) a store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).context("opening SQLite database")?;
        Self::init(conn)
    }

    /// Open an in-memory store (tests, ephemeral sessions).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory database")?;
        Self::init(conn)
    }

    /// Backing path for a durable workspace. In-memory databases have no path.
    pub fn path(&self) -> Option<&Path> {
        self.conn
            .path()
            .filter(|path| !path.is_empty())
            .map(Path::new)
    }

    fn init(mut conn: Connection) -> Result<Self> {
        // WAL + NORMAL keeps writes durable and reads concurrent without the
        // full-sync cost; tuned for an interactive local workbench (plan §5).
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        anyhow::ensure!(
            version <= SCHEMA_VERSION,
            "unsupported store schema version {version}"
        );
        if version < SCHEMA_VERSION {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
            anyhow::ensure!(
                version <= SCHEMA_VERSION,
                "unsupported store schema version {version}"
            );
            if version == 0 {
                tx.execute_batch(SCHEMA)
                    .context("creating history schema")?;
                tx.execute_batch(workspace::SCHEMA)
                    .context("creating workbench schema")?;
                tx.execute_batch(review::SCHEMA)
                    .context("creating review schema")?;
                tx.execute_batch(evidence::SCHEMA)
                    .context("creating evidence schema")?;
            }
            if version < 2 {
                tx.execute_batch(workflow::SCHEMA)
                    .context("creating workflow schema")?;
            }
            if version < 3 {
                tx.execute_batch(archive::SCHEMA)
                    .context("creating archive review schema")?;
            }
            if version < 4 {
                inventory::migrate(&tx).context("indexing recorded assets")?;
            }
            if version < 5 {
                tx.execute_batch(FINDING_STATUS_SCHEMA)
                    .context("creating finding-status (triage) schema")?;
            }
            if version < 6 {
                tx.execute_batch(SAVED_SEARCH_SCHEMA)
                    .context("creating saved-search schema")?;
            }
            if version < 7 {
                tx.execute_batch(EXCHANGE_LABEL_SCHEMA)
                    .context("creating exchange-label (organizer) schema")?;
            }
            if version < 8 {
                tx.execute_batch(tasks::SCHEMA)
                    .context("creating durable task-record schema")?;
            }
            if version < 9 {
                tx.execute_batch(OAST_INTERACTION_SCHEMA)
                    .context("creating durable OAST interaction schema")?;
            }
            if version < 10 {
                tx.execute_batch(audit::SCHEMA)
                    .context("creating durable audit-log schema")?;
            }
            if version < 11 {
                tx.execute_batch(collection::SCHEMA)
                    .context("creating collections schema")?;
            }
            if version < 12 {
                tx.execute_batch(BASELINE_SCHEMA)
                    .context("creating baseline schema")?;
            }
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            tx.commit()?;
        }
        // The journal mode is a database-wide setting. Updating it only when
        // necessary lets readers open a connection during an existing write.
        let journal: String = conn.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        if journal != "wal" && journal != "memory" {
            conn.pragma_update(None, "journal_mode", "WAL")?;
        }
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        Ok(Store { conn })
    }

    /// Number of stored exchanges.
    pub fn count(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM exchanges", [], |r| r.get(0))?)
    }

    /// Number of distinct stored body blobs (visibility into dedup savings).
    pub fn blob_count(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))?)
    }

    /// Record a durable OAST interaction (plan §F15).
    pub fn record_oast_interaction(&self, row: &OastRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO oast_interactions (token, method, target, host, source,
                                            received_at_ms, body_summary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                row.token,
                row.method,
                row.target,
                row.host,
                row.source,
                row.received_at_ms,
                row.body_summary,
            ],
        )?;
        Ok(())
    }

    /// Prune OAST interactions under the retention policy (count + age).
    pub fn prune_oast_interactions(&self, max_count: usize, max_age_ms: i64) -> Result<usize> {
        let oldest = now_ms() - max_age_ms.max(0);
        let by_age = self.conn.execute(
            "DELETE FROM oast_interactions WHERE received_at_ms < ?1",
            params![oldest],
        )?;
        let by_count = self.conn.execute(
            "DELETE FROM oast_interactions WHERE id NOT IN (
                 SELECT id FROM oast_interactions ORDER BY id DESC LIMIT ?1
             )",
            params![max_count as i64],
        )?;
        Ok(by_age + by_count)
    }

    /// Stored OAST interactions for one token (newest first).
    pub fn oast_interactions_for_token(&self, token: &str) -> Result<Vec<OastRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, token, method, target, host, source, received_at_ms, body_summary
             FROM oast_interactions WHERE token = ?1 ORDER BY id DESC LIMIT 200",
        )?;
        let rows = stmt.query_map(params![token], oast_row)?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Stored OAST interactions (newest first).
    pub fn oast_interactions(&self, limit: i64) -> Result<Vec<OastRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, token, method, target, host, source, received_at_ms, body_summary
             FROM oast_interactions ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], oast_row)?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Append one entry to the durable audit log (plan §F02), stamped now.
    /// Returns the new row id.
    pub fn record_audit(&self, entry: &NewAudit) -> Result<i64> {
        Ok(audit::append(&self.conn, now_ms(), entry)?)
    }

    /// Read the audit log, newest first.
    pub fn audit_log(&self, limit: i64) -> Result<Vec<AuditRecord>> {
        Ok(audit::list(&self.conn, limit)?)
    }

    /// Read audit entries of one policy class (`PASSIVE`/`ACTIVE`/`DESTRUCTIVE`).
    pub fn audit_log_by_class(&self, class: &str, limit: i64) -> Result<Vec<AuditRecord>> {
        Ok(audit::list_by_class(&self.conn, class, limit)?)
    }

    /// Total number of retained audit entries.
    pub fn audit_log_count(&self) -> Result<i64> {
        Ok(audit::count(&self.conn)?)
    }

    /// Prune the audit log under an explicit retention policy (never automatic).
    pub fn prune_audit_log(&self, max_count: usize, max_age_ms: i64) -> Result<usize> {
        Ok(audit::prune(&self.conn, now_ms(), max_count, max_age_ms)?)
    }

    /// Create a collection (idempotent by name), returning its id (plan §F18).
    pub fn collection_create(&self, name: &str) -> Result<i64> {
        Ok(collection::create(&self.conn, name, now_ms())?)
    }

    /// Add an item to a collection (idempotent). Returns whether it was new.
    pub fn collection_add(&self, id: i64, kind: ItemKind, ref_id: i64) -> Result<bool> {
        Ok(collection::add_item(&self.conn, id, kind, ref_id, now_ms())?)
    }

    /// Remove an item from a collection. Returns whether a row was removed.
    pub fn collection_remove(&self, id: i64, kind: ItemKind, ref_id: i64) -> Result<bool> {
        Ok(collection::remove_item(&self.conn, id, kind, ref_id)?)
    }

    /// List collections (newest first) with member counts.
    pub fn collections(&self) -> Result<Vec<Collection>> {
        Ok(collection::list(&self.conn)?)
    }

    /// Members of a collection, in insertion order.
    pub fn collection_items(&self, id: i64) -> Result<Vec<CollectionItem>> {
        Ok(collection::items(&self.conn, id)?)
    }

    /// Delete a collection and its membership (referenced rows untouched).
    pub fn collection_delete(&self, id: i64) -> Result<bool> {
        Ok(collection::delete(&self.conn, id)?)
    }

    /// Resolve a collection id by name.
    pub fn collection_id(&self, name: &str) -> Result<Option<i64>> {
        Ok(collection::id_by_name(&self.conn, name)?)
    }

    /// Set (or re-point) a named baseline to a stored exchange (plan §F09).
    pub fn set_baseline(&self, name: &str, exchange_id: ExchangeId) -> Result<()> {
        self.conn.execute(
            "INSERT INTO baseline (name, exchange_id, created_at_ms) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET exchange_id = excluded.exchange_id,
                                             created_at_ms = excluded.created_at_ms",
            params![name.trim(), exchange_id.0, now_ms()],
        )?;
        Ok(())
    }

    /// The exchange a named baseline points at, if set.
    pub fn baseline(&self, name: &str) -> Result<Option<ExchangeId>> {
        use rusqlite::OptionalExtension;
        let id: Option<i64> = self
            .conn
            .query_row(
                "SELECT exchange_id FROM baseline WHERE name = ?1",
                params![name.trim()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(id.map(ExchangeId))
    }

    /// List baselines as `(name, exchange_id)`, newest first.
    pub fn baselines(&self) -> Result<Vec<(String, ExchangeId)>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, exchange_id FROM baseline ORDER BY created_at_ms DESC, name ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, ExchangeId(r.get::<_, i64>(1)?)))
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Delete a named baseline. Returns whether it existed.
    pub fn delete_baseline(&self, name: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM baseline WHERE name = ?1", params![name.trim()])?;
        Ok(n > 0)
    }

    /// Persist a background-task record (plan §4.2 durable jobs).
    pub fn save_task(&self, row: &TaskRow) -> Result<()> {
        Ok(tasks::save(&self.conn, row)?)
    }

    /// Read one durable task record.
    pub fn task(&self, id: i64) -> Result<Option<TaskRow>> {
        Ok(tasks::get(&self.conn, id)?)
    }

    /// Read durable task records, newest first.
    pub fn tasks(&self, limit: i64) -> Result<Vec<TaskRow>> {
        Ok(tasks::list(&self.conn, limit)?)
    }

    /// Mark records still non-terminal after a restart as interrupted
    /// (plan §4.2 reconciliation). Returns how many were reconciled.
    pub fn reconcile_interrupted_tasks(&self) -> Result<usize> {
        Ok(tasks::reconcile_interrupted(&self.conn, now_ms())?)
    }

    /// Insert an exchange, returning its assigned id. Bodies are stored as
    /// deduplicated content-addressed blobs.
    pub fn insert(&mut self, ex: &HttpExchange) -> Result<ExchangeId> {
        let tx = self.conn.transaction()?;
        let id = Self::write_exchange(&tx, ex)?;
        tx.commit()?;
        Ok(id)
    }

    /// Save an archive atomically. A storage error leaves the archive unsaved.
    pub fn insert_exchanges(&mut self, exchanges: &[HttpExchange]) -> Result<usize> {
        let tx = self.conn.transaction()?;
        for exchange in exchanges {
            Self::write_exchange(&tx, exchange)?;
        }
        tx.commit()?;
        Ok(exchanges.len())
    }

    fn write_exchange(conn: &Connection, ex: &HttpExchange) -> Result<ExchangeId> {
        let (id, created_at) = Self::write_exchange_record(conn, ex)?;
        inventory::index_exchange(conn, id, &ex.request.url, created_at)?;
        Ok(id)
    }

    fn write_exchange_record(conn: &Connection, ex: &HttpExchange) -> Result<(ExchangeId, i64)> {
        let req_body_sha = store_blob(conn, &ex.request.body)?;
        let (resp_body_sha, resp_len, resp_status) = match &ex.response {
            Some(r) => (
                store_blob(conn, &r.body)?,
                Some(r.body.len() as i64),
                Some(r.status as i64),
            ),
            None => (None, None, None),
        };

        // Structured record with bodies elided (they live in `blobs`).
        let mut skeleton = ex.clone();
        skeleton.id = ExchangeId(0);
        skeleton.request.body = Body::empty();
        if let Some(r) = skeleton.response.as_mut() {
            r.body = Body::empty();
        }
        let meta_json = serde_json::to_string(&skeleton).context("serializing exchange")?;

        let created_at = if ex.created_at_ms == 0 {
            now_ms()
        } else {
            ex.created_at_ms
        };

        conn.execute(
            "INSERT INTO exchanges (
                created_at_ms, source, scope, fingerprint, method, url, host, port, path, ext,
                req_len, req_body_sha, has_response, resp_status, resp_len, resp_body_sha,
                roundtrip_ms, note, meta_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19
             )",
            params![
                created_at,
                ex.source.as_str(),
                ex.scope.map(|s| s.as_str()),
                ex.fingerprint_used.as_deref(),
                ex.request.method,
                ex.request.url,
                ex.request.host(),
                ex.request.port().map(|p| p as i64),
                ex.request.path(),
                ex.request.extension(),
                ex.request.body.len() as i64,
                req_body_sha,
                ex.response.is_some() as i64,
                resp_status,
                resp_len,
                resp_body_sha,
                ex.timings.map(|t| t.roundtrip_ms),
                ex.note,
                meta_json,
            ],
        )?;
        Ok((ExchangeId(conn.last_insert_rowid()), created_at))
    }

    /// Fetch one exchange by id (with full bodies).
    pub fn get(&self, id: ExchangeId) -> Result<Option<HttpExchange>> {
        self.exchange_with_preview(id, None)
            .map(|preview| preview.map(|p| p.exchange))
    }

    /// Return the most recent exchanges matching `query`, newest first, capped
    /// at `limit`. Body blobs are loaded only when the query inspects them.
    pub fn query(&self, query: &Query, limit: usize) -> Result<Vec<HttpExchange>> {
        self.query_exchanges(query, limit, false)
    }

    /// Return real body bytes even when a filter only matches metadata.
    pub fn query_with_bodies(&self, query: &Query, limit: usize) -> Result<Vec<HttpExchange>> {
        self.query_exchanges(query, limit, true)
    }

    fn query_exchanges(
        &self,
        query: &Query,
        limit: usize,
        full_results: bool,
    ) -> Result<Vec<HttpExchange>> {
        // Ceiling rather than an advisory: this path walks the table with no
        // SQL LIMIT, so an oversized limit is a memory-exhaustion request.
        let limit = limit.min(MAX_PAGE_LIMIT);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let with_bodies = query.needs_body();
        let sql = format!(
            "SELECT {} FROM exchanges ORDER BY id DESC",
            history::EXCHANGE_COLUMNS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;

        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let mut row = history::StoredExchange::from_row(row)?;
            if with_bodies {
                row.load_bodies(self)?;
            }
            if query.matches(&row) {
                let ex = if with_bodies {
                    row.exchange
                } else if full_results {
                    row.load_bodies(self)?;
                    row.exchange
                } else {
                    row.with_length_placeholders()
                };
                out.push(ex);
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Metadata-only query: like [`Store::query`] but the returned exchanges
    /// carry *no* body bytes at all instead of zero-filled placeholders sized
    /// to the original body.
    ///
    /// The old placeholder behavior allocated `Σ(req_len + resp_len)` across
    /// every matched row, so a metadata query over a store with large bodies
    /// could exhaust memory while answering a question that never needed the
    /// bytes. Use this for URL/host/status-shaped work (site maps, scoping,
    /// previews); use [`Store::query_with_bodies`] when the body is read.
    pub fn query_metadata(&self, query: &Query, limit: usize) -> Result<Vec<HttpExchange>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let with_bodies = query.needs_body();
        let scan = self.metadata_scan(query, MAX_SCAN_WINDOW);
        let mut out = Vec::new();
        for mut row in scan? {
            if with_bodies {
                row.load_bodies(self)?;
            }
            if query.matches(&row) {
                out.push(row.into_exchange());
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// A bounded scan of matching *metadata* rows, with the query's
    /// required-metadata conjunct pushed into SQL so the query is answered from
    /// the `exchanges` indexes instead of walking the whole table in Rust
    /// (plan §5: "indexed query planning").
    ///
    /// The SQL clause is a superset prefilter of the full query — the caller
    /// still applies `Query::matches` — so results stay exact, and the window
    /// bound keeps a query that matches nothing from scanning forever.
    pub(crate) fn metadata_scan(
        &self,
        query: &Query,
        window: usize,
    ) -> Result<Vec<history::StoredExchange>> {
        // Every required conjunct is pushed (host, method, source, status are
        // all indexed), so a multi-predicate query is narrowed by all of them
        // instead of only the first. They are AND-ed: each is *required* by the
        // query, so the SQL set stays a superset of the real result set.
        // Interpolates a &'static str column list only; pushed filters take the
        // form `column op ?n` with values bound as parameters.
        // audit-allow: M1
        let mut sql = format!("SELECT {} FROM exchanges", history::EXCHANGE_COLUMNS);
        let mut bind: Vec<rusqlite::types::Value> = Vec::new();
        let mut clauses: Vec<String> = Vec::new();
        for filter in query.required_metadata_all() {
            if let Some((clause, value)) = history::metadata_clause(filter) {
                // `metadata_clause` writes the paged view's `?3` placeholder;
                // renumber to this query's own parameter index.
                let param = bind.len() + 1;
                clauses.push(clause.replace("?3", &format!("?{param}")));
                bind.push(value);
            }
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(&format!(" ORDER BY id DESC LIMIT {}", window.max(1) as i64));
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(bind))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(history::StoredExchange::from_row(row)?);
        }
        Ok(out)
    }

    /// Load exchanges for a passive scan, bounded by *both* a row count and a
    /// cumulative body-byte budget.
    ///
    /// A synchronous scan request must not load 1000 exchanges' worth of real
    /// bodies (several GiB for a store with large payloads) into memory inside
    /// one single-threaded request: rows whose bodies would exceed the budget
    /// are skipped and counted instead, so the caller can say so.
    pub fn query_for_scan(
        &self,
        query: &Query,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<(Vec<HttpExchange>, usize)> {
        if max_rows == 0 || max_bytes == 0 {
            return Ok((Vec::new(), 0));
        }
        let with_bodies = query.needs_body();
        let scan = self.metadata_scan(query, MAX_SCAN_WINDOW);

        let mut out = Vec::new();
        let mut skipped = 0usize;
        let mut budget = max_bytes;
        for mut row in scan? {
            if out.len() >= max_rows {
                break;
            }
            if with_bodies {
                row.load_bodies(self)?;
            }
            if !query.matches(&row) {
                continue;
            }
            let used = row.body_bytes();
            if used > budget {
                skipped += 1;
                continue;
            }
            budget = budget.saturating_sub(used);
            out.push(row.into_exchange());
        }
        Ok((out, skipped))
    }

    /// Convenience: the `limit` most recent exchanges (no filter).
    pub fn recent(&self, limit: usize) -> Result<Vec<HttpExchange>> {
        self.query(&Query::all(), limit)
    }

    // --- Findings (plan §8) -------------------------------------------------

    /// Record a finding, returning its id.
    /// Insert one finding, deduplicating against what is already stored (plan
    /// §F14): an identical finding — same producing check (`rule`), title,
    /// evidence set, and detail — returns the existing id instead of a new row.
    pub fn insert_finding(&mut self, finding: &Finding) -> Result<FindingId> {
        if let Some(id) = Self::find_duplicate(&self.conn, finding)? {
            return Ok(FindingId(id));
        }
        Self::write_finding(&self.conn, finding)
    }

    /// Insert a batch, deduplicating against the store (and within the batch),
    /// and return the number actually inserted (duplicates are skipped).
    pub fn insert_findings(&mut self, findings: &[Finding]) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let mut inserted = 0usize;
        for finding in findings {
            // Within the transaction, a finding inserted earlier in this batch is
            // visible to `find_duplicate`, so in-batch duplicates are collapsed too.
            if Self::find_duplicate(&tx, finding)?.is_none() {
                Self::write_finding(&tx, finding)?;
                inserted += 1;
            }
        }
        tx.commit()?;
        Ok(inserted)
    }

    /// The id of a stored finding identical to `finding` (same dedup signature),
    /// or `None`. Deliberately *not* applied by [`write_finding`]: the review
    /// workflow has its own `passive_keys` dedup and must keep getting a fresh
    /// row id, so cross-run dedup lives only in the public insert path.
    fn find_duplicate(conn: &Connection, finding: &Finding) -> Result<Option<i64>> {
        let signature = finding_signature(finding);
        let mut stmt = conn.prepare("SELECT id, data_json FROM findings WHERE title = ?1")?;
        let mut rows = stmt.query(params![finding.title])?;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let json: String = row.get(1)?;
            if let Ok(other) = serde_json::from_str::<Finding>(&json) {
                if finding_signature(&other) == signature {
                    return Ok(Some(id));
                }
            }
        }
        Ok(None)
    }

    /// Insert a finding row unconditionally (no dedup) and return its new id.
    fn write_finding(conn: &Connection, finding: &Finding) -> Result<FindingId> {
        let created_at = if finding.created_at_ms == 0 {
            now_ms()
        } else {
            finding.created_at_ms
        };
        let mut f = finding.clone();
        f.id = FindingId(0);
        f.created_at_ms = created_at;
        let json = serde_json::to_string(&f)?;
        conn.execute(
            "INSERT INTO findings (title, severity, confidence, created_at_ms, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                finding.title,
                serde_json::to_string(&finding.severity)?.trim_matches('"'),
                serde_json::to_string(&finding.confidence)?.trim_matches('"'),
                created_at,
                json,
            ],
        )?;
        Ok(FindingId(conn.last_insert_rowid()))
    }

    /// All findings, most severe first.
    pub fn list_findings(&self) -> Result<Vec<Finding>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, data_json FROM findings ORDER BY created_at_ms DESC")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, json) = r?;
            let mut f: Finding = serde_json::from_str(&json)?;
            f.id = FindingId(id);
            out.push(f);
        }
        out.sort_by_key(|f| std::cmp::Reverse(f.severity));
        Ok(out)
    }

    /// Count stored findings grouped by severity label (`critical`/`high`/
    /// `medium`/`low`/`info`). Cheap `GROUP BY`; drives the dashboard breakdown.
    pub fn findings_severity_counts(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT severity, count(*) FROM findings GROUP BY severity")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        // Order by severity rank, most severe first.
        let rank = |s: &str| match s {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        };
        out.sort_by_key(|(s, _)| rank(s));
        Ok(out)
    }

    /// Set (or clear the note of) a finding's triage status (plan §F14).
    pub fn set_finding_status(
        &mut self,
        id: FindingId,
        status: FindingStatus,
        note: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO finding_status (finding_id, status, note, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(finding_id) DO UPDATE SET
                 status = excluded.status, note = excluded.note, updated_at_ms = excluded.updated_at_ms",
            params![id.0, status.as_str(), note, now_ms()],
        )?;
        Ok(())
    }

    /// The triage status + note for a finding, or `None` if never triaged
    /// (treat as [`FindingStatus::Open`]).
    pub fn finding_status(&self, id: FindingId) -> Result<Option<(FindingStatus, Option<String>)>> {
        let row = self
            .conn
            .query_row(
                "SELECT status, note FROM finding_status WHERE finding_id = ?1",
                params![id.0],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
            )
            .optional()?;
        Ok(row.map(|(s, n)| (FindingStatus::parse(&s).unwrap_or(FindingStatus::Open), n)))
    }

    /// Save (or overwrite) a named CamioQL search (plan §F07).
    pub fn save_search(&mut self, name: &str, query: &str) -> Result<()> {
        // Bound the name like the sibling saved-object APIs: an empty or
        // unbounded name is an operator-visible defect, not a silent row.
        ensure!(
            !name.trim().is_empty() && name.len() <= 100,
            "saved-search name supports 1-100 bytes"
        );
        self.conn.execute(
            "INSERT INTO saved_search (name, query, created_at_ms) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET query = excluded.query",
            params![name, query, now_ms()],
        )?;
        Ok(())
    }

    /// The CamioQL text of a saved search, if it exists.
    pub fn saved_search(&self, name: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT query FROM saved_search WHERE name = ?1",
                params![name],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
    }

    /// All saved searches as `(name, query)`, by name.
    pub fn list_saved_searches(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, query FROM saved_search ORDER BY name")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Delete a saved search; returns whether a row was removed.
    pub fn delete_saved_search(&mut self, name: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM saved_search WHERE name = ?1", params![name])?;
        Ok(n > 0)
    }

    /// Attach a label to an exchange (plan §F18). Idempotent.
    pub fn add_label(&mut self, id: ExchangeId, label: &str) -> Result<()> {
        ensure!(
            !label.trim().is_empty() && label.len() <= 120,
            "a label supports 1-120 bytes"
        );
        self.conn.execute(
            "INSERT OR IGNORE INTO exchange_label (exchange_id, label, created_at_ms)
             VALUES (?1, ?2, ?3)",
            params![id.0, label.trim(), now_ms()],
        )?;
        Ok(())
    }

    /// Remove a label from an exchange; returns whether a row was removed.
    pub fn remove_label(&mut self, id: ExchangeId, label: &str) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM exchange_label WHERE exchange_id = ?1 AND label = ?2",
            params![id.0, label.trim()],
        )?;
        Ok(n > 0)
    }

    /// The labels on one exchange, sorted.
    pub fn labels_for(&self, id: ExchangeId) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT label FROM exchange_label WHERE exchange_id = ?1 ORDER BY label")?;
        let rows = stmt.query_map(params![id.0], |r| r.get::<_, String>(0))?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Exchange ids carrying `label`, newest first.
    pub fn exchanges_with_label(&self, label: &str) -> Result<Vec<ExchangeId>> {
        let mut stmt = self.conn.prepare(
            "SELECT exchange_id FROM exchange_label WHERE label = ?1 ORDER BY exchange_id DESC",
        )?;
        let rows = stmt.query_map(params![label.trim()], |r| r.get::<_, i64>(0))?;
        Ok(rows.filter_map(Result::ok).map(ExchangeId).collect())
    }

    /// All labels in use, with how many exchanges carry each, by label.
    pub fn all_labels(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT label, COUNT(*) FROM exchange_label GROUP BY label ORDER BY label")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// All findings with their triage status (default `Open`) and note.
    pub fn list_findings_with_status(
        &self,
    ) -> Result<Vec<(Finding, FindingStatus, Option<String>)>> {
        let findings = self.list_findings()?;
        let mut out = Vec::with_capacity(findings.len());
        for f in findings {
            let (status, note) = self
                .finding_status(f.id)?
                .unwrap_or((FindingStatus::Open, None));
            out.push((f, status, note));
        }
        Ok(out)
    }
}

/// Store a body as a content-addressed blob (deduplicated); returns its sha, or
/// `None` for an empty body.
fn store_blob(conn: &Connection, body: &Body) -> Result<Option<String>> {
    if body.is_empty() {
        return Ok(None);
    }
    let sha = sha256_hex(body.as_bytes());
    conn.execute(
        "INSERT OR IGNORE INTO blobs (sha, bytes) VALUES (?1, ?2)",
        params![sha, body.as_bytes()],
    )?;
    Ok(Some(sha))
}

/// A cross-run deduplication signature for a finding: its producing check
/// (`rule`), title, sorted evidence-exchange set, and `detail`. Two findings
/// with the same signature are the same occurrence (plan §F14).
///
/// `detail` is part of the key because some sources (notably Nuclei) carry the
/// distinguishing location — the matched URL — only in the detail text and leave
/// `evidence` empty; without it, the same template matching two different URLs
/// would collapse to one stored row. Check `detail` strings are deterministic
/// (templated from input names/status, never response bodies or timestamps), so
/// re-scanning the same data still dedups.
fn finding_signature(finding: &Finding) -> String {
    let mut evidence: Vec<i64> = finding.evidence.iter().map(|e| e.0).collect();
    evidence.sort_unstable();
    let evidence: Vec<String> = evidence.iter().map(|n| n.to_string()).collect();
    format!(
        "{}\u{1}{}\u{1}{}\u{1}{}",
        finding.rule.as_deref().unwrap_or(""),
        finding.title,
        evidence.join(","),
        finding.detail,
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    // Hex by `format!` per byte: appending to a String cannot fail, so there is
    // no `Result` to discard in the first place.
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS blobs (
    sha   TEXT PRIMARY KEY,
    bytes BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS exchanges (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at_ms INTEGER NOT NULL,
    source        TEXT NOT NULL,
    scope         TEXT,
    fingerprint   TEXT,
    method        TEXT NOT NULL,
    url           TEXT NOT NULL,
    host          TEXT,
    port          INTEGER,
    path          TEXT,
    ext           TEXT,
    req_len       INTEGER NOT NULL,
    req_body_sha  TEXT,
    has_response  INTEGER NOT NULL,
    resp_status   INTEGER,
    resp_len      INTEGER,
    resp_body_sha TEXT,
    roundtrip_ms  INTEGER,
    note          TEXT,
    meta_json     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exchanges_host    ON exchanges(host);
CREATE INDEX IF NOT EXISTS idx_exchanges_status  ON exchanges(resp_status);
CREATE INDEX IF NOT EXISTS idx_exchanges_created ON exchanges(created_at_ms);
CREATE INDEX IF NOT EXISTS idx_exchanges_source  ON exchanges(source);
CREATE INDEX IF NOT EXISTS idx_exchanges_method  ON exchanges(method);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    confidence    TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    data_json     TEXT NOT NULL
);
-- Dedup (find_duplicate) looks findings up by title; index it so a batch save
-- is indexed lookups rather than a full scan per finding (plan §F14).
CREATE INDEX IF NOT EXISTS idx_findings_title ON findings(title);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{
        Body, Confidence, HeaderList, HttpRequest, HttpResponse, HttpVersion, Severity, Source,
    };

    fn exchange(url: &str, status: u16, body: &str) -> HttpExchange {
        let mut req = HttpRequest::get(url);
        req.headers.push("User-Agent", "camio-test");
        let mut rh = HeaderList::new();
        rh.push("Content-Type", "text/html");
        let resp = HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers: rh,
            body: Body::from_text(body),
        };
        HttpExchange::new(req, Source::Replay).with_response(resp)
    }

    #[test]
    fn insert_and_get_roundtrips_exact_bytes() {
        let mut store = Store::open_in_memory().unwrap();
        let ex = exchange("https://example.com/a", 200, "hello world");
        let id = store.insert(&ex).unwrap();

        let got = store.get(id).unwrap().unwrap();
        assert_eq!(got.id, id);
        assert_eq!(got.request.url, "https://example.com/a");
        assert_eq!(got.response.as_ref().unwrap().status, 200);
        assert_eq!(got.response.as_ref().unwrap().body.as_text(), "hello world");
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn a_limit_smaller_than_the_table_returns_exactly_that_many_rows() {
        // `query_exchanges` walks the table and keeps what matches, so the
        // limit is the only thing bounding the result set.
        let mut store = Store::open_in_memory().unwrap();
        for i in 0..50 {
            store
                .insert(&exchange(&format!("https://x.test/{i}"), 200, "b"))
                .unwrap();
        }
        let all = store
            .query(&Query::compile("").unwrap(), usize::MAX)
            .unwrap();
        assert_eq!(
            all.len(),
            50,
            "a limit above the row count returns them all"
        );
        assert_eq!(
            store.query(&Query::compile("").unwrap(), 7).unwrap().len(),
            7,
            "a limit below the row count returns exactly that many"
        );
    }

    // Slow by necessity (~14 s in a debug build): proving the ceiling means a
    // table LARGER than MAX_PAGE_LIMIT. Run it deliberately with
    // `cargo test -p camio-store -- --ignored`.
    #[test]
    #[ignore = "slow: proves MAX_PAGE_LIMIT end-to-end against a bigger table"]
    fn an_absurd_limit_is_clamped_to_the_page_ceiling() {
        // `query_exchanges` walks the table with no SQL LIMIT, so a limit of
        // usize::MAX used to turn one call into a full-table materialisation.
        // This needs a table LARGER than the ceiling to distinguish the
        // clamped call from the unclamped one, so it is the slow test in the
        // file by design.
        let mut store = Store::open_in_memory().unwrap();
        let rows = MAX_PAGE_LIMIT + 3;
        for i in 0..rows {
            store
                .insert(&exchange(&format!("https://x.test/{i}"), 200, "b"))
                .unwrap();
        }
        let capped = store
            .query(&Query::compile("").unwrap(), usize::MAX)
            .unwrap();
        assert_eq!(
            capped.len(),
            MAX_PAGE_LIMIT,
            "the store answers at most MAX_PAGE_LIMIT rows, however large the \
             requested limit"
        );
        assert_eq!(
            store
                .query(&Query::compile("").unwrap(), MAX_PAGE_LIMIT + 100)
                .unwrap()
                .len(),
            MAX_PAGE_LIMIT,
            "asking for more than the ceiling is capped, not rejected"
        );
    }

    #[test]
    fn bounded_limit_clamps_a_caller_supplied_row_count() {
        assert_eq!(bounded_limit(None, 1000), 1000, "absent → default");
        assert_eq!(bounded_limit(Some(0), 1000), 1, "zero → one row, not none");
        assert_eq!(
            bounded_limit(Some(u64::MAX), 1000),
            MAX_PAGE_LIMIT,
            "an enormous limit is capped, not cast (the cast silently \
             truncates on a 32-bit target)"
        );
        assert_eq!(
            bounded_limit(Some(MAX_PAGE_LIMIT as u64 + 1), 1000),
            MAX_PAGE_LIMIT
        );
        assert_eq!(bounded_limit(None, 0), 1, "a zero default yields one row");
        assert_eq!(bounded_limit(None, usize::MAX), MAX_PAGE_LIMIT);
    }

    #[test]
    fn bodies_are_deduplicated() {
        let mut store = Store::open_in_memory().unwrap();
        // Same body text in three exchanges → one blob.
        for i in 0..3 {
            store
                .insert(&exchange(
                    &format!("https://x.test/{i}"),
                    200,
                    "identical body",
                ))
                .unwrap();
        }
        assert_eq!(store.count().unwrap(), 3);
        assert_eq!(
            store.blob_count().unwrap(),
            1,
            "identical bodies should dedup to one blob"
        );
    }

    #[test]
    fn query_filters_with_camioql() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert(&exchange("https://a.test/", 200, "ok"))
            .unwrap();
        store
            .insert(&exchange("https://b.test/", 500, "boom"))
            .unwrap();
        store
            .insert(&exchange("https://c.test/", 404, "missing"))
            .unwrap();

        let errors = store
            .query(&Query::compile("resp.code.gte:500").unwrap(), 100)
            .unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].request.host().as_deref(), Some("b.test"));

        // Metadata-only query must not need bodies.
        let q = Query::compile("resp.code.gte:400").unwrap();
        assert!(!q.needs_body());
        assert_eq!(store.query(&q, 100).unwrap().len(), 2);
    }

    #[test]
    fn body_query_loads_blobs() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert(&exchange("https://a.test/", 200, "nothing here"))
            .unwrap();
        store
            .insert(&exchange("https://b.test/", 200, "secret token leaked"))
            .unwrap();

        let q = Query::compile(r#"resp.body.cont:"secret""#).unwrap();
        assert!(q.needs_body());
        let hits = store.query(&q, 100).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].request.host().as_deref(), Some("b.test"));
    }

    #[test]
    fn recent_is_newest_first() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert(&exchange("https://1.test/", 200, "a"))
            .unwrap();
        store
            .insert(&exchange("https://2.test/", 200, "b"))
            .unwrap();
        let recent = store.recent(10).unwrap();
        assert_eq!(recent[0].request.host().as_deref(), Some("2.test"));
        assert_eq!(recent[1].request.host().as_deref(), Some("1.test"));
    }

    #[test]
    fn findings_persist_and_sort_by_severity() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert_finding(&Finding {
                id: FindingId(0),
                title: "Reflected XSS".into(),
                severity: Severity::High,
                confidence: Confidence::Firm,
                detail: "param `q` reflected".into(),
                evidence: vec![ExchangeId(1)],
                created_at_ms: 0,
                rule: None,
            })
            .unwrap();
        store
            .insert_finding(&Finding {
                id: FindingId(0),
                title: "Missing header".into(),
                severity: Severity::Low,
                confidence: Confidence::Certain,
                detail: "no X-Frame-Options".into(),
                evidence: vec![],
                created_at_ms: 0,
                rule: None,
            })
            .unwrap();

        let findings = store.list_findings().unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High); // most severe first
    }

    #[test]
    fn identical_findings_are_deduplicated_across_inserts() {
        let mut store = Store::open_in_memory().unwrap();
        let f = Finding {
            id: FindingId(0),
            title: "Reflected XSS".into(),
            severity: Severity::High,
            confidence: Confidence::Firm,
            detail: "param `q`".into(),
            evidence: vec![ExchangeId(1)],
            created_at_ms: 0,
            rule: Some("reflected-xss".into()),
        };
        // Same finding (same rule/title/evidence) inserted twice → one row.
        let first = store.insert_finding(&f).unwrap();
        let second = store.insert_finding(&f).unwrap();
        assert_eq!(first, second, "duplicate returns the existing id");
        assert_eq!(store.list_findings().unwrap().len(), 1);

        // A batch re-insert reports zero new rows.
        assert_eq!(store.insert_findings(&[f.clone(), f.clone()]).unwrap(), 0);
        assert_eq!(store.list_findings().unwrap().len(), 1);

        // Different evidence is a distinct occurrence and IS stored.
        let mut g = f.clone();
        g.evidence = vec![ExchangeId(2)];
        assert_eq!(store.insert_findings(&[g]).unwrap(), 1);
        assert_eq!(store.list_findings().unwrap().len(), 2);
    }

    #[test]
    fn severity_counts_group_and_rank() {
        let mut store = Store::open_in_memory().unwrap();
        let mk = |title: &str, sev: Severity| Finding {
            id: FindingId(0),
            title: title.into(),
            severity: sev,
            confidence: Confidence::Firm,
            detail: String::new(),
            evidence: vec![],
            created_at_ms: 0,
            rule: None,
        };
        store.insert_finding(&mk("a", Severity::Low)).unwrap();
        store.insert_finding(&mk("b", Severity::High)).unwrap();
        store.insert_finding(&mk("c", Severity::High)).unwrap();
        let counts = store.findings_severity_counts().unwrap();
        // Ranked most-severe first.
        assert_eq!(counts, vec![("high".to_string(), 2), ("low".to_string(), 1)]);
    }

    #[test]
    fn evidenceless_findings_are_distinguished_by_detail() {
        // Nuclei-style findings carry no evidence and the same template title/
        // rule; the matched URL lives in `detail`. They must NOT collapse.
        let mut store = Store::open_in_memory().unwrap();
        let mk = |detail: &str| Finding {
            id: FindingId(0),
            title: "Exposed .git directory".into(),
            severity: Severity::Medium,
            confidence: Confidence::Firm,
            detail: detail.into(),
            evidence: vec![],
            created_at_ms: 0,
            rule: Some("git-config".into()),
        };
        let a = mk("- Matched at: `https://x.test/admin/.git/`\n");
        let b = mk("- Matched at: `https://x.test/app/.git/`\n");
        assert_eq!(store.insert_findings(&[a.clone(), b, a]).unwrap(), 2);
        assert_eq!(store.list_findings().unwrap().len(), 2);
    }

    #[test]
    fn finding_triage_status_roundtrip() {
        let mut store = Store::open_in_memory().unwrap();
        let id = store
            .insert_finding(&Finding {
                id: FindingId(0),
                title: "Open redirect".into(),
                severity: Severity::Medium,
                confidence: Confidence::Firm,
                detail: "d".into(),
                evidence: vec![],
                created_at_ms: 0,
                rule: None,
            })
            .unwrap();

        // Untriaged findings default to Open.
        assert!(store.finding_status(id).unwrap().is_none());
        let listed = store.list_findings_with_status().unwrap();
        assert_eq!(listed[0].1, FindingStatus::Open);

        // Confirm with a note, then re-classify as false positive clearing it.
        store
            .set_finding_status(id, FindingStatus::Confirmed, Some("verified"))
            .unwrap();
        let (s, note) = store.finding_status(id).unwrap().unwrap();
        assert_eq!(s, FindingStatus::Confirmed);
        assert_eq!(note.as_deref(), Some("verified"));

        store
            .set_finding_status(id, FindingStatus::FalsePositive, None)
            .unwrap();
        let (s2, note2) = store.finding_status(id).unwrap().unwrap();
        assert_eq!(s2, FindingStatus::FalsePositive);
        assert!(note2.is_none());
    }

    #[test]
    fn backup_produces_a_reopenable_copy() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert(&exchange("https://b.test/", 200, "x"))
            .unwrap();
        store.save_search("q", "resp.code.eq:200").unwrap();

        let dir = std::env::temp_dir().join(format!("camio-bk-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let dest = dir.join("backup.db");
        let _ = std::fs::remove_file(&dest);
        store.backup_to(&dest).unwrap();
        assert!(dest.exists());
        // Refusing to overwrite an existing file.
        assert!(store.backup_to(&dest).is_err());

        let reopened = Store::open(&dest).unwrap();
        assert_eq!(reopened.count().unwrap(), 1);
        assert_eq!(
            reopened.saved_search("q").unwrap().as_deref(),
            Some("resp.code.eq:200")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exchange_labels_roundtrip() {
        let mut store = Store::open_in_memory().unwrap();
        let a = store
            .insert(&exchange("https://a.test/", 200, "x"))
            .unwrap();
        let b = store
            .insert(&exchange("https://b.test/", 200, "y"))
            .unwrap();

        store.add_label(a, "review").unwrap();
        store.add_label(a, "auth").unwrap();
        store.add_label(a, "review").unwrap(); // idempotent
        store.add_label(b, "auth").unwrap();

        assert_eq!(store.labels_for(a).unwrap(), vec!["auth", "review"]);
        assert_eq!(store.exchanges_with_label("auth").unwrap().len(), 2);
        assert_eq!(store.exchanges_with_label("review").unwrap(), vec![a]);
        assert_eq!(
            store.all_labels().unwrap(),
            vec![("auth".to_string(), 2), ("review".to_string(), 1)]
        );

        assert!(store.remove_label(a, "auth").unwrap());
        assert!(!store.remove_label(a, "auth").unwrap());
        assert_eq!(store.labels_for(a).unwrap(), vec!["review"]);
    }

    #[test]
    fn saved_searches_roundtrip() {
        let mut store = Store::open_in_memory().unwrap();
        assert!(store.saved_search("5xx").unwrap().is_none());
        store.save_search("5xx", "resp.code.gte:500").unwrap();
        store.save_search("api", "req.host.cont:\"api\"").unwrap();
        assert_eq!(
            store.saved_search("5xx").unwrap().as_deref(),
            Some("resp.code.gte:500")
        );
        // Overwrite.
        store.save_search("5xx", "resp.code.gte:599").unwrap();
        assert_eq!(
            store.saved_search("5xx").unwrap().as_deref(),
            Some("resp.code.gte:599")
        );
        let all = store.list_saved_searches().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0, "5xx"); // sorted by name
        assert!(store.delete_saved_search("api").unwrap());
        assert!(!store.delete_saved_search("api").unwrap());
        assert_eq!(store.list_saved_searches().unwrap().len(), 1);
    }

    #[test]
    fn migrates_unversioned_history_and_pages_without_body_placeholders() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let binary = vec![0xa5; INSPECT_BYTES as usize + 1];
        let mut record = exchange("https://project.test/a", 204, "");
        record.request.body = Body::from_bytes(binary.clone());
        record.request.headers.push("x-Duplicate", "one");
        record.request.headers.push("X-Duplicate", "two");
        let (older, _) = Store::write_exchange_record(&conn, &record).unwrap();
        record.request.url = "https://project.test/b".into();
        let (newer, _) = Store::write_exchange_record(&conn, &record).unwrap();

        let store = Store::init(conn).unwrap();
        let filter = Query::compile("req.len.gt:65536 AND resp.code:204").unwrap();
        let one = store.history_page(&filter, None, 1).unwrap();
        assert_eq!(one.exchanges[0].id, newer);
        assert_eq!(one.next_before, Some(newer));
        let two = store.history_page(&filter, one.next_before, 1).unwrap();
        assert_eq!(two.exchanges[0].id, older);
        assert!(two.next_before.is_none());
        let inspector = store.inspect_exchange(older).unwrap().unwrap();
        assert_eq!(inspector.req_len, INSPECT_BYTES + 1);
        assert_eq!(
            inspector.exchange.request.body.as_bytes(),
            &binary[..INSPECT_BYTES as usize]
        );
        assert_eq!(inspector.exchange.request.headers, record.request.headers);
        assert_eq!(
            store.get(older).unwrap().unwrap().request.body.as_bytes(),
            binary
        );
        assert!(store.workspace().is_ok());
        let asset = store.asset_inventory("https://project.test", None).unwrap();
        assert_eq!(asset.asset.captured, 2);
        assert_eq!(asset.endpoints.len(), 2);
    }

    #[test]
    fn preserves_imported_artifacts_and_distinguishes_tool_errors() {
        let mut store = Store::open_in_memory().unwrap();
        let input = concat!(
            r#"{"url":"https://left:right@EXAMPLE.test:8443/a?secret=value","status_code":429,"title":"Start"}"#,
            "\ninvalid\n",
            r#"{"input":"https://other.test/","failed":true}"#,
        );
        let preview = store
            .import_artifact(ArtifactFormat::Httpx, input, None, false)
            .unwrap();
        assert_eq!(
            (preview.records, preview.skipped, preview.artifact_id),
            (2, 1, None)
        );
        assert_eq!(preview.sample[0].location, "https://example.test:8443/a");
        let report = store
            .import_artifact(ArtifactFormat::Httpx, input, None, true)
            .unwrap();
        let id = report.artifact_id.unwrap();
        assert_eq!(store.artifact_text(id).unwrap().as_deref(), Some(input));
        assert_eq!(
            store.observations(id, None).unwrap().observations[0].outcome,
            "probe failed"
        );
        assert!(
            store
                .import_artifact(ArtifactFormat::Httpx, input, None, true)
                .unwrap()
                .existing
        );
        assert_eq!(store.artifacts(None).unwrap().len(), 1);

        let findings = concat!(
            r#"{"template-id":"header-review","matched-at":"https://sample.test/page","info":{"name":"Header review","severity":"low"}}"#,
            "\n",
            r#"{"template-id":"header-review","matched-at":"https://sample.test/page","matcher-status":false}"#,
        );
        let nuclei = store
            .import_artifact(ArtifactFormat::Nuclei, findings, None, true)
            .unwrap();
        assert_eq!(nuclei.records, 2);
        assert_eq!(nuclei.sample[0].outcome, "unverified observation");
        assert_eq!(nuclei.sample[1].outcome, "no match");
        assert!(store.list_findings().unwrap().is_empty());
    }

    #[test]
    fn cancelled_reviews_cannot_commit_and_reports_exclude_notes() {
        let mut store = Store::open_in_memory().unwrap();
        let id = store.queue_review("", 2, true).unwrap();
        assert!(store.start_review(id).unwrap());
        let candidate = ReviewCandidate {
            rule: "test-check",
            host: "sample.test".into(),
            finding: Finding {
                id: FindingId(0),
                title: "Raw title marker".into(),
                severity: Severity::Low,
                confidence: Confidence::Firm,
                detail: "Raw detail marker".into(),
                evidence: Vec::new(),
                created_at_ms: 0,
                rule: None,
            },
        };
        assert!(store
            .commit_review(
                id,
                &ReviewCounts::default(),
                std::slice::from_ref(&candidate),
                true
            )
            .unwrap());
        assert!(store.cancel_review(id).unwrap());
        assert!(!store
            .commit_review(id, &ReviewCounts::default(), &[candidate], true)
            .unwrap());
        let findings = store.finding_reviews(None, 0, 10).unwrap();
        assert_eq!(findings.len(), 1);
        let finding = findings[0].finding.id;
        store
            .update_finding_review(finding, ReviewState::Confirmed, "Raw notes marker")
            .unwrap();
        let report = store.finding_report(Some(ReviewState::Confirmed)).unwrap();
        for format in ReportFormat::ALL {
            let output = report.render(format).unwrap();
            assert!(output.contains("test-check"));
            assert!(!output.contains("marker"));
            assert_eq!(report.render(format).unwrap(), output);
        }
        let sarif: serde_json::Value =
            serde_json::from_str(&report.render(ReportFormat::Sarif).unwrap()).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["camioTriageStatus"],
            "confirmed"
        );
        assert_eq!(
            store.review_task(id).unwrap().unwrap().task.state,
            camio_core::TaskState::Cancelled
        );
    }

    #[test]
    fn migrates_v7_workspaces_and_adds_task_records() {
        // A v7 workspace (labels, findings triage, saved searches) opens on v8
        // with prior data intact and the new durable task table ready.
        let conn = Connection::open_in_memory().unwrap();
        for schema in [
            SCHEMA,
            workspace::SCHEMA,
            review::SCHEMA,
            evidence::SCHEMA,
            FINDING_STATUS_SCHEMA,
            SAVED_SEARCH_SCHEMA,
            EXCHANGE_LABEL_SCHEMA,
        ] {
            conn.execute_batch(schema).unwrap();
        }
        conn.pragma_update(None, "user_version", 7).unwrap();
        conn.execute(
            "INSERT INTO exchange_label(exchange_id, label, created_at_ms) VALUES (1, 'triage', 5)",
            [],
        )
        .unwrap();
        let store = Store::init(conn).unwrap();
        // Old data survived.
        assert_eq!(store.all_labels().unwrap(), vec![("triage".to_string(), 1)]);
        // New table works.
        store
            .save_task(&TaskRow {
                id: 1,
                kind: "scan".into(),
                state: camio_core::TaskState::Running,
                progress_done: 0,
                progress_total: None,
                message: String::new(),
                result: None,
                error: None,
                outcome: None,
                created_at_ms: 1,
                updated_at_ms: 1,
            })
            .unwrap();
        assert_eq!(
            store.task(1).unwrap().unwrap().state,
            camio_core::TaskState::Running
        );
        assert_eq!(store.reconcile_interrupted_tasks().unwrap(), 1);
        assert_eq!(
            store.task(1).unwrap().unwrap().state,
            camio_core::TaskState::Interrupted
        );
    }

    #[test]
    fn baselines_point_at_an_exchange_and_repoint_cleanly() {
        let mut store = Store::open_in_memory().unwrap();
        let a = store
            .insert(&HttpExchange::new(
                HttpRequest::get("https://x.test/a"),
                Source::Replay,
            ))
            .unwrap();
        let b = store
            .insert(&HttpExchange::new(
                HttpRequest::get("https://x.test/b"),
                Source::Replay,
            ))
            .unwrap();
        store.set_baseline("prod", a).unwrap();
        assert_eq!(store.baseline("prod").unwrap(), Some(a));
        // Re-pointing is an upsert, not a duplicate.
        store.set_baseline("prod", b).unwrap();
        assert_eq!(store.baseline("prod").unwrap(), Some(b));
        assert_eq!(store.baselines().unwrap().len(), 1);
        // Deleting a baseline leaves the referenced exchange intact.
        assert!(store.delete_baseline("prod").unwrap());
        assert_eq!(store.baseline("prod").unwrap(), None);
        assert!(store.get(b).unwrap().is_some());
    }

    #[test]
    fn migrates_v9_store_and_adds_the_audit_log() {
        // A v9 store (OAST interactions table present) opens on v10 with prior
        // data intact and the new append-only audit table ready to use.
        let conn = Connection::open_in_memory().unwrap();
        for schema in [
            SCHEMA,
            workspace::SCHEMA,
            review::SCHEMA,
            evidence::SCHEMA,
            FINDING_STATUS_SCHEMA,
            SAVED_SEARCH_SCHEMA,
            EXCHANGE_LABEL_SCHEMA,
            tasks::SCHEMA,
            OAST_INTERACTION_SCHEMA,
        ] {
            conn.execute_batch(schema).unwrap();
        }
        conn.pragma_update(None, "user_version", 9).unwrap();
        conn.execute(
            "INSERT INTO oast_interactions(method, target, source, received_at_ms)
             VALUES ('GET', 'x.test', 'http', 5)",
            [],
        )
        .unwrap();
        let store = Store::init(conn).unwrap();
        // Old data survived the migration.
        assert_eq!(store.oast_interactions(10).unwrap().len(), 1);
        // The new audit table exists and is usable.
        store
            .record_audit(&NewAudit::new("cli", "ACTIVE", "send", "allowed").target("x.test"))
            .unwrap();
        let rows = store.audit_log(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target.as_deref(), Some("x.test"));
    }

    #[test]
    fn saved_workflow_runs_keep_the_selected_version_across_edits() {
        let conn = Connection::open_in_memory().unwrap();
        for schema in [SCHEMA, workspace::SCHEMA, review::SCHEMA, evidence::SCHEMA] {
            conn.execute_batch(schema).unwrap();
        }
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute_batch(
            "INSERT INTO review_tasks(state, query, scan_limit, save, created_at_ms, updated_at_ms)
            VALUES ('completed', '', 50, 0, 1, 1)",
        )
        .unwrap();
        let mut store = Store::init(conn).unwrap();
        assert!(store.review_tasks().unwrap()[0].workflow.is_none());

        let older_plan = ReviewPlan::new("resp.code.eq:200", 17, false);
        let older = store
            .save_review_workflow("Header review", &older_plan)
            .unwrap();
        let retry = store
            .save_review_workflow("Header review", &older_plan)
            .unwrap();
        assert_eq!(retry.revision, older.revision);
        let newer = store
            .save_review_workflow("Header review", &ReviewPlan::new("", 30, true))
            .unwrap();
        assert_eq!(store.review_workflows().unwrap().len(), 1);
        assert_eq!(newer.revision.id, older.revision.id);
        assert_eq!(
            store
                .review_workflow_versions(older.revision.id)
                .unwrap()
                .len(),
            2
        );

        let (task, filter) = store
            .queue_saved_review(older.revision.id, Some(older.revision.version))
            .unwrap();
        assert_eq!(filter.source(), "resp.code.eq:200");
        let task = store.review_task(task).unwrap().unwrap();
        assert_eq!(task.workflow.unwrap(), older.revision);
        assert_eq!(task.limit, 17);
        assert!(!task.save);
    }
}

#[cfg(test)]
mod metadata_query_tests {
    use super::*;
    use camio_core::{HeaderList, HttpExchange, HttpRequest, HttpResponse, HttpVersion, Source};

    fn big(url: &str) -> HttpExchange {
        let mut req = HttpRequest::get(url);
        req.body = Body::from_bytes(vec![b'a'; 4096]);
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_bytes(vec![b'b'; 8192]),
        };
        HttpExchange::new(req, Source::Replay).with_response(resp)
    }

    #[test]
    fn metadata_query_loads_no_body_bytes() {
        let mut store = Store::open_in_memory().unwrap();
        store.insert(&big("https://ex.test/a")).unwrap();
        store.insert(&big("https://ex.test/b")).unwrap();

        let query = Query::compile("").unwrap();
        let meta = store.query_metadata(&query, 100).unwrap();
        assert_eq!(meta.len(), 2);
        for ex in &meta {
            assert!(
                ex.request.body.is_empty(),
                "metadata queries must not allocate body bytes"
            );
            assert!(
                ex.response
                    .as_ref()
                    .map(|r| r.body.is_empty())
                    .unwrap_or(true),
                "metadata queries must not allocate response bytes"
            );
        }
        // URL metadata is still there — the site map works from it.
        assert_eq!(meta[0].request.url, "https://ex.test/b");

        // The full-body path still loads real bytes.
        let full = store.query_with_bodies(&query, 100).unwrap();
        assert_eq!(full[0].request.body.len(), 4096);
        assert_eq!(full[0].response.as_ref().unwrap().body.len(), 8192);
    }
}

#[cfg(test)]
mod scan_budget_tests {
    use super::*;
    use camio_core::{HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn big(url: &str, body_len: usize) -> HttpExchange {
        let mut req = HttpRequest::get(url);
        req.body = Body::from_bytes(vec![b'a'; body_len]);
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_bytes(vec![b'b'; body_len]),
        };
        HttpExchange::new(req, Source::Replay).with_response(resp)
    }

    #[test]
    fn the_byte_budget_skips_oversized_bodies() {
        let mut store = Store::open_in_memory().unwrap();
        store.insert(&big("https://ex.test/a", 1024)).unwrap();
        store.insert(&big("https://ex.test/b", 4096)).unwrap();
        store.insert(&big("https://ex.test/c", 1024)).unwrap();

        // A body filter loads real bodies, so the byte budget engages: it fits
        // only the two 1024-byte rows, not the 4096-byte one.
        let (rows, skipped) = store
            .query_for_scan(&Query::compile(r#"resp.body.cont:"b""#).unwrap(), 100, 4096)
            .unwrap();
        assert!(rows.len() <= 2, "returned {} rows", rows.len());
        assert_eq!(
            skipped + rows.len(),
            3,
            "every row is either scanned or reported skipped"
        );
        assert_eq!(
            rows.iter()
                .map(|r| r.request.url.clone())
                .collect::<Vec<_>>(),
            vec!["https://ex.test/c", "https://ex.test/a"],
            "newest first, no body placeholders"
        );
    }

    #[test]
    fn a_zero_budget_returns_nothing() {
        let mut store = Store::open_in_memory().unwrap();
        store.insert(&big("https://ex.test/a", 16)).unwrap();
        let (rows, skipped) = store
            .query_for_scan(&Query::compile(r#"resp.body.cont:"b""#).unwrap(), 100, 0)
            .unwrap();
        assert!(rows.is_empty());
        assert_eq!(skipped, 0, "a zero budget scans nothing, not even one row");
    }
}

#[cfg(test)]
mod pushdown_tests {
    use super::*;
    use camio_core::{HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(url: &str, status: u16, source: Source, host: &str) -> HttpExchange {
        let mut req = HttpRequest::get(url);
        req.headers.push("Host", host);
        let resp = HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text("body-bytes"),
        };
        HttpExchange::new(req, source).with_response(resp)
    }

    #[test]
    fn the_metadata_predicate_is_pushed_into_sql_and_results_are_exact() {
        let mut store = Store::open_in_memory().unwrap();
        for i in 0..50 {
            let host = if i % 2 == 0 { "even.test" } else { "odd.test" };
            store
                .insert(&exchange(
                    &format!("https://{host}/{i}"),
                    200,
                    Source::Replay,
                    host,
                ))
                .unwrap();
        }
        // Only even.test matches; the SQL prefilter narrows the scan, the
        // Rust-side match still decides, so exactly 25 rows come back.
        let rows = store
            .query_metadata(&Query::compile(r#"req.host.eq:"even.test""#).unwrap(), 100)
            .unwrap();
        assert_eq!(rows.len(), 25);
        assert!(rows.iter().all(|r| r.request.url.contains("even.test")));

        // A status predicate is pushed too.
        let not_found = store
            .query_metadata(&Query::compile("resp.code.eq:404").unwrap(), 100)
            .unwrap();
        assert!(not_found.is_empty());

        // A non-pushable query (free text over bodies) still works — bodies are
        // loaded and matched in Rust.
        store
            .insert(&exchange(
                "https://even.test/needle",
                200,
                Source::Replay,
                "even.test",
            ))
            .unwrap();
        let text = store
            .query_metadata(&Query::compile("body-bytes").unwrap(), 100)
            .unwrap();
        assert_eq!(text.len(), 51);
    }
}

#[cfg(test)]
mod multi_predicate_tests {
    use super::*;
    use camio_core::{HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn exchange(url: &str, status: u16, source: Source, host: &str, method: &str) -> HttpExchange {
        let mut req = HttpRequest::get(url);
        req.method = method.to_string();
        req.headers.push("Host", host);
        let resp = HttpResponse {
            status,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text("payload-body"),
        };
        HttpExchange::new(req, source).with_response(resp)
    }

    #[test]
    fn every_predicate_contributes_to_the_sql_narrowing() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert(&exchange(
                "https://a.test/1",
                200,
                Source::Replay,
                "a.test",
                "GET",
            ))
            .unwrap();
        store
            .insert(&exchange(
                "https://a.test/2",
                500,
                Source::Replay,
                "a.test",
                "POST",
            ))
            .unwrap();
        store
            .insert(&exchange(
                "https://b.test/3",
                500,
                Source::Replay,
                "b.test",
                "POST",
            ))
            .unwrap();

        // Two conjuncts: host = a.test AND method = POST. Exactly one row.
        let rows = store
            .query_metadata(
                &Query::compile(r#"req.host.eq:"a.test" AND req.method.eq:"POST""#).unwrap(),
                100,
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].request.url, "https://a.test/2");

        // Three conjuncts (host + method + status) narrow to the same row.
        let rows = store
            .query_metadata(
                &Query::compile(
                    r#"req.host.eq:"a.test" AND req.method.eq:"POST" AND resp.code.gte:500"#,
                )
                .unwrap(),
                100,
            )
            .unwrap();
        assert_eq!(rows.len(), 1);

        // An OR is not narrowed (neither disjunct is required), but the result
        // is still exact.
        let rows = store
            .query_metadata(
                &Query::compile(r#"req.host.eq:"a.test" OR req.host.eq:"b.test""#).unwrap(),
                100,
            )
            .unwrap();
        assert_eq!(rows.len(), 3);
    }
}
