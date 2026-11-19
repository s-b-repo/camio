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

use anyhow::{Context, Result};
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
mod bundle;
mod evidence;
mod history;
mod inventory;
mod report;
mod review;
mod workflow;
mod workspace;

pub use archive::ReviewArchive;
pub use bundle::{ReviewEvidenceBundle, MAX_BUNDLE_BYTES};
pub use evidence::{
    ArtifactFormat, ArtifactImport, ArtifactSummary, Observation, ObservationPage, ARTIFACT_BYTES,
};
pub use history::{ExchangePreview, HistoryPage, HistoryRow, INSPECT_BYTES, REVIEW_BODY_LIMIT};
pub use inventory::{
    Asset, AssetInventory, AssetNote, Endpoint, EndpointEvidence, InventoryEvidence, InventoryPage,
};
pub use report::{FindingReport, ReportFormat};
pub use review::{ReviewCandidate, ReviewCounts, ReviewTask};
pub use workflow::{ReviewPlan, ReviewWorkflow, WorkflowVersion, MAX_REVIEW_EXCHANGES};
pub use workspace::{FindingReview, ReviewState, SavedExchange, SavedQuery, WorkspaceSummary};

const SCHEMA_VERSION: i64 = 5;

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

    /// Convenience: the `limit` most recent exchanges (no filter).
    pub fn recent(&self, limit: usize) -> Result<Vec<HttpExchange>> {
        self.query(&Query::compile("").expect("empty query compiles"), limit)
    }

    // --- Findings (plan §8) -------------------------------------------------

    /// Record a finding, returning its id.
    pub fn insert_finding(&mut self, finding: &Finding) -> Result<FindingId> {
        Self::write_finding(&self.conn, finding)
    }

    pub fn insert_findings(&mut self, findings: &[Finding]) -> Result<usize> {
        let tx = self.conn.transaction()?;
        for finding in findings {
            Self::write_finding(&tx, finding)?;
        }
        tx.commit()?;
        Ok(findings.len())
    }

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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    use std::fmt::Write;
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
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
            })
            .unwrap();

        let findings = store.list_findings().unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High); // most severe first
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
