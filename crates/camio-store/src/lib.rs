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
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// The embedded store.
pub struct Store {
    conn: Connection,
}

/// Columns selected when reconstructing an exchange (keep in sync with
/// [`Store::row_to_exchange`]).
const RECONSTRUCT_COLS: &str = "id, req_len, req_body_sha, resp_len, resp_body_sha, meta_json";

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

    fn init(conn: Connection) -> Result<Self> {
        // WAL + NORMAL keeps writes durable and reads concurrent without the
        // full-sync cost; tuned for an interactive local workbench (plan §5).
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "synchronous", "NORMAL").ok();
        conn.pragma_update(None, "foreign_keys", "ON").ok();

        conn.execute_batch(SCHEMA).context("creating schema")?;
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

        let req_body_sha = store_blob(&tx, &ex.request.body)?;
        let (resp_body_sha, resp_len, resp_status) = match &ex.response {
            Some(r) => (
                store_blob(&tx, &r.body)?,
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

        tx.execute(
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
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(ExchangeId(id))
    }

    /// Fetch one exchange by id (with full bodies).
    pub fn get(&self, id: ExchangeId) -> Result<Option<HttpExchange>> {
        let sql = format!("SELECT {RECONSTRUCT_COLS} FROM exchanges WHERE id = ?1");
        let row = self
            .conn
            .query_row(&sql, params![id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .optional()?;
        match row {
            Some(r) => Ok(Some(self.row_to_exchange(r, true)?)),
            None => Ok(None),
        }
    }

    /// Return the most recent exchanges matching `query`, newest first, capped
    /// at `limit`. Body blobs are loaded only when the query inspects them.
    pub fn query(&self, query: &Query, limit: usize) -> Result<Vec<HttpExchange>> {
        let with_bodies = query.needs_body();
        let sql = format!("SELECT {RECONSTRUCT_COLS} FROM exchanges ORDER BY id DESC");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;

        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let tuple = (
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
            );
            let ex = self.row_to_exchange(tuple, with_bodies)?;
            if query.matches(&ex) {
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

    fn row_to_exchange(
        &self,
        (id, req_len, req_sha, resp_len, resp_sha, meta_json): (
            i64,
            i64,
            Option<String>,
            Option<i64>,
            Option<String>,
            String,
        ),
        with_bodies: bool,
    ) -> Result<HttpExchange> {
        let mut ex: HttpExchange =
            serde_json::from_str(&meta_json).context("deserializing exchange")?;
        ex.id = ExchangeId(id);
        ex.request.body = self.load_body(req_sha, req_len, with_bodies)?;
        if let Some(resp) = ex.response.as_mut() {
            resp.body = self.load_body(resp_sha, resp_len.unwrap_or(0), with_bodies)?;
        }
        Ok(ex)
    }

    /// Reconstitute a body. With `with_bodies == false`, returns a zero-filled
    /// placeholder of the correct length so length/metadata queries stay exact
    /// without paying for the blob read.
    fn load_body(&self, sha: Option<String>, len: i64, with_bodies: bool) -> Result<Body> {
        match sha {
            None => Ok(Body::empty()),
            Some(sha) if with_bodies => {
                let bytes: Vec<u8> = self.conn.query_row(
                    "SELECT bytes FROM blobs WHERE sha = ?1",
                    params![sha],
                    |r| r.get(0),
                )?;
                Ok(Body::from_bytes(bytes))
            }
            Some(_) => Ok(Body::from_bytes(vec![0u8; len.max(0) as usize])),
        }
    }

    // --- Findings (plan §8) -------------------------------------------------

    /// Record a finding, returning its id.
    pub fn insert_finding(&mut self, finding: &Finding) -> Result<FindingId> {
        let created_at = if finding.created_at_ms == 0 {
            now_ms()
        } else {
            finding.created_at_ms
        };
        let mut f = finding.clone();
        f.id = FindingId(0);
        f.created_at_ms = created_at;
        let json = serde_json::to_string(&f)?;
        self.conn.execute(
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
        Ok(FindingId(self.conn.last_insert_rowid()))
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
}
