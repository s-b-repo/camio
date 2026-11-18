use super::{now_ms, Store};
use anyhow::{ensure, Context, Result};
use camio_core::ExchangeId;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use url::Url;

const PAGE_SIZE: usize = 50;

const SCHEMA: &str = r#"
CREATE TABLE inventory_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    origin TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('history', 'httpx', 'nuclei')),
    seen_at_ms INTEGER NOT NULL,
    exchange_id INTEGER UNIQUE REFERENCES exchanges(id) ON DELETE CASCADE,
    observation_id INTEGER UNIQUE REFERENCES observations(id) ON DELETE CASCADE,
    CHECK ((source = 'history' AND exchange_id IS NOT NULL AND observation_id IS NULL)
        OR (source != 'history' AND observation_id IS NOT NULL AND exchange_id IS NULL))
);
CREATE INDEX inventory_by_origin ON inventory_records(origin, endpoint);
CREATE INDEX inventory_by_endpoint ON inventory_records(endpoint, id DESC);
CREATE TABLE asset_notes (
    origin TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    note TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub origin: String,
    pub endpoints: i64,
    pub captured: i64,
    pub httpx: i64,
    pub nuclei: i64,
    pub last_seen_at_ms: i64,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub location: String,
    pub captured: i64,
    pub httpx: i64,
    pub nuclei: i64,
    pub last_seen_at_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssetNote {
    pub label: String,
    pub note: String,
    pub updated_at_ms: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InventoryPage {
    pub assets: Vec<Asset>,
    pub next_after: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssetInventory {
    pub asset: Asset,
    pub note: AssetNote,
    pub endpoints: Vec<Endpoint>,
    pub next_after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryEvidence {
    pub id: i64,
    pub source: String,
    pub seen_at_ms: i64,
    pub exchange_id: Option<ExchangeId>,
    pub artifact_id: Option<i64>,
    pub line: Option<i64>,
    pub status: Option<u16>,
    pub description: Option<String>,
    pub outcome: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EndpointEvidence {
    pub location: String,
    pub records: Vec<InventoryEvidence>,
    pub next_before: Option<i64>,
}

pub(super) fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    {
        let mut stmt = conn.prepare("SELECT id, url, created_at_ms FROM exchanges ORDER BY id")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let url: String = row.get(1)?;
            index_exchange(conn, ExchangeId(row.get(0)?), &url, row.get(2)?)?;
        }
    }
    let mut stmt = conn.prepare(
        "SELECT o.id, CASE WHEN json_valid(o.data_json) THEN json_extract(o.data_json, '$.location') END,
                a.format, a.imported_at_ms
         FROM observations o JOIN evidence_artifacts a ON a.id = o.artifact_id
         WHERE a.format IN ('httpx', 'nuclei') ORDER BY o.id",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        if let Some(location) = row.get::<_, Option<String>>(1)? {
            let source: String = row.get(2)?;
            index_observation(conn, row.get(0)?, &location, &source, row.get(3)?)?;
        }
    }
    Ok(())
}

pub(super) fn index_exchange(conn: &Connection, id: ExchangeId, url: &str, timestamp: i64) -> Result<()> {
    if let Some((origin, endpoint)) = location(url) {
        conn.prepare_cached(
            "INSERT INTO inventory_records(origin, endpoint, source, seen_at_ms, exchange_id)
             VALUES (?1, ?2, 'history', ?3, ?4)",
        )?.execute(params![origin, endpoint, timestamp, id.0])?;
    }
    Ok(())
}

pub(super) fn index_observation(conn: &Connection, id: i64, url: &str, source: &str, timestamp: i64) -> Result<()> {
    if let Some((origin, endpoint)) = location(url) {
        conn.prepare_cached(
            "INSERT INTO inventory_records(origin, endpoint, source, seen_at_ms, observation_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?.execute(params![origin, endpoint, source, timestamp, id])?;
    }
    Ok(())
}

fn location(value: &str) -> Option<(String, String)> {
    let url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") || !url.has_host() {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    let endpoint = format!("{origin}{}", url.path());
    (origin.len() <= 512 && endpoint.len() <= 16_384).then_some((origin, endpoint))
}

const ASSETS: &str = "SELECT r.origin, COUNT(DISTINCT r.endpoint), SUM(r.source = 'history'),
    SUM(r.source = 'httpx'), SUM(r.source = 'nuclei'), MAX(r.seen_at_ms), COALESCE(n.label, '')
    FROM inventory_records r LEFT JOIN asset_notes n ON n.origin = r.origin";

impl Store {
    pub fn inventory(&self, filter: &str, after: Option<&str>) -> Result<InventoryPage> {
        ensure!(filter.len() <= 256 && !after.is_some_and(|value| value.len() > 512), "inventory filters or cursors are too long");
        let sql = format!("{ASSETS} WHERE r.origin > ?1 AND instr(r.origin, ?2) > 0
             GROUP BY r.origin ORDER BY r.origin LIMIT ?3");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![after.unwrap_or(""), filter.trim().to_ascii_lowercase(), (PAGE_SIZE + 1) as i64],
            read_asset,
        )?;
        let mut assets = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let next_after = trim_page(&mut assets).map(|asset| asset.origin.clone());
        Ok(InventoryPage { assets, next_after })
    }

    pub fn asset_inventory(&self, origin: &str, after: Option<&str>) -> Result<AssetInventory> {
        ensure!(origin.len() <= 512 && !after.is_some_and(|value| value.len() > 16_384), "inventory location or cursor is too long");
        let asset = self.conn.query_row(
            &format!("{ASSETS} WHERE r.origin = ?1 GROUP BY r.origin"),
            [origin],
            read_asset,
        ).optional()?.context("asset was not found")?;
        let note = self.conn.query_row(
            "SELECT label, note, updated_at_ms FROM asset_notes WHERE origin = ?1", [origin], |row| Ok(AssetNote {
                label: row.get(0)?, note: row.get(1)?, updated_at_ms: row.get(2)?,
            }),
        ).optional()?.unwrap_or_default();
        let mut stmt = self.conn.prepare(
            "SELECT endpoint, SUM(source = 'history'), SUM(source = 'httpx'), SUM(source = 'nuclei'), MAX(seen_at_ms)
             FROM inventory_records WHERE origin = ?1 AND endpoint > ?2
             GROUP BY endpoint ORDER BY endpoint LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![origin, after.unwrap_or(""), (PAGE_SIZE + 1) as i64], |row| Ok(Endpoint {
            location: row.get(0)?, captured: row.get(1)?, httpx: row.get(2)?,
            nuclei: row.get(3)?, last_seen_at_ms: row.get(4)?,
        }))?;
        let mut endpoints = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let next_after = trim_page(&mut endpoints).map(|endpoint| endpoint.location.clone());
        Ok(AssetInventory { asset, note, endpoints, next_after })
    }

    pub fn endpoint_evidence(&self, endpoint: &str, before: Option<i64>) -> Result<EndpointEvidence> {
        ensure!(endpoint.len() <= 16_384, "inventory location is too long");
        let mut stmt = self.conn.prepare(
            "SELECT r.id, r.source, r.seen_at_ms, r.exchange_id, o.artifact_id, o.line,
                    COALESCE(e.resp_status, json_extract(o.data_json, '$.status')),
                    COALESCE(json_extract(o.data_json, '$.title'), json_extract(o.data_json, '$.template'), e.method),
                    json_extract(o.data_json, '$.outcome')
             FROM inventory_records r
             LEFT JOIN exchanges e ON e.id = r.exchange_id
             LEFT JOIN observations o ON o.id = r.observation_id
             WHERE r.endpoint = ?1 AND r.id < ?2 ORDER BY r.id DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![endpoint, before.unwrap_or(i64::MAX), (PAGE_SIZE + 1) as i64], |row| Ok(InventoryEvidence {
            id: row.get(0)?, source: row.get(1)?, seen_at_ms: row.get(2)?,
            exchange_id: row.get::<_, Option<i64>>(3)?.map(ExchangeId),
            artifact_id: row.get(4)?, line: row.get(5)?, status: row.get(6)?,
            description: row.get(7)?, outcome: row.get(8)?,
        }))?;
        let mut records = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let next_before = trim_page(&mut records).map(|record| record.id);
        Ok(EndpointEvidence { location: endpoint.into(), records, next_before })
    }

    pub fn save_asset_note(&self, origin: &str, label: &str, note: &str) -> Result<()> {
        ensure!(origin.len() <= 512 && label.len() <= 120 && note.len() <= 4096, "use a label of up to 120 bytes and a note of up to 4096 bytes");
        let changed = self.conn.execute(
            "INSERT INTO asset_notes(origin, label, note, updated_at_ms)
             SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM inventory_records WHERE origin = ?1)
             ON CONFLICT(origin) DO UPDATE SET label = excluded.label, note = excluded.note,
                                               updated_at_ms = excluded.updated_at_ms",
            params![origin, label.trim(), note.trim(), now_ms()],
        )?;
        ensure!(changed == 1, "asset was not found");
        Ok(())
    }
}

fn read_asset(row: &Row<'_>) -> rusqlite::Result<Asset> {
    Ok(Asset {
        origin: row.get(0)?, endpoints: row.get(1)?, captured: row.get(2)?,
        httpx: row.get(3)?, nuclei: row.get(4)?, last_seen_at_ms: row.get(5)?, label: row.get(6)?,
    })
}

fn trim_page<T>(page: &mut Vec<T>) -> Option<&T> {
    if page.len() > PAGE_SIZE {
        page.truncate(PAGE_SIZE);
        page.last()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ArtifactFormat;
    use camio_core::{HttpExchange, HttpRequest, Source};

    #[test]
    fn joins_observations_to_an_endpoint_preserving_sources_and_ports() {
        let mut store = Store::open_in_memory().unwrap();
        let request = HttpRequest::get("https://demo:test@site.test:8443/a?secret=one#subject");
        let first = store.insert(&HttpExchange::new(request, Source::Import)).unwrap();
        store.insert(&HttpExchange::new(HttpRequest::get("https://site.test/a"), Source::Import)).unwrap();
        let probe = r#"{"url":"https://site.test:8443/a?other=two","status_code":200,"title":"Recorded page"}"#;
        let httpx = store.import_artifact(ArtifactFormat::Httpx, probe, None, true).unwrap();
        assert!(store.import_artifact(ArtifactFormat::Httpx, probe, None, true).unwrap().existing);
        let nuclei = store.import_artifact(ArtifactFormat::Nuclei,
            r#"{"template-id":"fixture-headers","matched-at":"https://site.test:8443/a","info":{"severity":"info"}}"#,
            None, true).unwrap();
        let page = store.inventory(":8443", None).unwrap();
        assert_eq!(page.assets.len(), 1);
        let asset = &page.assets[0];
        assert_eq!(asset.origin, "https://site.test:8443");
        assert_eq!((asset.endpoints, asset.captured, asset.httpx, asset.nuclei), (1, 1, 1, 1));
        store.save_asset_note(&asset.origin, "Review owner", "Internal note").unwrap();
        let detail = store.asset_inventory(&asset.origin, None).unwrap();
        assert_eq!(detail.note.note, "Internal note");
        assert_eq!(detail.endpoints[0].location, "https://site.test:8443/a");
        let evidence = store.endpoint_evidence(&detail.endpoints[0].location, None).unwrap();
        assert_eq!(evidence.records.len(), 3);
        assert_eq!(evidence.records[0].artifact_id, nuclei.artifact_id);
        assert_eq!(evidence.records[0].outcome.as_deref(), Some("unverified observation"));
        assert_eq!(evidence.records[1].artifact_id, httpx.artifact_id);
        assert_eq!(evidence.records[1].status, Some(200));
        assert_eq!(evidence.records[2].exchange_id, Some(first));
        assert!(store.list_findings().unwrap().is_empty());
    }

    #[test]
    fn origins_page_forward_without_repeating_the_boundary() {
        let mut store = Store::open_in_memory().unwrap();
        for port in 8100..8152 {
            let url = format!("http://origin.test:{port}/path");
            store.insert(&HttpExchange::new(HttpRequest::get(url), Source::Import)).unwrap();
        }
        let first = store.inventory("origin.test", None).unwrap();
        assert_eq!(first.assets.len(), 50);
        let next = store.inventory("origin.test", first.next_after.as_deref()).unwrap();
        assert_eq!(next.assets.len(), 2);
        assert_eq!(next.assets[0].origin, "http://origin.test:8150");
        assert!(next.next_after.is_none());
    }
}
