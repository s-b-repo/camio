use super::Store;
use anyhow::{Context, Result};
use camio_core::camioql::{Operator, QueryTarget, RequiredMetadata};
use camio_core::{Body, ExchangeId, HttpExchange, Query};
use rusqlite::{params, params_from_iter, types::Value, Row};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

pub const INSPECT_BYTES: i64 = 65_536;
pub const REVIEW_BODY_LIMIT: i64 = 2 * 1024 * 1024;
const HISTORY_WINDOW: usize = 2048;
pub(super) const EXCHANGE_COLUMNS: &str =
    "id, req_len, req_body_sha, resp_len, resp_body_sha, created_at_ms, meta_json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRow {
    pub id: ExchangeId,
    pub method: String,
    pub url: String,
    pub host: Option<String>,
    pub status: Option<u16>,
    pub source: String,
    pub req_len: i64,
    pub resp_len: Option<i64>,
    pub created_at_ms: i64,
    pub fingerprint: Option<String>,
    pub roundtrip_ms: Option<i64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HistoryPage {
    pub exchanges: Vec<HistoryRow>,
    pub next_before: Option<ExchangeId>,
    pub skipped_large: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangePreview {
    pub exchange: HttpExchange,
    pub req_len: i64,
    pub resp_len: Option<i64>,
}

pub(super) struct StoredExchange {
    pub(super) exchange: HttpExchange,
    req_len: i64,
    req_sha: Option<String>,
    resp_len: Option<i64>,
    resp_sha: Option<String>,
}

impl StoredExchange {
    pub(super) fn from_row(row: &Row<'_>) -> Result<Self> {
        let data: String = row.get(6)?;
        let mut exchange: HttpExchange =
            serde_json::from_str(&data).context("deserializing exchange")?;
        exchange.id = ExchangeId(row.get(0)?);
        exchange.created_at_ms = row.get(5)?;
        Ok(Self {
            exchange,
            req_len: row.get(1)?,
            req_sha: row.get(2)?,
            resp_len: row.get(3)?,
            resp_sha: row.get(4)?,
        })
    }

    fn load(&mut self, store: &Store, limit: Option<i64>) -> Result<()> {
        self.exchange.request.body = store.read_blob(self.req_sha.as_deref(), limit)?;
        if let Some(response) = self.exchange.response.as_mut() {
            response.body = store.read_blob(self.resp_sha.as_deref(), limit)?;
        }
        Ok(())
    }

    pub(super) fn load_bodies(&mut self, store: &Store) -> Result<()> {
        self.load(store, None)
    }

    // Older query callers expect length-sized placeholders. Paged views and
    // body filters use the stored lengths directly instead.
    pub(super) fn with_length_placeholders(mut self) -> HttpExchange {
        self.exchange.request.body = Body::from_bytes(vec![0; self.req_len.max(0) as usize]);
        if let Some(response) = self.exchange.response.as_mut() {
            response.body = Body::from_bytes(vec![0; self.resp_len.unwrap_or(0).max(0) as usize]);
        }
        self.exchange
    }

    fn into_row(self) -> HistoryRow {
        let exchange = self.exchange;
        HistoryRow {
            id: exchange.id,
            status: exchange.response.map(|response| response.status),
            source: exchange.source.as_str().into(),
            host: exchange.request.host(),
            url: exchange.request.url,
            method: exchange.request.method,
            req_len: self.req_len,
            resp_len: self.resp_len,
            created_at_ms: exchange.created_at_ms,
            fingerprint: exchange.fingerprint_used,
            roundtrip_ms: exchange.timings.map(|timings| timings.roundtrip_ms),
        }
    }
}

impl QueryTarget for StoredExchange {
    fn get_str(&self, field: &[String]) -> Option<Cow<'_, str>> {
        self.exchange.get_str(field)
    }

    fn get_int(&self, field: &[String]) -> Option<i64> {
        match field {
            [side, name]
                if name.eq_ignore_ascii_case("len") && side.eq_ignore_ascii_case("req") =>
            {
                Some(self.req_len)
            }
            [side, name]
                if name.eq_ignore_ascii_case("len") && side.eq_ignore_ascii_case("resp") =>
            {
                self.resp_len
            }
            _ => self.exchange.get_int(field),
        }
    }

    fn freetext_haystack(&self) -> Cow<'_, str> {
        self.exchange.freetext_haystack()
    }
}

impl Store {
    /// Read up to 200 matches newest first. An empty page may have a cursor
    /// when a filter matches nothing in the examined window.
    pub fn history_page(
        &self,
        query: &Query,
        before: Option<ExchangeId>,
        limit: usize,
    ) -> Result<HistoryPage> {
        if limit == 0 {
            return Ok(HistoryPage::default());
        }
        let (cursor, mut bind) = match before {
            Some(id) => ("id < ?1", vec![Value::Integer(id.0)]),
            None => ("1", vec![Value::Null]),
        };
        bind.push(Value::Integer(HISTORY_WINDOW as i64 + 1));
        let metadata =
            if let Some((clause, value)) = query.required_metadata().and_then(metadata_clause) {
                bind.push(value);
                clause
            } else {
                "1"
            };
        let sql = format!("SELECT {EXCHANGE_COLUMNS} FROM exchanges WHERE {cursor} AND {metadata} ORDER BY id DESC LIMIT ?2");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query(params_from_iter(bind))?;
        let mut result = HistoryPage::default();
        let mut last = None;
        for _ in 0..HISTORY_WINDOW {
            let Some(row) = rows.next()? else {
                return Ok(result);
            };
            let mut row = StoredExchange::from_row(row)?;
            last = Some(row.exchange.id);
            if query.needs_body() {
                if row.req_len > REVIEW_BODY_LIMIT || row.resp_len.unwrap_or(0) > REVIEW_BODY_LIMIT
                {
                    result.skipped_large += 1;
                    continue;
                }
                row.load_bodies(self)?;
            }
            if query.matches(&row) {
                result.exchanges.push(row.into_row());
                if result.exchanges.len() == limit.min(200) {
                    break;
                }
            }
        }
        if rows.next()?.is_some() {
            result.next_before = last;
        }
        Ok(result)
    }

    pub fn inspect_exchange(&self, id: ExchangeId) -> Result<Option<ExchangePreview>> {
        self.exchange_with_preview(id, Some(INSPECT_BYTES))
    }

    pub(super) fn exchange_with_preview(
        &self,
        id: ExchangeId,
        limit: Option<i64>,
    ) -> Result<Option<ExchangePreview>> {
        let sql = format!("SELECT {EXCHANGE_COLUMNS} FROM exchanges WHERE id = ?1");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([id.0])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let mut row = StoredExchange::from_row(row)?;
        row.load(self, limit)?;
        Ok(Some(ExchangePreview {
            exchange: row.exchange,
            req_len: row.req_len,
            resp_len: row.resp_len,
        }))
    }

    fn read_blob(&self, sha: Option<&str>, limit: Option<i64>) -> Result<Body> {
        let Some(sha) = sha else {
            return Ok(Body::empty());
        };
        let bytes: Vec<u8> = if let Some(limit) = limit {
            self.conn.query_row(
                "SELECT substr(bytes, 1, ?2) FROM blobs WHERE sha = ?1",
                params![sha, limit],
                |row| row.get(0),
            )?
        } else {
            self.conn
                .query_row("SELECT bytes FROM blobs WHERE sha = ?1", [sha], |row| {
                    row.get(0)
                })?
        };
        Ok(Body::from_bytes(bytes))
    }
}

fn metadata_clause(filter: RequiredMetadata<'_>) -> Option<(&'static str, Value)> {
    Some(match filter {
        RequiredMetadata::Method(value) => ("method = ?3", Value::Text(value.to_owned())),
        RequiredMetadata::Host(value) => ("host = ?3", Value::Text(value.to_owned())),
        RequiredMetadata::Source(value) => ("source = ?3", Value::Text(value.to_owned())),
        RequiredMetadata::Status(operator, value) => (
            match operator {
                Operator::Eq => "resp_status = ?3",
                Operator::Gt => "resp_status > ?3",
                Operator::Gte => "resp_status >= ?3",
                Operator::Lt => "resp_status < ?3",
                Operator::Lte => "resp_status <= ?3",
                _ => return None,
            },
            Value::Integer(value),
        ),
    })
}
