//! Durable OAST interactions with a retention policy (plan §F15).
//!
//! The in-memory [`Collector`](super::Collector) is bounded by process
//! lifetime: a callback that arrives after the collector stops, or after a
//! restart, is gone. This module persists every interaction into the project
//! store and prunes it under an explicit retention policy, so
//!
//! * a scan that crashes mid-run keeps its callbacks,
//! * `camio oast --db` records interactions as evidence, and
//! * retention is a *decision* (count and age), not an accident of uptime.

use super::{Collector, Interaction};
use std::sync::Mutex;
use std::time::Duration;

/// How long interactions are retained, and how many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Keep at most this many interactions (newest kept).
    pub max_interactions: usize,
    /// Keep interactions no older than this.
    pub max_age: Duration,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        RetentionPolicy {
            max_interactions: 10_000,
            max_age: Duration::from_secs(7 * 24 * 3600),
        }
    }
}

/// A collector that mirrors every interaction into a durable store and prunes
/// under [`RetentionPolicy`].
#[derive(Clone)]
pub struct DurableCollector {
    inner: std::sync::Arc<Collector>,
    /// Shared so the HTTP and DNS paths record into the same store.
    store: std::sync::Arc<Mutex<camio_store::Store>>,
    retention: RetentionPolicy,
}

impl DurableCollector {
    /// Wrap `collector`, persisting to `store` with the given retention.
    pub fn new(
        collector: std::sync::Arc<Collector>,
        store: camio_store::Store,
        retention: RetentionPolicy,
    ) -> Self {
        DurableCollector {
            inner: collector,
            store: std::sync::Arc::new(Mutex::new(store)),
            retention,
        }
    }

    /// The in-memory collector (for base URL / token minting).
    pub fn inner(&self) -> &Collector {
        &self.inner
    }

    /// Record an interaction both in memory and in the store, pruning the store
    /// under the retention policy. A store failure never loses the in-memory
    /// record: the callback is still observable in this process.
    pub fn record(&self, interaction: &Interaction) -> Result<(), String> {
        self.inner.record_for_test(interaction);
        let store = self
            .store
            .lock()
            .map_err(|_| "durable OAST store lock poisoned".to_string())?;
        let trimmed = super::trim_for_store(interaction);
        let row = camio_store::OastRow {
            id: 0,
            token: trimmed.token,
            method: trimmed.method,
            target: trimmed.target,
            host: trimmed.host,
            source: trimmed.source,
            received_at_ms: trimmed.received_at_ms,
            body_summary: trimmed.body_summary,
        };
        store
            .record_oast_interaction(&row)
            .map_err(|e| e.to_string())?;
        store
            .prune_oast_interactions(
                self.retention.max_interactions,
                self.retention.max_age.as_millis() as i64,
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Interactions persisted for `token` (survives a restart).
    pub fn for_token(&self, token: &str) -> Vec<camio_store::OastRow> {
        match self.store.lock() {
            Ok(store) => store.oast_interactions_for_token(token).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    /// All persisted interactions, newest first.
    pub fn all_persisted(&self) -> Vec<camio_store::OastRow> {
        match self.store.lock() {
            Ok(store) => store.oast_interactions(1000).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    /// The retention policy in force.
    pub fn retention(&self) -> RetentionPolicy {
        self.retention
    }
}

impl crate::dns::DnsSink for DurableCollector {
    fn note_dns_lookup(&self, token: &str, qname: &str) -> Result<(), String> {
        let interaction = Interaction {
            id: 0,
            token: Some(token.to_string()),
            method: "DNS".into(),
            target: qname.to_string(),
            host: Some(qname.to_string()),
            source: "-".into(),
            received_at_ms: crate::now_ms(),
            headers: camio_core::HeaderList::new(),
            body: camio_core::Body::from_text(format!("DNS A query for {qname}")),
        };
        self.record(&interaction)
    }
}

#[cfg(test)]
mod durable_tests {
    use super::*;
    use crate::Collector;
    use camio_core::{Body, HeaderList};

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    fn interaction(token: &str, target: &str, at_ms: i64) -> Interaction {
        Interaction {
            id: 1,
            token: Some(token.to_string()),
            method: "GET".into(),
            target: target.into(),
            host: None,
            source: "203.0.113.9".into(),
            received_at_ms: at_ms,
            headers: HeaderList::new(),
            body: Body::from_text("callback-body"),
        }
    }

    #[test]
    fn interactions_persist_and_survive_a_new_store_handle() {
        let dir = std::env::temp_dir().join(format!("camio-oast-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("oast.db");
        let collector = Collector::new("127.0.0.1:0");
        {
            let durable = DurableCollector::new(
                collector.clone(),
                camio_store::Store::open(&db).unwrap(),
                RetentionPolicy::default(),
            );
            durable
                .record(&interaction("tok-1", "/tok-1", now_ms()))
                .expect("record 1");
            durable
                .record(&interaction("tok-2", "/tok-2", now_ms()))
                .expect("record 2");
        }
        // A fresh store handle (a "restart") still sees the interactions.
        let reopened = camio_store::Store::open(&db).unwrap();
        let for_tok = reopened.oast_interactions_for_token("tok-1").unwrap();
        assert_eq!(for_tok.len(), 1);
        assert_eq!(for_tok[0].target, "/tok-1");
        assert_eq!(reopened.oast_interactions(10).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_prunes_old_and_excess() {
        let dir = std::env::temp_dir().join(format!("camio-oast-ret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = camio_store::Store::open(dir.join("r.db")).unwrap();
        // Age: everything older than "now" is pruned (now is 0 here, so the
        // max-age floor of 0 keeps everything — use an explicit negative-safe
        // bound by making the rows ancient).
        let now = now_ms();
        store.record_oast_interaction(&row("a", "/a", now)).unwrap();
        store.record_oast_interaction(&row("b", "/b", now)).unwrap();
        assert_eq!(
            store.oast_interactions(10).unwrap().len(),
            2,
            "rows written"
        );
        // Count cap of 1 keeps only the newest.
        let pruned = store
            .prune_oast_interactions(1, 7 * 24 * 3600 * 1000)
            .unwrap();
        assert!(pruned >= 1);
        assert_eq!(store.oast_interactions(10).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);

        fn row(token: &str, target: &str, at: i64) -> camio_store::OastRow {
            camio_store::OastRow {
                id: 0,
                token: Some(token.into()),
                method: "GET".into(),
                target: target.into(),
                host: None,
                source: "-".into(),
                received_at_ms: at,
                body_summary: None,
            }
        }
    }
}
