//! Where captured exchanges go. The proxy stays storage-agnostic: it emits a
//! fully-formed [`HttpExchange`] (already tagged `Source::Proxy` with its scope
//! decision) to an [`ExchangeSink`], and the embedder decides whether that
//! lands in the SQLite store, an NDJSON file, a live UI table, or all three.

use camio_core::HttpExchange;
use std::sync::Mutex;

/// A destination for captured proxy exchanges. Implementations must be cheap and
/// non-blocking where possible; a slow sink backpressures the connection thread
/// it runs on but never the whole proxy.
pub trait ExchangeSink: Send + Sync {
    /// Record one captured exchange. Errors are the sink's own concern (it
    /// should log/absorb them) — capture must never abort request handling.
    fn record(&self, exchange: &HttpExchange);
}

/// A sink that discards everything (useful when only live interception matters).
pub struct NullSink;

impl ExchangeSink for NullSink {
    // A sink that records nothing still has to satisfy `ExchangeSink`.
    // audit-allow: B13
    fn record(&self, _exchange: &HttpExchange) {}
}

/// A sink backed by a closure, for ad-hoc wiring (store insert, NDJSON append).
pub struct FnSink<F: Fn(&HttpExchange) + Send + Sync>(pub F);

impl<F: Fn(&HttpExchange) + Send + Sync> ExchangeSink for FnSink<F> {
    fn record(&self, exchange: &HttpExchange) {
        (self.0)(exchange)
    }
}

/// An in-memory sink that collects exchanges, for tests and short captures.
#[derive(Default)]
pub struct VecSink {
    items: Mutex<Vec<HttpExchange>>,
}

impl VecSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of everything captured so far.
    pub fn snapshot(&self) -> Vec<HttpExchange> {
        camio_core::sync::recovered_lock(&self.items).clone()
    }

    /// How many exchanges have been captured.
    pub fn len(&self) -> usize {
        camio_core::sync::recovered_lock(&self.items).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ExchangeSink for VecSink {
    fn record(&self, exchange: &HttpExchange) {
        camio_core::sync::recovered_lock(&self.items).push(exchange.clone());
    }
}
