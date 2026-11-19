//! A ready-made [`Forwarder`](crate::Forwarder) backed by Camio's
//! fingerprint-matched request engine (feature `engine`).
//!
//! The impersonating engine drives a current-thread Tokio runtime that must not
//! be entered concurrently from multiple connection threads. Rather than loosen
//! the engine's public bounds, this confines it to one worker thread and funnels
//! every send through a channel — serial, correct, and reusing the same
//! engine/connection pool across the whole proxy session. This is exactly the
//! wiring the CLI and the native app would otherwise each reinvent.

use crate::{ForwardError, Forwarder};
use camio_core::{FingerprintProfile, HttpExchange, HttpRequest, Source};
use camio_request::matched_engine_with_proxy;
use std::sync::mpsc;
use std::sync::Mutex;

struct Job {
    req: HttpRequest,
    reply: mpsc::Sender<Result<HttpExchange, ForwardError>>,
}

/// A forwarder that sends upstream through the fingerprint-matched engine,
/// serialized on a dedicated worker thread.
pub struct EngineForwarder {
    tx: Mutex<mpsc::Sender<Job>>,
}

impl EngineForwarder {
    /// Spawn the engine worker for `profile`. The engine is built on the worker
    /// thread (its trait object is not `Send`), so this returns only once the
    /// engine has been constructed — surfacing a build error eagerly.
    pub fn spawn(profile: FingerprintProfile) -> Result<Self, ForwardError> {
        Self::spawn_with_proxy(profile, None)
    }

    /// Like [`spawn`](Self::spawn) but routes upstream traffic through a chained
    /// proxy (`http://…` or `socks5://…`). Only the engine-forwarded paths (plain
    /// HTTP and TLS-intercepted HTTPS) traverse it; blind-relayed HTTPS and
    /// WebSocket connections go direct.
    pub fn spawn_with_proxy(
        profile: FingerprintProfile,
        upstream_proxy: Option<String>,
    ) -> Result<Self, ForwardError> {
        let (tx, rx) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        std::thread::Builder::new()
            .name("camio-proxy-engine".into())
            .spawn(move || {
                let engine = match matched_engine_with_proxy(&profile, upstream_proxy.as_deref()) {
                    Ok(e) => {
                        let _ = ready_tx.send(Ok(()));
                        e
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.to_string()));
                        return;
                    }
                };
                for job in rx {
                    // Faithful send: the request is the browser's own, so its
                    // headers go out verbatim (no synthesis/reorder) — the
                    // intercepted request is indistinguishable at the header layer
                    // from the browser's, while the matched transport supplies the
                    // real TLS/HTTP-2 fingerprint.
                    let res = engine
                        .send_faithful(job.req, Source::Proxy)
                        .map_err(|e| ForwardError(e.to_string()));
                    let _ = job.reply.send(res);
                }
            })
            .map_err(|e| ForwardError(format!("spawning proxy engine worker: {e}")))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(EngineForwarder { tx: Mutex::new(tx) }),
            Ok(Err(e)) => Err(ForwardError(format!(
                "building matched request engine: {e}"
            ))),
            Err(_) => Err(ForwardError("proxy engine worker failed to start".into())),
        }
    }
}

impl Forwarder for EngineForwarder {
    fn forward(&self, request: HttpRequest) -> Result<HttpExchange, ForwardError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        {
            let tx = self
                .tx
                .lock()
                .map_err(|_| ForwardError("proxy forwarder poisoned".into()))?;
            tx.send(Job {
                req: request,
                reply: reply_tx,
            })
            .map_err(|_| ForwardError("proxy engine worker stopped".into()))?;
        }
        reply_rx
            .recv()
            .map_err(|_| ForwardError("proxy engine worker dropped the reply".into()))?
    }
}
