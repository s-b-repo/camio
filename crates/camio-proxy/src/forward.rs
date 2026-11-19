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
use camio_request::matched_engine;
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
        let (tx, rx) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        std::thread::Builder::new()
            .name("camio-proxy-engine".into())
            .spawn(move || {
                let engine = match matched_engine(&profile) {
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
                    let res = engine
                        .send(job.req, Source::Proxy)
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
