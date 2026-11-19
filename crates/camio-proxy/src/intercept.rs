//! The intercept queue — Burp's "Proxy ▸ Intercept" seam.
//!
//! An [`Interceptor`] sees every in-scope request before it is forwarded and
//! every response before it is returned, and may edit or drop it. The proxy
//! ships two implementations:
//!
//! * [`AutoForward`] — pass everything through unchanged (interception off).
//! * [`QueueInterceptor`] — park each message and block until an operator (a GUI,
//!   the CLI, or an automated rule) submits a decision. This is the reusable
//!   queue a front-end drives: `next_pending()` to pull a held message,
//!   `resolve()` to release it.
//!
//! The queue is intentionally UI-agnostic: it is a thread-safe rendezvous, so
//! the native app, the web UI, and a headless test can all drive it the same
//! way.

use camio_core::{HttpRequest, HttpResponse};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// What to do with an intercepted request.
#[derive(Debug, Clone)]
pub enum RequestDecision {
    /// Forward this (possibly edited) request upstream.
    Forward(HttpRequest),
    /// Drop the request; the client receives a synthetic 504.
    Drop,
}

/// What to do with an intercepted response.
#[derive(Debug, Clone)]
pub enum ResponseDecision {
    /// Return this (possibly edited) response to the client.
    Forward(HttpResponse),
    /// Drop the response; the client connection is closed.
    Drop,
}

/// The interception hook. Both methods are called from the connection thread, so
/// an implementation that blocks (like [`QueueInterceptor`]) holds that one
/// connection, never the whole proxy.
pub trait Interceptor: Send + Sync {
    /// Inspect/edit/drop a request before it is forwarded.
    fn on_request(&self, request: HttpRequest) -> RequestDecision;

    /// Inspect/edit/drop a response before it reaches the client. The `request`
    /// is the one that produced it (post-edit), for context.
    fn on_response(&self, _request: &HttpRequest, response: HttpResponse) -> ResponseDecision {
        ResponseDecision::Forward(response)
    }
}

/// Interception off: forward everything unchanged.
pub struct AutoForward;

impl Interceptor for AutoForward {
    fn on_request(&self, request: HttpRequest) -> RequestDecision {
        RequestDecision::Forward(request)
    }
}

/// A message parked in the intercept queue, awaiting an operator decision.
pub enum Pending {
    Request {
        id: u64,
        request: HttpRequest,
    },
    Response {
        id: u64,
        request: HttpRequest,
        response: HttpResponse,
    },
}

impl Pending {
    pub fn id(&self) -> u64 {
        match self {
            Pending::Request { id, .. } | Pending::Response { id, .. } => *id,
        }
    }
}

enum Slot {
    WaitingRequest(HttpRequest),
    WaitingResponse(HttpRequest, HttpResponse),
    ResolvedRequest(RequestDecision),
    ResolvedResponse(ResponseDecision),
}

struct Inner {
    queue: VecDeque<u64>,
    slots: std::collections::HashMap<u64, Slot>,
    next_id: u64,
    /// When false, the queue degrades to auto-forward so a front-end can toggle
    /// interception without tearing down the proxy.
    active: bool,
    /// When false, responses are never parked (requests only) — so a front-end
    /// that only drives request interception can't leave responses hanging.
    intercept_responses: bool,
}

/// A thread-safe intercept queue a front-end drives.
pub struct QueueInterceptor {
    inner: Mutex<Inner>,
    cv: Condvar,
}

impl Default for QueueInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl QueueInterceptor {
    pub fn new() -> Self {
        QueueInterceptor {
            inner: Mutex::new(Inner {
                queue: VecDeque::new(),
                slots: std::collections::HashMap::new(),
                next_id: 1,
                active: true,
                intercept_responses: false,
            }),
            cv: Condvar::new(),
        }
    }

    /// Turn interception on or off. Turning it off releases nothing already
    /// parked — resolve those explicitly — but new messages pass straight
    /// through.
    pub fn set_active(&self, active: bool) {
        let mut g = self.inner.lock().expect("intercept queue poisoned");
        g.active = active;
    }

    pub fn is_active(&self) -> bool {
        self.inner.lock().expect("intercept queue poisoned").active
    }

    /// Enable or disable parking of responses (default disabled). Requests are
    /// always governed by [`set_active`](Self::set_active).
    pub fn set_intercept_responses(&self, on: bool) {
        self.inner
            .lock()
            .expect("intercept queue poisoned")
            .intercept_responses = on;
    }

    /// Number of messages currently parked awaiting a decision.
    pub fn pending_count(&self) -> usize {
        self.inner
            .lock()
            .expect("intercept queue poisoned")
            .queue
            .len()
    }

    /// Pull the next parked message for display, if any. Non-blocking.
    pub fn next_pending(&self) -> Option<Pending> {
        let g = self.inner.lock().expect("intercept queue poisoned");
        let id = *g.queue.front()?;
        match g.slots.get(&id)? {
            Slot::WaitingRequest(req) => Some(Pending::Request {
                id,
                request: req.clone(),
            }),
            Slot::WaitingResponse(req, resp) => Some(Pending::Response {
                id,
                request: req.clone(),
                response: resp.clone(),
            }),
            _ => None,
        }
    }

    /// Submit a decision for a parked request. Returns `false` if the id is
    /// unknown or was not awaiting a request decision.
    pub fn resolve_request(&self, id: u64, decision: RequestDecision) -> bool {
        self.resolve(id, Slot::ResolvedRequest(decision))
    }

    /// Submit a decision for a parked response.
    pub fn resolve_response(&self, id: u64, decision: ResponseDecision) -> bool {
        self.resolve(id, Slot::ResolvedResponse(decision))
    }

    fn resolve(&self, id: u64, resolved: Slot) -> bool {
        let mut g = self.inner.lock().expect("intercept queue poisoned");
        let ok = matches!(
            (g.slots.get(&id), &resolved),
            (Some(Slot::WaitingRequest(_)), Slot::ResolvedRequest(_))
                | (Some(Slot::WaitingResponse(..)), Slot::ResolvedResponse(_))
        );
        if ok {
            g.slots.insert(id, resolved);
            g.queue.retain(|q| *q != id);
            self.cv.notify_all();
        }
        ok
    }

    fn park_request(&self, request: HttpRequest) -> RequestDecision {
        let mut g = self.inner.lock().expect("intercept queue poisoned");
        if !g.active {
            return RequestDecision::Forward(request);
        }
        let id = g.next_id;
        g.next_id += 1;
        g.slots.insert(id, Slot::WaitingRequest(request));
        g.queue.push_back(id);
        self.cv.notify_all();
        loop {
            // Poll so a `set_active(false)` toggle can release waiters too.
            let (guard, _timeout) = self
                .cv
                .wait_timeout(g, Duration::from_millis(200))
                .expect("intercept queue poisoned");
            g = guard;
            if let Some(Slot::ResolvedRequest(_)) = g.slots.get(&id) {
                if let Some(Slot::ResolvedRequest(d)) = g.slots.remove(&id) {
                    return d;
                }
            }
            if !g.active {
                // Interception switched off while parked: release unchanged.
                if let Some(Slot::WaitingRequest(req)) = g.slots.remove(&id) {
                    g.queue.retain(|q| *q != id);
                    return RequestDecision::Forward(req);
                }
            }
        }
    }

    fn park_response(&self, request: &HttpRequest, response: HttpResponse) -> ResponseDecision {
        let mut g = self.inner.lock().expect("intercept queue poisoned");
        if !g.active || !g.intercept_responses {
            return ResponseDecision::Forward(response);
        }
        let id = g.next_id;
        g.next_id += 1;
        g.slots
            .insert(id, Slot::WaitingResponse(request.clone(), response));
        g.queue.push_back(id);
        self.cv.notify_all();
        loop {
            let (guard, _timeout) = self
                .cv
                .wait_timeout(g, Duration::from_millis(200))
                .expect("intercept queue poisoned");
            g = guard;
            if let Some(Slot::ResolvedResponse(_)) = g.slots.get(&id) {
                if let Some(Slot::ResolvedResponse(d)) = g.slots.remove(&id) {
                    return d;
                }
            }
            if !g.active {
                if let Some(Slot::WaitingResponse(_, resp)) = g.slots.remove(&id) {
                    g.queue.retain(|q| *q != id);
                    return ResponseDecision::Forward(resp);
                }
            }
        }
    }
}

impl Interceptor for QueueInterceptor {
    fn on_request(&self, request: HttpRequest) -> RequestDecision {
        self.park_request(request)
    }
    fn on_response(&self, request: &HttpRequest, response: HttpResponse) -> ResponseDecision {
        self.park_response(request, response)
    }
}

/// Convenience: share a [`QueueInterceptor`] between the proxy and a front-end.
pub type SharedQueue = Arc<QueueInterceptor>;

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::HttpRequest;
    use std::thread;

    #[test]
    fn auto_forward_passes_through() {
        let i = AutoForward;
        match i.on_request(HttpRequest::get("http://h/")) {
            RequestDecision::Forward(r) => assert_eq!(r.url, "http://h/"),
            RequestDecision::Drop => panic!("should forward"),
        }
    }

    #[test]
    fn queue_parks_and_resolves_with_edit() {
        let q = Arc::new(QueueInterceptor::new());
        let q2 = q.clone();
        let handle = thread::spawn(move || q2.on_request(HttpRequest::get("http://h/orig")));

        // Wait for the request to be parked.
        let id = loop {
            if let Some(p) = q.next_pending() {
                break p.id();
            }
            thread::yield_now();
        };
        let mut edited = HttpRequest::get("http://h/edited");
        edited.method = "DELETE".into();
        assert!(q.resolve_request(id, RequestDecision::Forward(edited)));

        match handle.join().unwrap() {
            RequestDecision::Forward(r) => {
                assert_eq!(r.url, "http://h/edited");
                assert_eq!(r.method, "DELETE");
            }
            RequestDecision::Drop => panic!("expected forward"),
        }
    }

    #[test]
    fn inactive_queue_forwards_immediately() {
        let q = QueueInterceptor::new();
        q.set_active(false);
        match q.on_request(HttpRequest::get("http://h/")) {
            RequestDecision::Forward(_) => {}
            RequestDecision::Drop => panic!("inactive queue must forward"),
        }
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn responses_not_parked_by_default() {
        // With response interception off (default), an active queue forwards
        // responses immediately instead of blocking on an operator decision.
        let q = QueueInterceptor::new();
        assert!(q.is_active());
        let req = HttpRequest::get("http://h/");
        let resp = camio_core::HttpResponse {
            status: 200,
            version: camio_core::HttpVersion::Http11,
            reason: None,
            headers: camio_core::HeaderList::new(),
            body: camio_core::Body::empty(),
        };
        match q.on_response(&req, resp) {
            ResponseDecision::Forward(r) => assert_eq!(r.status, 200),
            ResponseDecision::Drop => panic!("should forward"),
        }
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn drop_decision_is_honored() {
        let q = Arc::new(QueueInterceptor::new());
        let q2 = q.clone();
        let handle = thread::spawn(move || q2.on_request(HttpRequest::get("http://h/")));
        let id = loop {
            if let Some(p) = q.next_pending() {
                break p.id();
            }
            thread::yield_now();
        };
        assert!(q.resolve_request(id, RequestDecision::Drop));
        assert!(matches!(handle.join().unwrap(), RequestDecision::Drop));
    }
}
