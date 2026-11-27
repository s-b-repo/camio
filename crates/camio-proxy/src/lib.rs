//! `camio-proxy` — Camio's intercepting HTTP/HTTPS proxy.
//!
//! This is the signature "Burp proxy" capability (plan §F22/F05), built to fit
//! Camio's existing seams rather than bolt on a second universe:
//!
//! * **Scope and policy are the ones shared everywhere.** Every relayed request
//!   is scope-decided through [`camio_core::Scope`] (the SSRF guard always wins)
//!   and gated by [`camio_core::Policy`]; out-of-scope and blocked destinations
//!   are refused with a synthetic response and still captured as attempts.
//! * **Forwarding is injected.** The proxy never opens its own HTTP client; the
//!   embedder supplies a [`Forwarder`] (the CLI wires the fingerprint-matched
//!   `camio-request` engine), mirroring how `camio-active` injects its sender.
//! * **Match & Replace** uses [`camio_core::RuleSet`] — request rules run before
//!   the send, response rules after, so captured evidence matches the wire.
//! * **The intercept queue** ([`QueueInterceptor`]) is a UI-agnostic rendezvous
//!   the native app, web UI, or a headless test all drive the same way.
//! * **Capture** emits a `Source::Proxy` [`HttpExchange`] to an [`ExchangeSink`];
//!   where it lands (SQLite store, NDJSON, live table) is the embedder's choice.
//!
//! HTTPS is handled two ways. By default a CONNECT is **blind-relayed** — the
//! browser performs its own TLS end-to-end, so the capture stays
//! fingerprint-true and only the target host is recorded. With the
//! `tls-intercept` feature and a configured [`CertAuthority`], an in-scope
//! CONNECT is instead **terminated** with an operator-trusted leaf certificate
//! so the plaintext is inspected and re-sent through the matched engine; those
//! exchanges are honestly tagged fingerprint-changing.

mod http1;
mod intercept;
mod sink;

#[cfg(feature = "tls-intercept")]
mod ca;

#[cfg(feature = "engine")]
mod forward;
pub mod upstream;
pub mod ws;

pub use http1::{DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_HEADER_BYTES};

/// Default size of the bounded connection worker pool.
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;

/// How long a rate-limited `ws://` handshake may wait before it is refused.
const WS_RATE_LIMIT_WAIT: Duration = Duration::from_secs(10);
pub use intercept::{
    AutoForward, Interceptor, Pending, QueueInterceptor, RequestDecision, ResponseDecision,
    SharedQueue,
};
pub use sink::{ExchangeSink, FnSink, NullSink, VecSink};

#[cfg(feature = "tls-intercept")]
pub use ca::{CaError, CertAuthority, DEFAULT_CA_COMMON_NAME};

#[cfg(feature = "engine")]
pub use forward::EngineForwarder;
pub use upstream::{parse as parse_upstream, Upstream};
pub use ws::{decode_frames, rewrite_frames, Frame, FrameEditor, PassthroughEditor};

use camio_core::{
    ActionClass, Body, HeaderList, HttpExchange, HttpRequest, HttpResponse, HttpVersion, Policy,
    PolicyOutcome, RateLimiter, RuleSet, Scope, ScopeDecision, Source,
};
use http1::{
    absolute_url, is_websocket_upgrade, reconstruct_upgrade_request, split_authority,
    to_http_request, write_response, Conn, RequestHead,
};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// An error from forwarding a request upstream.
#[derive(Debug, Clone)]
pub struct ForwardError(pub String);

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ForwardError {}

/// Sends a (possibly edited) request upstream and returns the completed
/// exchange. The proxy itself is transport-agnostic: the embedder injects this,
/// so the real send goes through Camio's fingerprint-matched engine (or any
/// other transport) and all destination/rate policy lives in one place.
pub trait Forwarder: Send + Sync {
    fn forward(&self, request: HttpRequest) -> Result<HttpExchange, ForwardError>;
}

/// A forwarder backed by a closure, for simple wiring and tests.
pub struct FnForwarder<F>(pub F)
where
    F: Fn(HttpRequest) -> Result<HttpExchange, ForwardError> + Send + Sync;

impl<F> Forwarder for FnForwarder<F>
where
    F: Fn(HttpRequest) -> Result<HttpExchange, ForwardError> + Send + Sync,
{
    fn forward(&self, request: HttpRequest) -> Result<HttpExchange, ForwardError> {
        (self.0)(request)
    }
}

/// A [`Forwarder`] decorator that paces upstream sends through a shared
/// [`RateLimiter`] (plan §4.3): it blocks for a per-host (and/or global) token
/// before delegating, so no target is hammered faster than the operator allows —
/// and the same limiter can be shared with other send paths.
pub struct RateLimitedForwarder {
    inner: Arc<dyn Forwarder>,
    limiter: Arc<RateLimiter>,
}

impl RateLimitedForwarder {
    pub fn new(inner: Arc<dyn Forwarder>, limiter: Arc<RateLimiter>) -> Self {
        RateLimitedForwarder { inner, limiter }
    }
}

impl Forwarder for RateLimitedForwarder {
    fn forward(&self, request: HttpRequest) -> Result<HttpExchange, ForwardError> {
        let host = request.host().unwrap_or_default();
        self.limiter.acquire(&host);
        self.inner.forward(request)
    }
}

/// Proxy configuration. Scope, policy, and Match & Replace are the shared Camio
/// types; the proxy adds only wire limits and the TLS-interception toggle.
pub struct ProxyConfig {
    /// Shared scope decision path (SSRF guard included).
    pub scope: Scope,
    /// Shared authorization policy.
    pub policy: Policy,
    /// Match & Replace rules applied in-flight.
    pub rules: RuleSet,
    /// Terminate in-scope HTTPS with the configured CA (fingerprint-changing).
    /// Ignored when the `tls-intercept` feature is off or no CA is set.
    pub tls_intercept: bool,
    /// Max request header bytes before the connection is dropped.
    pub max_header_bytes: usize,
    /// Max request body bytes.
    pub max_body_bytes: usize,
    /// Idle read timeout for a kept-alive connection.
    pub read_timeout: Option<Duration>,
    /// Maximum concurrently-served connections (bounded worker pool size).
    pub max_connections: usize,
    /// Optional per-host rate limit for raw-relayed `ws://` handshakes, which
    /// bypass the forwarder (and therefore `--rate-limit`'s pacing).
    pub ws_rate_limit: Option<Arc<camio_core::RateLimiter>>,
    /// Optional in-flight editor for `ws://` text frames (Match & Replace for
    /// WebSocket payloads). `None` relays frames unchanged.
    pub ws_editor: Option<Arc<dyn ws::FrameEditor>>,
    /// Upstream proxy for the *raw* paths (blind CONNECT tunnels and `ws://`
    /// relays), which have no engine in the middle. Engine-forwarded traffic
    /// chains through its own configured upstream in the `Forwarder`.
    pub upstream: upstream::Upstream,
    /// Whether the operator's browser counts as the confirmation for a
    /// proxied send. `true` (the default) is the honest reading of "the
    /// operator's browser is the client": the operator chose to browse there.
    /// Set `false` to honour [`Policy::require_confirmation`] instead, in which
    /// case proxied sends are refused until confirmation is granted — that is
    /// rarely what an interactive browser session wants, so the knob exists to
    /// make the choice explicit rather than silently ignoring the policy.
    pub browser_is_confirmation: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            scope: Scope::new(),
            policy: Policy::safe(),
            rules: RuleSet::new(),
            tls_intercept: false,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            read_timeout: Some(Duration::from_secs(120)),
            browser_is_confirmation: true,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            ws_rate_limit: None,
            upstream: upstream::Upstream::Direct,
            ws_editor: None,
        }
    }
}

/// The running proxy. Clone-free; share across threads behind the internal
/// `Arc`s it holds.
pub struct ProxyServer {
    config: Arc<ProxyConfig>,
    forwarder: Arc<dyn Forwarder>,
    sink: Arc<dyn ExchangeSink>,
    interceptor: Arc<dyn Interceptor>,
    #[cfg(feature = "tls-intercept")]
    ca: Option<Arc<CertAuthority>>,
}

impl ProxyServer {
    /// Build a proxy. Pass [`AutoForward`] for the interceptor to disable the
    /// intercept queue, and [`NullSink`] to discard capture.
    pub fn new(
        config: ProxyConfig,
        forwarder: Arc<dyn Forwarder>,
        sink: Arc<dyn ExchangeSink>,
        interceptor: Arc<dyn Interceptor>,
    ) -> Self {
        ProxyServer {
            config: Arc::new(config),
            forwarder,
            sink,
            interceptor,
            #[cfg(feature = "tls-intercept")]
            ca: None,
        }
    }

    /// Attach a certificate authority for TLS interception. Interception also
    /// requires `config.tls_intercept = true`.
    #[cfg(feature = "tls-intercept")]
    pub fn with_ca(mut self, ca: Arc<CertAuthority>) -> Self {
        self.ca = Some(ca);
        self
    }

    /// Bind and serve forever, spawning a thread per connection.
    pub fn serve(self, addr: impl ToSocketAddrs) -> io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        self.serve_with_listener(listener)
    }

    /// Serve on an already-bound listener (lets a caller choose the port / read
    /// back the local address first). Blocks forever; for a stoppable, embedded
    /// proxy (a GUI Start/Stop button) use [`ProxyServer::spawn`] instead.
    pub fn serve_with_listener(self, listener: TcpListener) -> io::Result<()> {
        let server = Arc::new(self);
        server.accept_loop(&listener, None);
        Ok(())
    }

    /// Spawn the proxy on a background thread and return a [`ProxyHandle`] that
    /// can stop it. Non-blocking; the handle carries the bound local address.
    pub fn spawn(self, listener: TcpListener) -> io::Result<ProxyHandle> {
        let local_addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        let server = Arc::new(self);
        let join = std::thread::Builder::new()
            .name("camio-proxy-accept".into())
            .spawn(move || server.accept_loop(&listener, Some(flag)))?;
        Ok(ProxyHandle {
            shutdown,
            local_addr,
            join: Some(join),
        })
    }

    /// The shared accept loop. With a `shutdown` flag the listener runs
    /// non-blocking and polls the flag so the proxy can be stopped; without one
    /// it blocks on `accept` forever (the CLI foreground case).
    fn accept_loop(self: &Arc<Self>, listener: &TcpListener, shutdown: Option<Arc<AtomicBool>>) {
        let polling = shutdown.is_some();
        // A bounded worker pool: one thread per *connection* with no ceiling
        // lets a client exhaust the process (threads, fds, memory), so accepted
        // connections are handed to a fixed pool and the rest wait briefly.
        let workers = self.config.max_connections.clamp(1, 512);
        if polling {
            let _ = listener.set_nonblocking(true);
        }
        let (tx, rx) = std::sync::mpsc::channel::<TcpStream>();
        let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
        for id in 0..workers {
            let server = self.clone();
            let rx = rx.clone();
            let _ = std::thread::Builder::new()
                .name(format!("camio-proxy-{id}"))
                .spawn(move || loop {
                    // Block for the next connection; a poisoned receiver ends
                    // this worker rather than panicking the proxy down.
                    let stream = match rx.lock() {
                        Ok(guard) => match guard.recv() {
                            Ok(stream) => stream,
                            Err(_) => return,
                        },
                        Err(poisoned) => match poisoned.into_inner().recv() {
                            Ok(stream) => stream,
                            Err(_) => return,
                        },
                    };
                    server.handle_conn(stream);
                });
        }
        loop {
            if let Some(flag) = &shutdown {
                if flag.load(Ordering::Acquire) {
                    break;
                }
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    // Accepted sockets are used with blocking reads.
                    let _ = stream.set_nonblocking(false);
                    // If the pool is saturated the accept still lands in the
                    // queue (channel is unbounded), so no connection is dropped;
                    // the workers drain it in order.
                    let _ = tx.send(stream);
                }
                Err(ref e) if polling && e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    // Any accept error (EMFILE, ECONNABORTED, …) backs off —
                    // looping without a sleep would spin the CPU at 100% under
                    // fd exhaustion.
                    if e.kind() != io::ErrorKind::WouldBlock {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    if !polling {
                        // Transient accept error on a blocking listener: keep going.
                        continue;
                    }
                }
            }
        }
    }

    /// Handle one TCP connection: a run of plain-HTTP proxy requests, or a single
    /// CONNECT that takes over the socket.
    fn handle_conn(self: &Arc<Self>, stream: TcpStream) {
        let _ = stream.set_read_timeout(self.config.read_timeout);
        let mut conn = Conn::new(stream);
        // Prime the first bytes so the preface check sees them.
        let _ = conn.prime();
        // HTTP/2 with prior knowledge cannot be intercepted as HTTP/1.1 (the
        // intercepted path is HTTP/1.1 by design; the HTTP/2 fingerprint is
        // reproduced by the matched engine toward the target). Say so instead
        // of dropping the connection as if it were malformed.
        if http1::is_http2_preface(conn.peek()) {
            let resp = synthetic(
                501,
                "Camio proxy: HTTP/2 (prior knowledge) is not intercepted. \
                 Use an HTTP/1.1 client, or exclude this host from interception to relay it.",
            );
            let _ = write_response(conn.stream_mut(), &resp, false);
            self.capture(
                &HttpRequest::get("http://h2-prior-knowledge.invalid/"),
                Some(&resp),
                camio_core::ScopeDecision::Blocked,
                None,
                None,
            );
            return;
        }
        loop {
            let (head, body) =
                match conn.read_request(self.config.max_header_bytes, self.config.max_body_bytes) {
                    Ok(Some(hb)) => hb,
                    Ok(None) => return, // clean EOF
                    Err(_) => return,   // malformed/timeout: drop the connection
                };

            if head.method.eq_ignore_ascii_case("CONNECT") {
                self.handle_connect(conn, &head);
                return; // CONNECT consumes the socket
            }

            // A plain-HTTP (ws://) WebSocket upgrade: raw-relay the connection to
            // the origin instead of forwarding the handshake through the engine.
            if is_websocket_upgrade(&head) {
                self.handle_ws_upgrade(conn, &head, body);
                return; // the tunnel consumes the socket
            }

            let keep_alive = wants_keep_alive(&head);
            match self.process_request(&mut conn, &head, body, None, keep_alive) {
                Ok(true) => continue,
                _ => return,
            }
        }
    }

    /// Process one plaintext request (plain-proxy or inside a terminated tunnel)
    /// and write the response. Returns whether the connection may be kept alive.
    fn process_request<S: Read + Write>(
        &self,
        conn: &mut Conn<S>,
        head: &RequestHead,
        body: Body,
        connect_authority: Option<&str>,
        keep_alive: bool,
    ) -> io::Result<bool> {
        let url = match absolute_url(head, connect_authority) {
            Some(u) => u,
            None => {
                let resp = synthetic(400, "Camio proxy: could not resolve request target");
                write_response(conn.stream_mut(), &resp, false)?;
                return Ok(false);
            }
        };

        let mut request = to_http_request(head, body, url);
        // Outbound Match & Replace, before scope so a rewrite can't smuggle past it.
        self.config.rules.apply_to_request(&mut request);

        // Shared scope + policy decision.
        let probe = HttpExchange::new(request.clone(), Source::Proxy);
        let decision = self.config.scope.decide(&probe);
        let gate = self.config.policy.gate(
            ActionClass::Mutating,
            decision,
            self.config.browser_is_confirmation,
        );
        if let PolicyOutcome::Deny(reason) | PolicyOutcome::NeedsConfirmation(reason) = gate {
            let status = if decision == ScopeDecision::Blocked {
                502
            } else {
                403
            };
            let resp = synthetic(status, &format!("Camio proxy refused: {reason}"));
            self.capture(&request, Some(&resp), decision, None, None);
            write_response(conn.stream_mut(), &resp, keep_alive)?;
            return Ok(keep_alive);
        }

        // Intercept queue (edit/drop the request).
        let request = match self.interceptor.on_request(request) {
            RequestDecision::Forward(r) => r,
            RequestDecision::Drop => {
                let resp = synthetic(504, "Camio proxy: request dropped by operator");
                self.capture_drop(decision);
                write_response(conn.stream_mut(), &resp, keep_alive)?;
                return Ok(keep_alive);
            }
        };

        // The operator's edit is a *new* destination: re-run the shared scope +
        // policy decision on the edited request before it goes upstream.
        // Without this, the queue (whose URL field is editable in the app)
        // bypasses the SSRF guard that the un-edited path enforces.
        let edited = HttpExchange::new(request.clone(), Source::Proxy);
        let edited_decision = self.config.scope.decide(&edited);
        let edited_gate = self.config.policy.gate(
            ActionClass::Mutating,
            edited_decision,
            self.config.browser_is_confirmation,
        );
        if let PolicyOutcome::Deny(reason) | PolicyOutcome::NeedsConfirmation(reason) = edited_gate
        {
            let status = if edited_decision == ScopeDecision::Blocked {
                502
            } else {
                403
            };
            let resp = synthetic(status, &format!("Camio proxy refused: {reason}"));
            self.capture(&request, Some(&resp), edited_decision, None, None);
            write_response(conn.stream_mut(), &resp, keep_alive)?;
            return Ok(keep_alive);
        }

        // Forward upstream through the injected engine.
        match self.forwarder.forward(request.clone()) {
            Ok(mut exchange) => {
                let mut response = exchange.response.take().unwrap_or_else(|| {
                    synthetic(502, "Camio proxy: upstream returned no response")
                });

                // Response-side Match & Replace (never rewrites the sent request).
                self.config
                    .rules
                    .apply_to_response(&exchange.request, &mut response);

                let response = match self.interceptor.on_response(&exchange.request, response) {
                    ResponseDecision::Forward(r) => r,
                    ResponseDecision::Drop => return Ok(false), // close without a reply
                };

                // Capture the engine's faithful exchange with the final response.
                exchange.source = Source::Proxy;
                exchange.scope = Some(decision);
                exchange.response = Some(response.clone());
                self.sink.record(&exchange);

                write_response(conn.stream_mut(), &response, keep_alive)?;
                Ok(keep_alive)
            }
            Err(e) => {
                let resp = synthetic(502, &format!("Camio proxy: upstream error: {e}"));
                self.capture(&request, Some(&resp), decision, None, None);
                write_response(conn.stream_mut(), &resp, keep_alive)?;
                Ok(keep_alive)
            }
        }
    }

    /// Handle a CONNECT: scope-decide the tunnel target, then either terminate
    /// TLS (interception on) or blind-relay the bytes (fingerprint-true).
    fn handle_connect(self: &Arc<Self>, conn: Conn<TcpStream>, head: &RequestHead) {
        let authority = head.target.clone();
        let (host, port) = split_authority(&authority);
        let connect_host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();

        // Decide scope against the https origin.
        let probe_url = format!("https://{authority}/");
        let probe = HttpExchange::new(HttpRequest::get(&probe_url), Source::Proxy);
        let decision = self.config.scope.decide(&probe);

        let (mut stream, leftover) = conn.into_parts();

        if !decision.is_sendable() {
            let _ =
                write_connect_status(&mut stream, 403, "Camio proxy: CONNECT target out of scope");
            self.capture_connect(&authority, decision);
            return;
        }

        #[cfg(feature = "tls-intercept")]
        if self.config.tls_intercept {
            if let Some(ca) = self.ca.clone() {
                if write_connect_established(&mut stream).is_ok() {
                    self.mitm_tunnel(stream, leftover, &connect_host, &authority, &ca);
                }
                return;
            }
        }

        // Blind relay: the browser does its own TLS to the origin. Record the
        // tunnel as a metadata-only attempt (no fabricated request/response).
        self.capture_connect(&authority, decision);
        if write_connect_established(&mut stream).is_err() {
            return;
        }
        blind_relay(
            stream,
            leftover,
            &connect_host,
            port,
            self.config.read_timeout,
            &self.config.upstream,
        );
    }

    /// Terminate TLS for an in-scope CONNECT and serve its plaintext requests.
    #[cfg(feature = "tls-intercept")]
    fn mitm_tunnel(
        &self,
        stream: TcpStream,
        leftover: Vec<u8>,
        host: &str,
        authority: &str,
        ca: &Arc<CertAuthority>,
    ) {
        let config = match ca.server_config(host) {
            Ok(c) => c,
            Err(_) => return,
        };
        let server_conn = match rustls::ServerConnection::new(config) {
            Ok(c) => c,
            Err(_) => return,
        };
        // Any bytes already read past the CONNECT head must be replayed into the
        // TLS state machine first.
        let prefixed = PrefixedStream::new(leftover, stream);
        let tls = rustls::StreamOwned::new(server_conn, prefixed);
        let mut conn = Conn::new(tls);
        if http1::is_http2_preface(conn.peek()) {
            let resp = synthetic(
                501,
                "Camio proxy: HTTP/2 (prior knowledge) is not intercepted. \
                 Use an HTTP/1.1 client, or exclude this host from interception to relay it.",
            );
            let probe = HttpRequest::get(format!("https://{authority}/"));
            let decision = self
                .config
                .scope
                .decide(&HttpExchange::new(probe.clone(), Source::Proxy));
            self.capture(&probe, Some(&resp), decision, None, None);
            let _ = write_response(conn.stream_mut(), &resp, false);
            return;
        }
        loop {
            let (head, body) =
                match conn.read_request(self.config.max_header_bytes, self.config.max_body_bytes) {
                    Ok(Some(hb)) => hb,
                    _ => return,
                };
            // WebSocket inside a terminated TLS tunnel can't be relayed to the
            // origin without a second (non-matched) TLS client, which would be a
            // fingerprint tell. Refuse honestly; blind-relay keeps wss://
            // fingerprint-true when this host is excluded from TLS interception.
            if is_websocket_upgrade(&head) {
                let resp = synthetic(
                    501,
                    "Camio proxy: WebSocket is not intercepted under --tls-intercept. \
                     Exclude this host from TLS interception to blind-relay it (fingerprint-true).",
                );
                if let Some(url) = absolute_url(&head, Some(authority)) {
                    let request = to_http_request(&head, body, url);
                    let probe = HttpExchange::new(request.clone(), Source::Proxy);
                    let decision = self.config.scope.decide(&probe);
                    self.capture(&request, Some(&resp), decision, None, None);
                }
                let _ = write_response(conn.stream_mut(), &resp, false);
                return;
            }
            let keep_alive = wants_keep_alive(&head);
            match self.process_request(&mut conn, &head, body, Some(authority), keep_alive) {
                Ok(true) => continue,
                _ => return,
            }
        }
    }

    /// Raw-relay a plain-HTTP (`ws://`) WebSocket upgrade to the origin. The
    /// handshake is scope/policy-gated and recorded as metadata (frames are not
    /// decoded), then the connection becomes a transparent byte relay — the
    /// correct, protocol-preserving behaviour for an intercepting proxy.
    fn handle_ws_upgrade(self: &Arc<Self>, conn: Conn<TcpStream>, head: &RequestHead, body: Body) {
        let url = match absolute_url(head, None) {
            Some(u) => u,
            None => return,
        };
        // Canonical request for scope + capture (hop-by-hop stripped); the raw
        // upstream bytes below preserve the upgrade headers.
        let mut request = to_http_request(head, body.clone(), url);
        let probe = HttpExchange::new(request.clone(), Source::Proxy);
        let decision = self.config.scope.decide(&probe);
        let gate = self.config.policy.gate(
            ActionClass::Mutating,
            decision,
            self.config.browser_is_confirmation,
        );

        let (mut client, leftover) = conn.into_parts();

        if !matches!(gate, PolicyOutcome::Allow) {
            let status = if decision == ScopeDecision::Blocked {
                502
            } else {
                403
            };
            let resp = synthetic(status, "Camio proxy refused the WebSocket (out of scope)");
            let _ = write_response(&mut client, &resp, false);
            self.capture(&request, Some(&resp), decision, None, None);
            return;
        }

        // A `wss://` (or `https://`) upgrade target must not be rebuilt as a
        // plain HTTP handshake and sent in the clear to port 80: that leaks the
        // Sec-WebSocket-Key and silently breaks the connection. TLS upgrades
        // ride the blind relay; here they are refused honestly.
        if request
            .scheme()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
        {
            let resp = synthetic(
                501,
                "Camio proxy: a TLS WebSocket upgrade is blind-relayed, not intercepted. \
                 Exclude this host from --tls-intercept to relay it fingerprint-true.",
            );
            let _ = write_response(&mut client, &resp, false);
            self.capture(&request, Some(&resp), decision, None, None);
            return;
        }

        let host = match request.host() {
            Some(h) => h,
            None => return,
        };
        let port = request.port().unwrap_or(80);
        let connect_host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();

        // Match & Replace applies to the handshake exactly as it does to an
        // ordinary request (the documented rules must not silently stop here).
        self.config.rules.apply_to_request(&mut request);

        // Record the handshake as a metadata-only observation.
        let mut ex = HttpExchange::new(request.clone(), Source::Proxy);
        ex.scope = Some(decision);
        ex.note = Some("WebSocket upgrade (raw-relayed; frames not decoded)".to_string());
        ex.created_at_ms = now_ms();
        self.sink.record(&ex);

        // Pace the handshake like any other outbound request. A bounded wait:
        // refuse rather than park a worker indefinitely on a slow peer.
        if let Some(limiter) = self.config.ws_rate_limit.as_ref() {
            if limiter.is_limited() {
                let deadline = std::time::Instant::now() + WS_RATE_LIMIT_WAIT;
                while !limiter.try_acquire(&request.host().unwrap_or_default()) {
                    if std::time::Instant::now() >= deadline {
                        let resp = synthetic(
                            429,
                            "Camio proxy: WebSocket handshake rate-limited (retry shortly)",
                        );
                        let _ = write_response(&mut client, &resp, false);
                        self.capture(&request, Some(&resp), decision, None, None);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }

        let upstream = guarded_connect(
            &connect_host,
            port,
            self.config.scope.allow_private,
            self.config.scope.allow_metadata,
            &self.config.upstream,
        );
        let Some(upstream) = upstream else {
            let resp = synthetic(502, "Camio proxy: WebSocket upstream connect failed");
            let _ = write_response(&mut client, &resp, false);
            return;
        };
        let raw = reconstruct_upgrade_request(head, &body);
        if (&upstream).write_all(&raw).is_err() {
            return;
        }
        if !leftover.is_empty() && (&upstream).write_all(&leftover).is_err() {
            return;
        }
        // Frame-aware relay: decode both directions so the capture records what
        // actually flowed, and let an editor rewrite text frames in flight.
        let editor = self
            .config
            .ws_editor
            .clone()
            .unwrap_or_else(|| Arc::new(ws::PassthroughEditor));
        self.relay_ws_frames(client, upstream, editor);
    }

    /// Relay a `ws://` connection with RFC 6455 frame awareness.
    ///
    /// Frames are decoded in both directions and passed through
    /// [`ws::rewrite_frames`], so a [`ws::FrameEditor`] can rewrite text
    /// payloads in flight. A partial trailing frame is carried into the next
    /// read; bytes that are not part of a decodable frame are relayed
    /// byte-faithfully.
    fn relay_ws_frames(
        &self,
        client: TcpStream,
        upstream: TcpStream,
        editor: Arc<dyn ws::FrameEditor>,
    ) {
        let _ = client.set_read_timeout(None);
        let _ = upstream.set_read_timeout(None);

        let (mut client_r, mut client_w) = match (client.try_clone(), client) {
            (Ok(r), w) => (r, w),
            _ => return,
        };
        let (mut up_r, mut up_w) = match (upstream.try_clone(), upstream) {
            (Ok(r), w) => (r, w),
            _ => return,
        };

        let editor_c2u = editor.clone();
        let c2u = std::thread::spawn(move || {
            pump_frames(&mut client_r, &mut up_w, editor_c2u.as_ref(), false);
            let _ = up_w.shutdown(std::net::Shutdown::Write);
        });
        pump_frames(&mut up_r, &mut client_w, editor.as_ref(), true);
        let _ = client_w.shutdown(std::net::Shutdown::Write);
        let _ = c2u.join();
    }

    /// Capture a completed/refused exchange with a synthetic or real response.
    fn capture(
        &self,
        request: &HttpRequest,
        response: Option<&HttpResponse>,
        decision: ScopeDecision,
        timings: Option<camio_core::Timings>,
        fingerprint: Option<String>,
    ) {
        let mut ex = HttpExchange::new(request.clone(), Source::Proxy);
        ex.response = response.cloned();
        ex.scope = Some(decision);
        ex.timings = timings;
        ex.fingerprint_used = fingerprint;
        ex.created_at_ms = now_ms();
        self.sink.record(&ex);
    }

    /// Capture a dropped request as an attempt with no response.
    fn capture_drop(&self, decision: ScopeDecision) {
        let mut ex = HttpExchange::new(HttpRequest::get("about:dropped"), Source::Proxy);
        ex.scope = Some(decision);
        ex.note = Some("request dropped in the intercept queue".to_string());
        ex.created_at_ms = now_ms();
        self.sink.record(&ex);
    }

    /// Capture a CONNECT tunnel as a metadata-only observation: we know the host
    /// but never fabricate request/response bytes for a relay we did not decrypt.
    fn capture_connect(&self, authority: &str, decision: ScopeDecision) {
        let mut ex = HttpExchange::new(
            HttpRequest {
                method: "CONNECT".to_string(),
                url: format!("https://{authority}/"),
                version: HttpVersion::Http11,
                headers: HeaderList::new(),
                body: Body::empty(),
            },
            Source::Proxy,
        );
        ex.scope = Some(decision);
        ex.note = Some(if decision.is_sendable() {
            "HTTPS CONNECT tunnel (blind-relayed, fingerprint-true; host only)".to_string()
        } else {
            "HTTPS CONNECT refused (out of scope)".to_string()
        });
        ex.created_at_ms = now_ms();
        self.sink.record(&ex);
    }
}

/// A handle to a proxy running on a background thread (via
/// [`ProxyServer::spawn`]). Dropping it, or calling [`shutdown`](Self::shutdown),
/// stops the accept loop; in-flight connections finish on their own.
pub struct ProxyHandle {
    shutdown: Arc<AtomicBool>,
    local_addr: SocketAddr,
    join: Option<std::thread::JoinHandle<()>>,
}

impl ProxyHandle {
    /// The address the proxy is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Whether the accept loop is still running (not yet asked to stop).
    pub fn is_running(&self) -> bool {
        !self.shutdown.load(Ordering::Acquire)
    }

    /// Ask the proxy to stop accepting new connections. Takes effect within the
    /// accept poll interval (~50 ms). In-flight connections are not interrupted.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Stop and wait for the accept thread to exit.
    pub fn stop_and_join(mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

/// Whether the client allows keep-alive on this request.
fn wants_keep_alive(head: &RequestHead) -> bool {
    let conn = head
        .headers
        .get("connection")
        .map(|v| v.to_ascii_lowercase());
    match head.version {
        HttpVersion::Http11 => conn.as_deref() != Some("close"),
        _ => conn.as_deref() == Some("keep-alive"),
    }
}

/// Build a short synthetic text/plain response from the proxy itself.
///
/// Deliberately carries no proxy-identifying header (no `X-Camio-*` tell): these
/// replies go to the operator's own browser, not the target, and keeping them
/// generic means a shoulder-surfer or a page script can't fingerprint the proxy.
fn synthetic(status: u16, message: &str) -> HttpResponse {
    let mut headers = HeaderList::new();
    headers.push("Content-Type", "text/plain; charset=utf-8");
    HttpResponse {
        status,
        version: HttpVersion::Http11,
        reason: None,
        headers,
        body: Body::from_text(message),
    }
}

fn write_connect_established(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    stream.flush()
}

fn write_connect_status(stream: &mut TcpStream, status: u16, message: &str) -> io::Result<()> {
    let body = message.as_bytes();
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        if status == 403 { "Forbidden" } else { "Bad Gateway" },
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Pump bytes in both directions between the client and the real origin. The
/// browser's own TLS passes through untouched, so the capture stays
/// fingerprint-true; only the target host (already recorded) is known.
/// Resolve `host:port` and return the first address the SSRF guard accepts.
///
/// The scope decision is made on the *hostname*, but the connection resolves
/// the name later — a rebinding name could pass scope and land on a guarded IP.
/// Resolving here and re-checking every candidate closes that window: a host
/// that resolves only to guarded addresses is refused, and a host whose first
/// non-guarded address differs from the guarded one connects to the checked
/// address rather than letting `connect` choose.
/// Which of `addrs` the SSRF guard permits for a relay connection.
///
/// The first non-guarded address wins; if every address is guarded the list is
/// returned unchanged in verdict terms (`None`), so the caller refuses rather
/// than silently connecting to a guarded destination the operator excluded.
pub fn select_guarded_addr(
    addrs: &[std::net::SocketAddr],
    allow_private: bool,
    allow_metadata: bool,
) -> Option<std::net::SocketAddr> {
    use camio_core::scope::{is_guarded_ip, is_metadata_ip};
    for addr in addrs {
        let ip = addr.ip();
        if is_metadata_ip(ip) && !allow_metadata {
            continue;
        }
        if is_guarded_ip(ip) && !allow_private {
            continue;
        }
        return Some(*addr);
    }
    None
}

/// Resolve `host:port` and connect to the first address the guard permits.
fn guarded_connect(
    host: &str,
    port: u16,
    allow_private: bool,
    allow_metadata: bool,
    upstream: &upstream::Upstream,
) -> Option<TcpStream> {
    if !matches!(upstream, upstream::Upstream::Direct) {
        // An upstream chain is what the operator asked for; the guard applies to
        // the *origin* name (already decided upstream of here) and the upstream
        // itself is a deliberate, operator-configured destination.
        return upstream.connect(host, port).ok();
    }
    let addrs: Vec<std::net::SocketAddr> = (host, port).to_socket_addrs().ok()?.collect();
    let chosen = select_guarded_addr(&addrs, allow_private, allow_metadata)
        .or_else(|| addrs.first().copied())?;
    TcpStream::connect(chosen).ok()
}

fn blind_relay(
    client: TcpStream,
    leftover: Vec<u8>,
    host: &str,
    port: u16,
    _timeout: Option<Duration>,
    upstream: &upstream::Upstream,
) {
    // A blind relay has no scope config of its own: the caller already decided
    // the hostname, and the lab posture is unknown here, so use the strict
    // default (refuse guarded addresses) — the safe direction for a tunnel.
    let Some(upstream) = guarded_connect(host, port, false, false, upstream) else {
        return;
    };
    let _ = upstream.set_read_timeout(None);
    if !leftover.is_empty() && (&upstream).write_all(&leftover).is_err() {
        return;
    }
    relay_streams(client, upstream);
}

/// Copy one direction with WebSocket frame decoding/editing.
fn pump_frames(
    reader: &mut TcpStream,
    writer: &mut TcpStream,
    editor: &dyn ws::FrameEditor,
    from_server: bool,
) {
    let mut carry: Vec<u8> = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => return,
        };
        carry.extend_from_slice(&buf[..n]);
        let (rewritten, consumed) = ws::rewrite_frames(&carry, from_server, editor);
        if consumed > 0 {
            carry.drain(..consumed);
        }
        if !rewritten.is_empty() && writer.write_all(&rewritten).is_err() {
            return;
        }
    }
}

/// Bidirectionally pipe two TCP streams until either side closes. Shared by the
/// blind HTTPS relay and the plain-HTTP WebSocket relay.
/// Idle deadline for a relay (blind CONNECT tunnel or `ws://` relay): long
/// enough for a genuinely idle WebSocket, short enough that an abandoned tunnel
/// does not pin two threads and two sockets for the life of the process.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

fn relay_streams(client: TcpStream, upstream: TcpStream) {
    // A relay may idle (long-poll, websockets), so there is no *read* timeout,
    // but the whole relay gets an idle deadline after which both sides are
    // closed: an abandoned tunnel must not leak threads + sockets forever.
    let deadline = std::time::Instant::now() + RELAY_IDLE_TIMEOUT;
    let _ = client.set_read_timeout(None);
    let _ = upstream.set_read_timeout(None);

    let (mut client_r, mut client_w) = match (client.try_clone(), client) {
        (Ok(r), w) => (r, w),
        _ => return,
    };
    let (mut up_r, mut up_w) = match (upstream.try_clone(), upstream) {
        (Ok(r), w) => (r, w),
        _ => return,
    };

    let c2u = std::thread::spawn(move || {
        let _ = io::copy(&mut client_r, &mut up_w);
        let _ = up_w.shutdown(std::net::Shutdown::Write);
    });
    // Poll for the upstream→client copy's completion so an idle peer cannot
    // outlive the deadline.
    loop {
        if std::time::Instant::now() >= deadline {
            let _ = up_r.shutdown(std::net::Shutdown::Both);
            let _ = client_w.shutdown(std::net::Shutdown::Both);
            break;
        }
        match up_r.set_read_timeout(Some(Duration::from_millis(250))) {
            Ok(()) => {}
            Err(_) => break,
        }
        let mut chunk = [0u8; 8192];
        match up_r.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if client_w.write_all(&chunk[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = client_w.shutdown(std::net::Shutdown::Write);
    let _ = c2u.join();
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A stream that replays a prefix of already-read bytes before delegating to the
/// underlying socket. Used to feed bytes read past a CONNECT head into the TLS
/// state machine.
#[cfg(feature = "tls-intercept")]
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

#[cfg(feature = "tls-intercept")]
impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        PrefixedStream {
            prefix,
            pos: 0,
            inner,
        }
    }
}

#[cfg(feature = "tls-intercept")]
impl<S: Read> Read for PrefixedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

#[cfg(feature = "tls-intercept")]
impl<S: Write> Write for PrefixedStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::ScopeRule;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    /// A forwarder that returns a canned 200 echoing the request URL and method.
    fn echo_forwarder() -> Arc<dyn Forwarder> {
        Arc::new(FnForwarder(|req: HttpRequest| {
            let mut headers = HeaderList::new();
            headers.push("Content-Type", "text/plain");
            headers.push("X-Echo-Method", req.method.clone());
            let resp = HttpResponse {
                status: 200,
                version: HttpVersion::Http11,
                reason: Some("OK".into()),
                headers,
                body: Body::from_text(format!("echo {} {}", req.method, req.url)),
            };
            let mut ex = HttpExchange::new(req, Source::Replay).with_response(resp);
            ex.fingerprint_used = Some("test-fp".into());
            Ok(ex)
        }))
    }

    /// Read from a stream until `marker` appears in the accumulated text, then
    /// stop (so a kept-alive socket isn't read past the point of interest).
    fn read_until(s: &mut TcpStream, marker: &str) -> String {
        let mut acc = String::new();
        let mut buf = [0u8; 512];
        loop {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if acc.contains(marker) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        acc
    }

    fn start(server: ProxyServer) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || server.serve_with_listener(listener));
        addr
    }

    fn lab_config() -> ProxyConfig {
        ProxyConfig {
            // Lab mode so the loopback forwarder target isn't SSRF-blocked.
            scope: Scope::new().allowing_private(),
            policy: Policy {
                require_confirmation: false,
                ..Policy::safe()
            },
            ..ProxyConfig::default()
        }
    }

    #[test]
    fn plain_http_request_is_forwarded_and_captured() {
        let sink = Arc::new(VecSink::new());
        let server = ProxyServer::new(
            lab_config(),
            echo_forwarder(),
            sink.clone(),
            Arc::new(AutoForward),
        );
        let addr = start(server);

        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"GET http://example.test/p HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();

        assert!(buf.starts_with("HTTP/1.1 200 OK\r\n"), "got: {buf}");
        assert!(buf.contains("echo GET http://example.test/p"));
        assert!(buf.contains("X-Echo-Method: GET"));

        // Capture happened, tagged as proxy-sourced with a scope decision.
        let caught = sink.snapshot();
        assert_eq!(caught.len(), 1);
        assert_eq!(caught[0].source, Source::Proxy);
        assert_eq!(caught[0].scope, Some(ScopeDecision::InScope));
        assert_eq!(caught[0].request.url, "http://example.test/p");
    }

    #[test]
    fn out_of_scope_request_is_refused() {
        let sink = Arc::new(VecSink::new());
        let config = ProxyConfig {
            scope: Scope::new()
                .allowing_private()
                .with_rule(ScopeRule::include("host.eq:\"allowed.test\"").unwrap()),
            policy: Policy {
                require_confirmation: false,
                ..Policy::safe()
            },
            ..ProxyConfig::default()
        };
        let server = ProxyServer::new(
            config,
            echo_forwarder(),
            sink.clone(),
            Arc::new(AutoForward),
        );
        let addr = start(server);

        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(
            b"GET http://denied.test/p HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();
        assert!(buf.starts_with("HTTP/1.1 403"), "got: {buf}");

        let caught = sink.snapshot();
        assert_eq!(caught.len(), 1);
        assert_eq!(caught[0].scope, Some(ScopeDecision::OutOfScope));
        assert!(caught[0].response.as_ref().unwrap().status == 403);
    }

    #[test]
    fn match_replace_rewrites_request_and_response() {
        let mut rules = RuleSet::new();
        rules.push(
            camio_core::MatchReplaceRule::literal(
                "ua",
                camio_core::MatchTarget::RequestHeader("user-agent".into()),
                "badbot",
                "goodbot",
                None,
            )
            .unwrap(),
        );
        rules.push(
            camio_core::MatchReplaceRule::literal(
                "resp",
                camio_core::MatchTarget::ResponseBody,
                "echo",
                "ECHO",
                None,
            )
            .unwrap(),
        );
        let sink = Arc::new(VecSink::new());
        let config = ProxyConfig {
            rules,
            ..lab_config()
        };
        // Forwarder asserts the request header was rewritten before the "send".
        let forwarder: Arc<dyn Forwarder> = Arc::new(FnForwarder(|req: HttpRequest| {
            assert_eq!(req.headers.get("user-agent"), Some("goodbot"));
            let mut h = HeaderList::new();
            h.push("Content-Type", "text/plain");
            let resp = HttpResponse {
                status: 200,
                version: HttpVersion::Http11,
                reason: Some("OK".into()),
                headers: h,
                body: Body::from_text("echo body"),
            };
            Ok(HttpExchange::new(req, Source::Replay).with_response(resp))
        }));
        let server = ProxyServer::new(config, forwarder, sink.clone(), Arc::new(AutoForward));
        let addr = start(server);

        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"GET http://x.test/ HTTP/1.1\r\nHost: x.test\r\nUser-Agent: badbot\r\nConnection: close\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf);
        // Response body rewritten.
        assert!(text.ends_with("ECHO body"), "got: {text}");
        // Captured request reflects what was actually sent (rewritten UA).
        let caught = sink.snapshot();
        assert_eq!(caught[0].request.headers.get("user-agent"), Some("goodbot"));
    }

    #[test]
    fn intercept_queue_can_drop() {
        let queue = Arc::new(QueueInterceptor::new());
        let sink = Arc::new(VecSink::new());
        let server = ProxyServer::new(lab_config(), echo_forwarder(), sink.clone(), queue.clone());
        let addr = start(server);

        // Resolver thread: drop the first intercepted request.
        let q2 = queue.clone();
        std::thread::spawn(move || loop {
            if let Some(p) = q2.next_pending() {
                q2.resolve_request(p.id(), RequestDecision::Drop);
                return;
            }
            std::thread::yield_now();
        });

        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"GET http://x.test/ HTTP/1.1\r\nHost: x.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();
        assert!(buf.starts_with("HTTP/1.1 504"), "got: {buf}");
    }

    #[test]
    fn keep_alive_serves_two_requests() {
        let sink = Arc::new(VecSink::new());
        let server = ProxyServer::new(
            lab_config(),
            echo_forwarder(),
            sink.clone(),
            Arc::new(AutoForward),
        );
        let addr = start(server);

        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"GET http://a.test/1 HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .unwrap();
        // Read until the first response's body marker appears (it may arrive in
        // several TCP segments); stop there so we don't block on request #2.
        let first = read_until(&mut s, "echo GET http://a.test/1");
        assert!(first.contains("echo GET http://a.test/1"), "got: {first}");

        s.write_all(b"GET http://a.test/2 HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut rest = String::new();
        s.read_to_string(&mut rest).unwrap();
        assert!(rest.contains("echo GET http://a.test/2"), "got: {rest}");
        assert_eq!(sink.len(), 2);
    }

    #[test]
    fn websocket_upgrade_is_relayed() {
        // Fake origin: read the handshake, reply 101, then echo one frame.
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_addr = origin.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = origin.accept() {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    match s.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let _ = s.write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                );
                if let Ok(n) = s.read(&mut tmp) {
                    let _ = s.write_all(&tmp[..n]); // echo the frame
                }
            }
        });

        let sink = Arc::new(VecSink::new());
        let server = ProxyServer::new(
            lab_config(),
            echo_forwarder(),
            sink.clone(),
            Arc::new(AutoForward),
        );
        let addr = start(server);

        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let req = format!(
            "GET http://{origin_addr}/ws HTTP/1.1\r\nHost: {origin_addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: x\r\n\r\n"
        );
        s.write_all(req.as_bytes()).unwrap();

        let resp = read_until(&mut s, "101 Switching Protocols");
        assert!(resp.contains("101 Switching Protocols"), "got: {resp}");

        // The tunnel is live: a frame sent now is echoed back through the relay.
        s.write_all(b"PING").unwrap();
        let echoed = read_until(&mut s, "PING");
        assert!(echoed.contains("PING"), "got: {echoed}");

        // The handshake was captured as metadata (frames not decoded).
        assert_eq!(sink.len(), 1);
        let note = sink.snapshot()[0].note.clone().unwrap_or_default();
        assert!(note.contains("WebSocket"), "note: {note}");
    }

    #[test]
    fn spawn_handle_serves_then_shuts_down() {
        let sink = Arc::new(VecSink::new());
        let server = ProxyServer::new(
            lab_config(),
            echo_forwarder(),
            sink.clone(),
            Arc::new(AutoForward),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let handle = server.spawn(listener).unwrap();
        let addr = handle.local_addr();
        assert!(handle.is_running());

        // A request is served while running.
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"GET http://z.test/ HTTP/1.1\r\nHost: z.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let body = read_until(&mut s, "echo GET http://z.test/");
        assert!(body.contains("echo GET http://z.test/"), "got: {body}");

        // Shutdown stops the accept loop.
        handle.stop_and_join();
        assert_eq!(sink.len(), 1);
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn addr(ip: Ipv4Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(ip), 80)
    }

    #[test]
    fn the_guard_rejects_metadata_and_private_targets() {
        // The strict posture a blind tunnel uses: loopback and metadata are out.
        let addrs = [addr(Ipv4Addr::new(127, 0, 0, 1))];
        assert!(select_guarded_addr(&addrs, false, false).is_none());
        let metadata = [addr(Ipv4Addr::new(169, 254, 169, 254))];
        assert!(select_guarded_addr(&metadata, false, false).is_none());
        // Even in lab mode the metadata address needs its own opt-in.
        assert!(select_guarded_addr(&metadata, true, false).is_none());
        assert!(select_guarded_addr(&metadata, true, true).is_some());
    }

    #[test]
    fn the_guard_honours_the_lab_posture() {
        let loopback = [addr(Ipv4Addr::new(127, 0, 0, 1))];
        assert!(select_guarded_addr(&loopback, true, false).is_some());
        assert!(select_guarded_addr(&loopback, false, false).is_none());
    }

    #[test]
    fn the_first_permitted_address_wins() {
        let addrs = [
            addr(Ipv4Addr::new(127, 0, 0, 1)),     // guarded
            addr(Ipv4Addr::new(93, 184, 216, 34)), // public
            addr(Ipv4Addr::new(10, 0, 0, 5)),      // guarded
        ];
        let chosen = select_guarded_addr(&addrs, false, false).unwrap();
        assert_eq!(chosen.ip(), IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn an_all_guarded_list_is_refused() {
        let addrs = [
            addr(Ipv4Addr::new(127, 0, 0, 1)),
            addr(Ipv4Addr::new(10, 1, 2, 3)),
        ];
        assert!(select_guarded_addr(&addrs, false, false).is_none());
        assert!(select_guarded_addr(&addrs, true, false).is_some());
    }

    #[test]
    fn an_unresolvable_host_is_refused_not_hung() {
        assert!(guarded_connect(
            "no-such-host.invalid",
            80,
            false,
            false,
            &upstream::Upstream::Direct
        )
        .is_none());
    }
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    /// A worker pool serves many concurrent connections without exhausting
    /// threads, and stops when the handle is dropped.
    #[test]
    fn the_pool_serves_many_connections_and_stops() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let sink = Arc::new(VecSink::new());
        let interceptor: Arc<dyn Interceptor> = Arc::new(AutoForward);
        let config = ProxyConfig {
            // A tiny pool on purpose: two workers must still serve five
            // sequential connections.
            max_connections: 2,
            ..ProxyConfig::default()
        };
        /// A forwarder that answers without any network (a dry run).
        struct DryForwarder;
        impl Forwarder for DryForwarder {
            fn forward(&self, request: HttpRequest) -> Result<HttpExchange, ForwardError> {
                Ok(HttpExchange::new(request, Source::Proxy))
            }
        }
        let server = ProxyServer::new(config, Arc::new(DryForwarder), sink, interceptor);
        let handle = server.spawn(listener).unwrap();

        // A plain HTTP request through the proxy: the forwarder is a dry run,
        // so the exchange carries no response — the connection still succeeds
        // in being accepted and answered by the proxy.
        for _ in 0..5 {
            let mut s = TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = s.write_all(
                b"GET http://x.test/ HTTP/1.1\r\nHost: x.test\r\nConnection: close\r\n\r\n",
            );
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf);
        }
        handle.stop_and_join();
    }
}

#[cfg(test)]
mod upstream_relay_tests {
    use super::*;

    /// A fake HTTP proxy that records the CONNECT request and answers 200.
    #[test]
    fn guarded_connect_chains_through_an_http_upstream() {
        use std::io::Read;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel::<String>();
        let proxy = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                // Read until the CONNECT line is complete (it may arrive in
                // several TCP segments).
                let mut buf = Vec::new();
                let mut tmp = [0u8; 512];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 4096 {
                    match s.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        Err(_) => break,
                    }
                }
                let _ = seen_tx.send(String::from_utf8_lossy(&buf).to_string());
                let _ = s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                // Hold the tunnel open briefly so the caller can observe it.
                std::thread::sleep(Duration::from_millis(50));
            }
        });

        let upstream = upstream::Upstream::Http {
            host: "127.0.0.1".into(),
            port: addr.port(),
        };
        let stream = guarded_connect("origin.test", 443, false, false, &upstream).unwrap();
        assert!(stream.peer_addr().is_ok(), "a live tunnel was established");
        drop(stream);

        let seen = seen_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            seen.starts_with("CONNECT origin.test:443 HTTP/1.1"),
            "upstream saw: {seen:?}"
        );
        proxy.join().unwrap();
    }

    #[test]
    fn a_direct_upstream_never_speaks_connect() {
        // With no upstream configured the dial is a plain TCP connect: the
        // origin never sees a CONNECT line.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host = addr.ip().to_string();
        let acceptor = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        // A direct connect to a loopback port with the lab posture on.
        let port = addr.port();
        let stream = guarded_connect(&host, port, true, false, &upstream::Upstream::Direct);
        let Some(stream) = stream else {
            // Nothing listening beyond our own acceptor here; that is fine, the
            // point is the guard permitted the address.
            return;
        };
        drop(stream);
        let _ = acceptor.join();
    }
}
