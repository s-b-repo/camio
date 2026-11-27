# Changelog

All notable changes to Camio are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project uses semantic
versioning once it reaches 1.0.

## [0.4.0] — 2026-11-27

### Added

- **Security hardening pass 3 (all deferred findings closed):**
  - **Upstream chaining for raw relays** (`camio-proxy::upstream`): blind CONNECT
    tunnels and `ws://` relays now dial through an upstream HTTP (`CONNECT`) or
    SOCKS5 proxy instead of always going direct, mirroring the engine-forwarded
    path. Unknown schemes are refused rather than silently downgraded to a direct
    connection.
  - **WebSocket frame decoding and in-flight editing** (`camio-proxy::ws`): RFC
    6455 frames are decoded in both directions, a `FrameEditor` can rewrite text
    payloads in flight, partial frames are held correctly, and non-frame bytes
    after the upgrade are relayed verbatim.
  - **HTTP/2 prior-knowledge is refused honestly**: the connection preface is
    detected in both the plain and TLS-intercepted paths and answered with an
    explicit 501 + capture record, instead of being dropped as a malformed
    HTTP/1.1 request.
  - **Bounded connection worker pools** (`camio-proxy`, `camio-web`): the proxy
    serves at most `max_connections` (default 64) and the web API runs an
    `available_parallelism`-bounded pool, so one slow or hostile client no longer
    blocks everyone else.
  - **`ws://` rate limiting**: the configured `--rate-limit` now paces WebSocket
    handshakes too (bounded wait, then 429), not just HTTP requests.
  - **CA rotation/removal** (`camio-proxy`: `CertAuthority::rotate`/`remove`;
    CLI `camio proxy --rotate-ca` / `--remove-ca`), verified end-to-end.
  - **Bounded TLS leaf cache**: per-host leaf configs are a bounded LRU (256), so
    a client cannot force unbounded keygen + map growth.
  - **DNS TOCTOU closed**: relays resolve the host and re-check every candidate
    address against the SSRF guard before connecting.
  - **Durable OAST storage + retention** (`camio-oast::durable`, store schema v9,
    `camio oast --db --retain --retain-for`): interactions survive a restart and
    are pruned by count and age.
  - **DNS responder for pure-DNS exfiltration** (`camio-oast::dns`,
    `camio oast --dns-listen`): answers `A` queries for `<token>.<base>` with the
    collector's address and records the lookup as a correlated interaction —
    verified end-to-end over a real UDP socket.
  - **Resumable campaigns** (`camio-automate::generate_from`,
    `camio fuzz --resume-from N`): an interrupted campaign executes only its
    unexecuted remainder, never replaying sent work, still bound to the plan's
    approval hash.
  - **Approval surface beyond the CLI**: `/api/fuzz_run` returns and verifies
    `plan_hash`/`approval`; MCP `fuzz_plan` returns the plan hash and
    `active_scan` binds to it — the same binding semantics as
    `camio fuzz --approve`.
  - **Probe target seeding and caps** (`camio probe --from-sitemap`,
    `--from-saved`, `--max-probes`, `--max-response-bytes`): targets come from the
    project's own inventory or a saved CamioQL search, and both the run and each
    observation are bounded.
  - **Measured transport status** (native app overview, `/api/meta`): the
    transport panel reports *matched* vs *not matched* with the parity note,
    instead of a hardcoded "unverified" claim; the proxy also appears as a
    durable task whose stop is its cancellation.

- **httpx integration** (`camio-integrations::httpx`, `camio probe`, plan §6/F16):
  ProjectDiscovery's HTTP prober now has a real adapter — a tolerant JSONL parser
  (both `status-code` and `status_code` spellings, `cdn: false|string`, Go-style
  durations, TLS subject CN/SANs), a bounded runner (rate, concurrency,
  per-probe timeout, wall-clock kill, 16 MiB stdout cap, cooperative
  cancellation), and defaults that never follow redirects or expand hosts
  unless the operator opts in. Results are stored as `source=httpx`
  observations (raw artifact kept separately), never promoted to findings;
  unreachable targets stay visible as outcomes. `camio probe --import
  <file.jsonl>` is the import-only path. The adapter also refuses to run
  against a differently-named `httpx` binary (it checks ProjectDiscovery's
  `Current Version` marker first) instead of silently producing no results —
  and `camio integrations` now reports compatibility the same way.
- **Durable background tasks** (`camio-core`, `camio-tasks`, `camio-store`,
  `camio tasks`, plan §4.2/F03): the full persisted task lifecycle
  (queued / awaiting_approval / running / paused / cancelling / cancelled /
  completed / failed / interrupted) with validated transitions
  (`TaskState::can_transition_to`), distinct terminal outcomes
  (`TaskOutcome`: success, timeout, cancelled, scope_denied, parser_failure,
  tool_failure, storage_failure), a `task_record` table (schema migration
  v7→v8) that mirrors every lifecycle change through a `TaskSink`, restart
  reconciliation (non-terminal records become `interrupted`, never replayed),
  and `camio tasks [--reconcile]`. The native app spawns its background tasks
  through the sink and surfaces interrupted runs on the Tasks surface.
- **Approval binding** (`camio_core::Approval`, `camio fuzz --approve`,
  plan §4.3): an approval is bound to a sha-256 plan hash over the exact
  target set, action class, tool version, session reference, request/time/rate
  limits, and policy revision; reuse is refused on any drift, on a new target,
  on larger limits, or after expiry. `camio fuzz` prints the plan hash in its
  preview and refuses a stale `--approve <hash>`.
- **Security hardening pass 1** (external review of 20 crates):
  - **Request-smuggling / body corruption fixed** (`camio-proxy`): the proxy
    re-frames bodies, so the client's `Content-Length`/`Transfer-Encoding` are
    no longer forwarded verbatim; a Match & Replace body rewrite could
    otherwise desynchronize the origin (truncated bodies, hanging requests).
  - **Intercept-queue re-gate** (`camio-proxy`): an operator *edit* to a queued
    request is a new destination, so it is re-decided through the shared
    scope/policy path before forwarding — the queue no longer bypasses the
    SSRF guard (metadata/loopback targets are refused).
  - **Intercept-queue timeouts + cap** (`camio-proxy::QueueInterceptor`): a
    parked request/response now resolves after `set_park_timeout` (default
    5 minutes, forwarded unchanged) and at most 512 items may be parked, so a
    forgotten front-end cannot pin threads/sockets forever.
  - **CA key permissions** (`camio-proxy`): the CA private key is created
    `0600` from the start (no world-readable window) and repaired on load.
  - **Accept-loop backoff** (`camio-proxy`, `camio-oast`): a non-`WouldBlock`
    accept error no longer busy-spins the CPU at 100% under fd exhaustion.
  - **Bounded tool input** (`camio-engine`): engine unpacking caps total
    uncompressed size (1 GiB) and entries (50 000), and drops setuid/setgid
    bits; `locate_binary` no longer aborts its search on one unreadable entry.
  - **Import hardening** (`camio-import`): input size (32 MiB) and entry-count
    (50 000) caps inside the parser, and header names/values carrying
    CR/LF/NUL are refused with a reported warning — an imported archive can no
    longer inject request headers on replay.
  - **Decompression cap** (`camio-convert`): `Transform::apply` decompression
    is bounded (32 MiB), so a gzip bomb cannot OOM the CLI/MCP/app convert path.
  - **Bounded response reads** (`camio-request`, `camio-ai`): response bodies
    are read under a hard cap (64 MiB engine / 8 MiB AI) on top of the timeout,
    so a hostile target cannot OOM the workbench inside the request deadline.
  - **Transport honesty** (`camio-request`, `camio-web`, `camio-app`): the
    impersonating engine only reports `fingerprint_matched` when its preset
    actually matches the pinned browser build, tool-originated POST/PUT now
    send `Content-Length` with the browser's casing instead of a lowercase
    stack default, and a dry-run fallback announces itself (once at startup,
    on every send response) instead of silently swapping transport.
  - **OAST hardening** (`camio-oast`): correlation tokens come from the OS CSPRNG
    (not a hash of the clock/pid/counter), retention is bounded (10 000 most
    recent interactions), concurrent handlers are capped (64), and the
    poisoned-mutex panics are gone.
  - **Web API** (`camio-web`): `/api/fuzz_run` reports sent/failed/out-of-scope/
    unsaved counts instead of collapsing them into `sent: 0`, `/api/send`
    surfaces persistence failures and transport status, `/api/tasks` lists
    durable task records (read-only), `/api/sitemap` bounds its row limit and
    reads metadata without allocating padded bodies, sequencer tokens must be
    strings, the bearer scheme is case-insensitive per RFC 7235, the Host check
    is case-insensitive, and error responses no longer echo the DB path or raw
    SQL.
  - **MCP** (`camio-mcp`): `subfinder_enum` runs the shared scope/policy gate,
    `active_scan` no longer reports `done` when every probe failed,
    `import_file`/`send_request` surface store failures, argument types are
    validated (a numeric `method` is an error, not a silent `GET`), stdio
    messages are size-bounded, and `tasks_list` was added.
- **Security hardening pass 2** (the remaining findings):
  - **Indexed query planning** (`camio-store`, plan §5): `query_metadata` and
    the new `query_for_scan` push the query's required-metadata conjunct
    (host, method, source, status) into SQL, so a filtered query is answered by
    the `exchanges` indexes (`EXPLAIN QUERY PLAN` → `SEARCH … USING INDEX
    idx_exchanges_host`) instead of walking the table in Rust, with a 100
    000-row scan window as a bound. The Rust-side match still applies, so
    results stay exact (regression-tested for exact counts and non-pushable
    free-text queries).
  - **Bounded web scan** (`camio-web`, `camio-store`): `/api/scan` loads bodies
    under a cumulative 64 MiB byte budget as well as a row cap, reports
    `skipped_oversize` instead of silently dropping them, and loads no padded
    placeholder bodies.

### Changed

- **Automated testing requires explicit targets** (plan §4.3):
  `Scope::has_explicit_targets` + `Policy::gate_action`/`gate_action_with`
  are now the gate on every ACTIVE path (native app, CLI fuzz/activescan/
  scan/crawl/nuclei/probe, web, MCP). An empty or exclude-only scope is no
  longer read as permission to discover, scan, or fuzz; manual one-shot Replay
  sends (confirmed, `Mutating`) still work as before.

### Fixed

- **Full indexed query planning** (`camio-store`, plan §5): every *required*
  conjunct is pushed into SQL (`required_metadata_all`) with indexes on
  host/method/source/status, so a multi-predicate query is narrowed by all of
  them instead of only the first — verified by `EXPLAIN QUERY PLAN` and by exact
  result counts.
- **Crawler origin correctness** (`camio-active`): `same_origin` compares scheme,
  host, *and* effective port, so a page seeded on `https://app.test/` no longer
  silently enqueues `http://app.test/` (a downgrade) or `:8443` (another service).
- **Multipart input discovery** (`camio-automate`): `multipart/form-data` bodies
  are parsed by boundary into `(name, value)` inputs (a file part's position is
  its filename), so upload forms no longer yield zero inputs.
- **HAR status validation** (`camio-import`): only 100–599 is a status; 0 means
  "no response" and anything else is reported instead of stored as if real.
- **`input_echo` bound** (`camio-scan`): bodies over 2 MiB are skipped by the
  signature scan (it runs on the proxy's capture hot path).
- **Content-Length casing** (`camio-request`): tool-originated POST/PUT now emits
  `Content-Length` with the browser's casing rather than letting the HTTP stack
  inject a lowercase one.

- **SSRF guard bypass for cloud metadata** (`camio-core::scope`): lab mode
  (`--allow-private`) previously un-blocked link-local and the cloud-metadata
  address (`169.254.169.254`, `fe80::/10`, `metadata.google.internal`), so a
  "lab profile" silently allowed SSRF to the host's own infrastructure. These
  are now a separate, explicit opt-in (`Scope::allow_metadata` /
  `--allow-metadata`), blocked by default even in lab mode. Regression-tested
  against allowed lab targets, blocked metadata, and unapproved destinations.
- **httpx tool-name confusion**: a non-ProjectDiscovery `httpx` on PATH used
  to make `camio probe` print "no probe results" as if nothing answered; the
  adapter now verifies the binary before running and reports an actionable
  incompatibility (and keeps a bounded stderr snippet when a run yields no
  records).
- **Classifier false positives** (`camio-automate`): a 1-2 character payload
  (`'`/`"` and their hex encodings) no longer marks every response as
  `reflected` — the classifier applies the same minimum-length and
  structural-character guard the passive reflected-input check uses.
- **Campaign payload framing** (`camio-automate`): URL-position payloads are
  percent-encoded (a payload's `#`/`&`/`=` cannot truncate or reshape the
  request the URL re-parser sends), header values cannot inject CRLF, a `§`
  marker on a non-UTF-8 body is reported instead of silently dropped, a payload
  containing the marker char is refused, and a budget-less campaign is
  ceilinged at 100 000 requests.
- **Body preservation** (`camio-automate`): a chain substitution on a request
  with no `${…}` in its body no longer rewrites a binary body through the
  lossy text view (multipart/gzip bodies survive byte-for-byte).
- **Encoding correctness** (`camio-automate`): a URL *path* position keeps `/`
  unencoded (traversal probes are not defeated by `%2F`), null prefixes are
  not offered in URL/form contexts, and two encodings that produce identical
  bytes no longer emit the same request twice.
- **Input discovery** (`camio-automate`): JSON arrays of objects and nested
  scalar objects are discovered with `items.0.id`-style paths, every value of
  a repeated header is reported, `;`-separated legacy form bodies are split,
  JSON *string* slots that look numeric are no longer mis-encoded as numbers,
  and a payload starting with `#` (`#<script>`, `#!`) is no longer dropped as
  a comment.
- **Scanner accuracy** (`camio-scan`): "introspection disabled" errors are no
  longer reported as *enabled* introspection; CORS `null`-origin and
  suffix-reflection misconfigurations are detected; exposed-API-doc paths
  require a successful response (a 404 at `/swagger.json` is normal, not a
  finding); reflected-input findings redact credential-shaped values; the
  sensitive-key set covers `JSESSIONID`/`PHPSESSID`/`sid`/`jwt`/`auth`; and the
  bare `odbc` token requires an error context.
- **Panics on ordinary target data** (`camio-automate::chain`,
  `camio-scan::input_echo`): truncating a 1 MiB+ response body (or a long
  needle) at a raw byte offset now floors to a char boundary.
- **Import scoping** (`camio-import`): Burp XML field scoping is derived from
  a stack of open element names rather than a depth counter (defense in depth
  against a desynchronized invariant), and control characters in headers are
  refused with a reported warning rather than stored for replay.
- **Proxy relays and upgrades** (`camio-proxy`): blind relays and `ws://`
  relays now have a 15-minute idle deadline instead of pinning two threads +
  two sockets forever; Match & Replace request rules apply to a WebSocket
  handshake; and a TLS (`wss://`/`https://`) upgrade is refused honestly
  instead of being rebuilt as a cleartext request to port 80.
- **Active checks** (`camio-active`): the OAST blind-SSRF check waits one settle
  window for the whole run instead of `settle` per probe (N× blocking removed).
- **CLI enforcement** (`camio-cli`): `camio subfinder` and `camio launch --url`
  run the shared scope/policy path, `camio crawl` is gated as an ACTIVE action
  (so it requires explicit targets like the scanner), store failures on
  fuzz/activescan/nuclei are propagated instead of printed as "saved 0", and
  observed URLs/hosts after an httpx or Nuclei run are re-decided so a redirect
  or certificate name cannot quietly widen scope.
- **Storage** (`camio-store`): metadata queries have a no-body variant
  (`query_metadata`) that replaces the zero-filled length-sized placeholder
  bodies (the app site map and the CLI summary path use it), batch writes take
  the write lock up front, labels/saved searches are length-bounded, and task
  records saturate their `u64 → i64` casts with a bounded list limit.

## [0.1.0] — 2026-11-12

First tagged release: a working, local-first web-security workbench with
best-in-class fingerprint transparency.
