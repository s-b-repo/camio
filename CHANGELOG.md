# Changelog

All notable changes to Camio are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project uses semantic
versioning once it reaches 1.0.

## [Unreleased]

### Added

- **External-tool integrations** (`camio-integrations`): the start of the
  integration layer (plan §F16). A **Nuclei** adapter runs ProjectDiscovery's
  template scanner as a *bounded* subprocess — overall timeout with process kill,
  16 MiB stdout cap, update-check and public OOB server disabled — and normalizes
  its JSONL into Camio findings (severity mapped, matched-URL/template/tags in
  the detail; no fabricated exchange evidence). The parser is pure and
  fixture-tested; `camio nuclei <url>` is scope- and policy-gated (active,
  `--confirm`) and can `--save` findings. A missing binary is reported, never a
  crash.
- **Self-hosted OAST collector** (`camio-oast`, `camio oast`): a local-first
  analog of Burp's (paid, cloud) Collaborator. A small HTTP listener mints
  hard-to-guess correlation tokens, records every out-of-band callback (SSRF,
  blind XXE, webhook, DNS-style host exfil), and correlates each hit back to the
  token you planted — path-style (`/<token>`) or DNS-style (`<token>.<base>`).
  Interactions are kept in memory and exposed for live logging / polling;
  `camio oast` logs them, `camio oast --tokens N` prints sample callback URLs.
  Honest scope: it only sees callbacks that can reach the address you bind.
- **OAST-driven blind-SSRF detection** (`camio-active::run_oast_ssrf`): injects a
  correlated OAST callback URL into each discovered input, sends the probe
  through the scope/policy-gated engine, and reports a High/Firm finding when the
  target calls back — catching SSRF that leaves no trace in the response. Wired
  into `camio activescan --oast-listen <addr>` (with `--oast-base` and
  `--oast-settle-ms`), which starts a live collector for the run.
- **Intercepting HTTP/HTTPS proxy** (`camio-proxy`, `camio proxy`): a Burp-style
  proxy a browser points at. Each request is scope-decided and policy-gated
  through the shared `Scope`/`Policy` path (out-of-scope and SSRF-guarded targets
  are refused and recorded as attempts); **Match & Replace** runs in-flight
  (request rules before the send, response rules after, via the new
  `RuleSet::apply_to_response`); and every exchange is captured to the store as
  `source=proxy`. HTTPS is **blind-relayed** by default (the browser's own TLS
  stays end-to-end, fingerprint-true, host-only capture) or **terminated** with
  `--tls-intercept` using Camio's own operator-trusted CA (`--export-ca`,
  persisted with the private key `0600`), after which the decrypted request is
  re-sent through the fingerprint-matched engine and tagged fingerprint-changing.
  A UI-agnostic intercept queue (`QueueInterceptor`) supports pause/edit/drop of
  requests and responses. The upstream send is the injected matched engine, so no
  second HTTP client is added and all destination policy stays in one place. New
  CLI response-side rewrite targets: `resp-header=NAME`, `resp-body`,
  `status-reason`.
  - **Hard to fingerprint:** when intercepting, the upstream request is
    re-originated through the fingerprint-matched engine, so the *target* sees the
    matched JA3/JA4/H2 fingerprint, not a tool tell. The intercepted request is
    now forwarded **verbatim** — new `RequestEngine::send_faithful` skips the
    browser-header synthesis/reordering that tool traffic uses, so a captured
    request's exact header set and order go out unchanged (indistinguishable at
    the header layer from the browser's own). Proxy-generated replies carry no
    identifying header; the intercept CA's name is neutral by default
    (`Internal Root CA`) and operator-settable (`--ca-name`); minted
    certificates use **realistic validity windows** (CA ~10y, leaf ~90d) instead
    of rcgen's telltale 1975→4096 default; and the TLS server advertises
    `http/1.1` via ALPN.
  - **Scope-aware automation:** `--auto-scan` runs the passive scanner on every
    **in-scope** captured exchange and stores its findings as traffic flows;
    out-of-scope traffic is still recorded but never scanned or attacked.
  - **Upstream (chained) proxy:** `--upstream-proxy http://… | socks5://…` routes
    engine-forwarded traffic through another proxy (chain through Burp/ZAP or a
    corporate egress) without changing the fingerprint. New
    `camio_request::matched_engine_with_proxy` /
    `EngineForwarder::spawn_with_proxy`. Blind-relay and WebSocket go direct.
  - **WebSocket:** a plain `ws://` upgrade is scope-gated, recorded as metadata,
    then raw-relayed to the origin so the connection works through the proxy;
    `wss://` is preserved by the default blind-relay, and under `--tls-intercept`
    a WebSocket is refused honestly (501) rather than broken, since relaying it
    would require a second, non-matched TLS client.
  - **Native app:** a new **Proxy** surface starts/stops the proxy on a background
    thread (via the new `ProxyServer::spawn`/`ProxyHandle`), toggles TLS
    interception and auto-scan, exports the CA, shows a live capture table, and
    drives an **interactive intercept** (Burp's Proxy ▸ Intercept): toggle
    Intercept to hold a request, edit its method/URL/headers/body, then Forward or
    Drop. Response interception is gated off by default
    (`QueueInterceptor::set_intercept_responses`) so a request-only UI never hangs.

### Changed

- **Native app layout is now Burp-style.** The left sidebar is replaced by a
  horizontal **top tool-tab bar** (active tab accent-underlined) with full-width
  content, and the tools are reordered/renamed to Burp's names (Dashboard,
  Target, Proxy, Repeater, Intruder, Scanner, Decoder, Extensions, HTTP history,
  …) so the muscle memory carries over.
- **AI assistant** (`camio-ai`): optional, BYO-key, OpenAI-compatible client for
  NVIDIA NIM, OpenAI, or a local Ollama — explain an exchange, suggest next tests,
  or translate natural language to CamioQL. Off by default; the API key is read
  from env and never logged, serialized, or carried in errors. CLI `camio ai`,
  and an "AI assistant" surface in the native app (calls run on a background
  thread so the window stays responsive).
- **Active scanner** (`camio-active`): opt-in reflected-XSS, error-based SQLi and
  open-redirect probes. The checks are pure; the caller injects a scope- and
  policy-gated sender, so active testing stays in-scope, confirmed and bounded.
  CLI `camio activescan`, native-app "Active scan" surface, and a policy-gated
  `active_scan` MCP tool.
- **Automated passive API / JavaScript / web-domain testing** (`camio-scan`):
  seven new passive checks — hard-coded secret leaks (redacted), JS endpoint
  discovery, exposed Swagger/OpenAPI docs, GraphQL introspection, exposed source
  maps, sensitive JSON fields, and sensitive-path exposure — plus a reusable
  `analyze_js` helper and an `analyze_js` MCP tool (17 passive checks total).
- Native UI: a bottom status bar (DB, AI status, active-check state) and the three
  new surfaces above.

## [0.1.0] — 2026-11-12

First tagged release: a working, local-first web-security workbench with
best-in-class fingerprint transparency.

### Added

- **Managed Camoufox engine** (`camio-engine`): pinned build, download/unpack/
  locate/launch — no Node.js/Playwright server.
- **Fingerprint policy** (`camio-core`): Chameleon-inspired anti-detection policy
  rendered to Firefox `about:config` prefs and Camoufox engine config.
- **Matched request engine** (`camio-request`): BoringSSL-based impersonating
  client whose JA3/JA4 · HTTP-2 · header-order fingerprint is derived from and
  pinned to the browser profile. Parity is *measured*, not asserted.
- **CamioQL** (`camio-core`): HTTPQL-compatible query language used everywhere.
- **Storage** (`camio-store`): indexed SQLite history + content-addressed,
  deduplicated body blobs.
- **Scope + policy** (`camio-core`): one scope-decision path with an SSRF guard,
  one shared authorization policy (reads free; sends in-scope + confirmed;
  active/destructive off by default).
- **Convert / Decoder / Comparer** (`camio-convert`): encodings, hashes, JWT
  decode, byte/line diff.
- **Passive scanner** (`camio-scan`): ten checks → deduplicated, ranked findings.
- **Automate / Intruder** (`camio-automate`): insertion points, payload packs,
  four attack types, bounded campaigns, input discovery, result classification.
- **Importers** (`camio-import`): Burp items XML and HAR.
- **Sequencer** (`camio-sequencer`): token entropy/randomness estimate.
- **Site map + Match & Replace** (`camio-core`).
- **Native desktop app** (`camio-app`, egui/eframe): 21 surfaces, seven themes
  (incl. Antigravity, LibreWolf), live theme editor + background image, a
  process-based plugin system, a fingerprint view, and an "Open in browser"
  launcher that applies Camio's fingerprint to a LibreWolf/Camoufox browser with
  the Marionette automation channel enabled.
- **Local web UI** (`camio-web`): the same workbench over a loopback JSON API.
- **MCP server** (`camio-mcp`): 14 tools + resources under the shared policy.
- **CLI** (`camio`): engine, fingerprint, launch, send, query, history, scope,
  convert, compare, scan, fuzz, discover, import, sequencer, sitemap, payloads,
  app, ui, mcp.
- **Supply-chain CI**: `cargo-deny` config + GitHub Actions (`ci.yml`,
  `security.yml`). Upgraded rusqlite, quick-xml and zip to patched versions.

### Security

- Fixed SQLite (RUSTSEC-2026-0459), quick-xml XML-parser DoS
  (RUSTSEC-2026-0194/0195, relevant to Burp-XML import) and zip symlink/SUID
  extraction advisories by upgrading the affected dependencies.

[0.1.0]: https://github.com/s-b-repo/camio/releases/tag/v0.1.0
