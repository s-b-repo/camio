# Camio — Project Plan

**Status:** Proposed (rev. 2)
**Project name:** Camio
**Implementation language:** Rust for the application, request engine, proxy, storage, and orchestration
**Browser engine:** Camoufox (anti-detect Firefox, `daijro/camoufox`, MPL-2.0), managed as a separate native process
**Product goal:** A local-first web security testing workbench that is **faster and easier than Burp Suite, more capable than Caido, free, and fingerprint-transparent** — testing traffic should not be detectable *because of the tool*.

> **What changed in rev. 2 (and why).** Rev. 1 was organized entirely around "Burp Suite feature parity." Parity is a follower strategy that inherits Burp's complexity and leaves Camio permanently behind. This revision keeps the parity matrix as a *coverage checklist* but reorganizes the plan around three things Camio must win on: **fingerprint transparency**, **UX/performance**, and **modern automation primitives** (query language + workflows), all free and local-first. It also (a) adds a competitive analysis of Caido, the actual modern competitor; (b) adds a full UX / information-architecture section; (c) fixes factual errors — the engine is `daijro/camoufox` (MPL-2.0), not `jo-inc/camofox-browser`, which is an unrelated third-party REST wrapper — and standardizes the spelling as **Camoufox**; (d) reframes the "every UI action maps to MCP" contract as capability coverage; and (e) adds migration/import and a sustainability model.

---

## 1. Positioning and differentiation thesis

Camio competes with two tools, and must beat each on its own strongest axis:

- **Burp Suite** — the depth and ecosystem leader. Weaknesses (per user reviews): expensive, heavy/slow (JVM, high memory), steep learning curve, dated interface in places, and **highly fingerprintable** (its proxy TLS/HTTP-2 stack is a known tell for WAFs and anti-bot services).
- **Caido** — the modern UX/performance leader (Rust, native dark mode, fast start, low memory). Strengths: HTTPQL query language, node-based Workflows, Convert, Findings, a JS/TS plugin SDK. Weaknesses: historically weaker automated scanning, a freemium model with gated features (project/workflow/plugin limits), and it still routes through a proxy, so it carries a tool fingerprint.

**Camio's thesis:** *The speed and modern UX of Caido + the depth of Burp + something neither offers: testing traffic that doesn't stand out because of the tool — and all of it free, local-first, and MCP-native.*

The five pillars, in priority order:

1. **Fingerprint transparency** (the headline differentiator). The server should see the real browser, not a proxy. Tool-originated requests are matched to the browser's fingerprint. See §6.
2. **Zero-config onboarding.** Click "New test," the managed browser opens, traffic flows — no manual proxy config, no CA install step the user has to perform, no browser extension. Burp's #1 pain and Caido's residual friction, eliminated.
3. **Performance as a measured product gate.** Cold start, memory ceiling, and a large-history interaction budget are release gates, not aspirations. See §5.
4. **Modern automation primitives.** A unified query language (CamioQL, HTTPQL-compatible) and visual + scriptable Workflows, everywhere — search, filter, intercept, scope, automate.
5. **Free and open, with a credible sustainability model.** No paid edition, no feature locks; funded transparently so the promise survives. See §12.

Everything else (the parity matrix, scanner, extensions) is table stakes delivered in support of these pillars.

## 2. Operating assumptions and limits

- **Authorized use only.** The tool is for assessing systems the operator owns or is permitted to test. Target scope, rate limits, and scan controls are part of first-run and are enforced in the request scheduler below the UI layer.
- **Fingerprint transparency is "don't add a tool tell," not "defeat the target."** The objective is that Camio does not make the tester detectable *because of the tool* — i.e., it does not stamp a proxy's TLS/HTTP-2/header fingerprint onto browser-equivalent traffic, so WAFs and anti-bot services don't block *authorized* testing or return block pages that hide the app's real behavior. Camio does **not** promise undetectability, does not solve CAPTCHAs, does not rotate identities or proxies for evasion, and does not bundle third-party anti-bot bypass. Camoufox's engine-level anti-detect properties belong to the browser and are best-effort and target-dependent; Camio measures and reports fingerprint parity rather than guaranteeing it.
- **Browser-native interception is the default**, precisely because it preserves the browser's real connection fingerprint. The optional MITM proxy (for external clients) is clearly labeled as changing the server-visible connection and TLS fingerprint.
- **Fingerprint profiles are explicit, documented, stable per browser profile, and versioned** to track the pinned Camoufox build. A stale fingerprint is itself a tell; drift is treated as a defect. See §6.
- **"Fewer dependencies"** means a small Rust application/runtime dependency set and no bundled Node.js/Electron runtime. Camoufox/Firefox remains a substantial native browser dependency, managed separately.
- **Upstream source:** obtain and pin a reproducible revision of `daijro/camoufox` (MPL-2.0) and review its license, build, and automation surface during Phase 0. Use it as the browser engine and as a fingerprint reference; port the required control plane to Rust. Do not ship a Node.js/Playwright server. (If network is unavailable in the build environment, record this as a Phase-0 blocker and resolve it before committing integration details.)

## 3. Competitive analysis (what to copy, what to beat)

| Capability | Burp | Caido | Camio target |
|---|---|---|---|
| Traffic capture | Proxy MITM (fingerprintable) | Proxy MITM (fingerprintable) | **Browser-native, fingerprint-transparent** by default; matched request engine for tools |
| Onboarding | Manual proxy + CA install | Proxy config, less friction | **Zero-config**: launch managed browser, done |
| Query/filter | Filters, no unified language | **HTTPQL** (strong) | **CamioQL**, HTTPQL-compatible, used everywhere incl. intercept & scope |
| Automation | Intruder (powerful, dated UX) | **Workflows** (node-based) + Automate | Visual **Workflows** + text/MCP form; Intruder-class fuzzing under one roof |
| Data transforms | Decoder/Comparer | **Convert** | Convert-class, scriptable, reusable in workflows |
| Findings | Scanner issues (mature) | Findings (issue tracking) | Findings + **passive scanner early**; active opt-in |
| Extensibility | BApp Store (huge, Java/Jython) | JS/TS SDK + custom frontend | Rust ABI + JS/TS SDK + UI panels; migration path, not Burp-ABI compat |
| Performance | JVM, heavy | Rust, light | **Measured gates**, aim at/under Caido |
| Price | Paid (Pro/Enterprise) | Freemium (gated) | **Fully free**, no locks |
| Migration | — | — | **Import Burp & Caido projects** and match/replace rules |
| AI/MCP | Add-ons | Plugins | **Built-in MCP**, optional local/BYO-key copilot |

Recheck competitors each release; both move fast. Grounding sources: PortSwigger [desktop tool reference](https://portswigger.net/burp/documentation/desktop/tools); Caido [docs](https://docs.caido.io) and [Burp-vs-Caido reference](https://docs.caido.io/reference/burp_vs_caido); Camoufox [`daijro/camoufox`](https://github.com/daijro/camoufox).

## 4. Product definition

Camio is a Rust desktop security-testing application built around the managed Camoufox browser. It provides fingerprint-transparent traffic capture, manual testing tools, scoped automated testing, project/profile storage, findings and reports, a built-in MCP server, and a permissioned extension system. "Burp parity" is a multi-release coverage goal tracked in a versioned matrix (§8), not a first-release claim and not the organizing principle. Port equivalent *workflows and documented behavior*; never copy Burp code, branding, or proprietary internals.

## 5. Performance as a product gate

Performance is Rust's main advantage over Burp and must be defended with numbers, measured on a defined reference machine and enforced in CI:

- **Cold start** to interactive, managed browser launched: target budget set in Phase 1 and regression-gated thereafter.
- **Memory ceiling** under a standard session; flagged if exceeded.
- **History scale:** keep the request log responsive (scroll, search, CamioQL filter) at 1,000,000+ exchanges, via an indexed embedded store and content-addressed bodies — not all in RAM.
- **Interaction latency:** query/filter and open-exchange actions under an interactive threshold on the reference history size.
- **Idle cost:** low CPU/memory when not actively testing.

Publish the reference machine and the budgets; treat a regression as a release blocker.

## 6. Fingerprint transparency (core differentiator)

The goal: traffic Camio produces is indistinguishable from the same browser used normally, so authorized testing is not blocked or distorted by WAF/anti-bot detection of the *tool*.

### 6.1 Surfaces Camio must neutralize

1. **TLS ClientHello (JA3/JA4):** cipher suites, extensions, curves, and their order. A proxy's stack differs from the browser's — the primary Burp tell.
2. **HTTP/2 fingerprint (Akamai-style):** SETTINGS frame values and order, WINDOW_UPDATE, header-priority tree, and pseudo-header order (`:method :authority :scheme :path`).
3. **Header order and casing:** real browsers send a stable, characteristic order; proxies canonicalize. Camio preserves exact order and casing on the wire and never alphabetizes/normalizes outbound.
4. **Automation tells at the browser layer:** `navigator.webdriver`, CDP/BiDi detectability, canvas/WebGL/audio, fonts, UA-CH, timezone/locale. Camoufox handles most at the engine level; Camio must verify its control channel (BiDi/Gecko) does not re-introduce them.
5. **Behavioral/timing:** burst cadence from fuzzing. Camio offers pacing and jitter, and is honest that timing can still reveal automation.
6. **The MITM tell itself:** terminating TLS swaps the server-visible connection to the proxy's fingerprint. Avoided for the managed browser by design.

### 6.2 Two traffic paths

- **Organic browser traffic** (browsing, app-driven `fetch`/XHR): captured via browser-native interception. The browser makes the real connection, so JA3/JA4/H2 are genuinely the browser's. This is why browser-native, not MITM, is the default.
- **Tool-originated traffic** (Repeater, Intruder/fuzzing, Scanner, crawler): must not revert to a stock Rust TLS stack (`rustls`/`hyper` have their own flaggable JA3). Two modes:
  - **Matched request engine (default):** a BoringSSL-based HTTP client (e.g. the `rquest` crate / curl-impersonate approach) whose JA3/JA4 and HTTP/2 profile are **derived from and pinned to the exact Camoufox build in use**, so browser and tool traffic share one fingerprint. Supports raw bytes, arbitrary methods, malformed requests (smuggling tests), and full response capture.
  - **Replay-through-browser (optional):** send via the browser for maximum fidelity on organic-shaped, in-scope requests; limited by browser-forbidden methods/headers and CORS visibility. Offered where perfect fidelity matters more than raw control.

### 6.3 Fingerprint profile management

- A **FingerprintProfile** object is pinned to a Camoufox build and version, stored with the browser profile, and used by both the browser and the matched request engine so they cannot drift apart.
- **Measure, don't assert:** a built-in parity check runs the browser and the matched engine against controlled JA3/JA4/HTTP-2 reflection endpoints (self-hosted for CI) and reports any divergence between browser, engine, and a target real-browser baseline. Divergence is a defect.
- **Version with the browser:** when the pinned Camoufox build updates, regenerate and re-verify the profile. Surface the profile's age and a warning when it lags the impersonated browser's real release (stale = detectable).
- **No false promises in UI:** the fingerprint panel shows measured parity and known limitations, never a "you are invisible" claim.

### 6.4 Honesty and scope guardrails

Keep the authorized-use framing from §2. Fingerprint transparency is a property Camio *measures and preserves*, aimed at not corrupting authorized test results with tool detection — not a capability to defeat a specific target's defenses, and not marketed as such.

## 7. UX / UI design and information architecture

This is the section rev. 1 was missing. Camio's interface is a product pillar, not a skin over Burp's 15 tabs.

### 7.1 Design principles

- **Zero-config first run.** Launch → "New project / New test" → managed browser opens with capture already live. No proxy settings, no CA dialog, no extension install presented to the user. First meaningful capture within seconds.
- **Keyboard-first, command-palette-driven.** Every action reachable via a command palette (fuzzy search) and a documented shortcut. Target: any core action in ≤2 keystrokes. Mouse is never required.
- **One query language everywhere (CamioQL).** The same syntax filters history, scopes targets, drives intercept rules, and seeds workflows. HTTPQL-compatible so Caido users are instantly productive. A single query bar is a persistent, global surface.
- **Progressive disclosure.** Simple by default; power on demand. Raw/structured message views, advanced scan config, and fingerprint internals are available but not in the beginner's face.
- **Native light/dark + themes, WCAG 2.1 AA.** Real dark mode (table stakes now), high-contrast option, colorblind-safe status palettes, resizable/dockable panes, and a density toggle (comfortable/compact) for high-volume testers.
- **Consistency.** One message editor, one table component, one filter language, one context-menu grammar ("Send to…") across every surface.

### 7.2 Information architecture — consolidate Burp's tabs into a few verbs

Instead of mirroring Burp's tool list, organize around what the tester *does*. A left rail of primary surfaces; each owns a request/response editor and the shared query bar:

- **Capture** — live traffic + history + intercept (Proxy + HTTP history + Logger, unified). CamioQL filter, intercept queue with resume-all/stop, Match & Replace rules.
- **Replay** — Repeater-class: tabs, history, diff between sends, redirect/connection control, matched-engine or browser send.
- **Automate** — Intruder-class fuzzing *and* visual Workflows in one place: payload positions, payload packs, attack modes, result filters; node-based workflows that compile to a text/MCP form.
- **Discover** — Target/site map tree, scope editor (CamioQL-backed), API/schema import, crawl controls.
- **Scan** — passive findings early, opt-in active checks; Findings tracker with Markdown notes, severity/confidence, dedup, evidence, export.
- **Collaborate/OAST** — self-hosted interaction collection.
- **Library** — payload packs, browser profiles, saved items/Organizer, extensions, fingerprint profiles.

A persistent **Fingerprint status** indicator (parity measured / profile age / MITM-active warning) lives in the status bar so the tester always knows how they appear on the wire.

### 7.3 Key interactions to get right

- **Command palette** (global): run any action, jump to any surface, execute a saved CamioQL query or workflow.
- **The query bar**: autocomplete on fields, inline validation, saved queries, and "turn this filter into an intercept/scope/workflow" one-click.
- **Message editor**: raw and structured views (headers, params, cookies, JSON, forms, multipart, GraphQL, WebSocket), safe round-tripping, inline encode/decode (Convert-class), and byte-level diff (Comparer-class) built in.
- **Send to…**: consistent context action from any table/editor to Replay, Automate, Scan, Discover, Organizer, or a Workflow.
- **Empty/onboarding states** that teach the next action rather than showing a blank tool.

### 7.4 Migration and adoption

- **Importers** for Burp project/state files, Burp Match & Replace rules, and Caido projects/workflows where format allows — the biggest lever against switching cost.
- **Caido/HTTPQL compatibility** for the query language so existing muscle memory transfers.
- Validate UX with task-completion time and scope-selection error rate against Burp/Caido on the same tasks; publish results.

## 8. Capability coverage matrix (parity as a checklist, not the spine)

Every row needs a requirements page, acceptance criteria, and a status (`not started`, `in progress`, `equivalent`, `partial`, `excluded with rationale`), with edition labels so coverage doesn't hide Community/Pro/DAST differences.

| Area | Planned capability |
|---|---|
| Dashboard & project | Overview, live tasks, findings, scan status, saved project/user settings, workspace/layout management. |
| Target/Discover | Scope rules (CamioQL), site map, discovered URLs, annotations, in-scope filtering, Send-to actions, schema import. |
| Browser | Managed Camoufox launch, named isolated profiles (cookies/storage/IndexedDB), downloads, screenshots, lifecycle, and browser-native request/response inspect/edit/pause/continue/drop/replay. No user-performed CA step. |
| Browser traffic capture | Capture HTTP(S) at the browser layer; pause before send / before delivery, edit supported fields/body, edit/replace responses, continue/drop/replay. Preserve the browser's real TLS connection and fingerprint. Record protocol limits explicitly. |
| Fingerprint transparency | Matched request engine for tool traffic, pinned per Camoufox build; measured JA3/JA4/H2 parity; versioned fingerprint profiles; status indicator. (§6) |
| Optional external proxy | Opt-in MITM for external clients/devices: interception, editing, rules, history, upstream proxy, TLS lifecycle, WebSocket, HTTP/2 where feasible. Clearly labeled as fingerprint-changing. Not used by the managed browser. |
| Message editor & Inspector | Raw + structured views; headers, params, cookies, JSON, forms, multipart, WebSocket, GraphQL, encodings; editable, safe round-trip. |
| Replay (Repeater) | Send/edit/resend, response diff, tabs/history, redirect/connection control, Send-from-other-tools, matched-engine or browser send. |
| Automate (Intruder + Workflows) | Payload positions/sources/attack modes, throttling, concurrency, stop/resume, results table/filters, response diff; node-based visual workflows with text/MCP form. Explicit scope + per-task budget. |
| Input/API campaigns | Discover inputs from traffic, forms, uploads, JSON/XML/multipart, URL path/query, headers, cookies, WebSocket, GraphQL, imported OpenAPI/GraphQL. Method matrix GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS/TRACE/CONNECT + approved custom tokens. `fetch()` is a request initiator, not an HTTP method. |
| Scan & crawl | Passive checks first; opt-in scoped active checks; scan configs, evidence, severity/confidence, dedup, exclusions, login/session handling, rate limits, exportable reports. |
| Sequencer | Sample capture + documented randomness analysis, sample limits, reproducible reports. |
| Collaborator/OAST | Unique identifiers, DNS/HTTP(S) interaction collection via self-hosted/explicit service. Nothing sent to third parties by default. |
| Convert / Decoder / Comparer | Encode/decode/hash transforms and byte-level comparison, reusable inside workflows. |
| Logger & Search | Unified log, CamioQL search over fields/bodies, filter presets, saved searches, links back to origin task. |
| Organizer | Save requests/responses with notes, labels, project references. |
| DOM Invader | Browser-assisted DOM/client-side inspection, source-to-sink, reproducible evidence. |
| Clickbandit | Operator-built clickjacking proof against an authorized page; safe local artifact + cleanup. |
| Infiltrator | Optional, visible instrumentation for unsafe API flows; off by default; discloses page-behavior changes. |
| Engagement tools | Scope, notes, issue tracking, target lists, evidence, exports. |
| Extensions | Permissioned Rust ABI + JS/TS SDK for UI panels, passive checks, transforms, tool actions. Migration path, not Burp-ABI compatibility. |
| MCP | Built-in local MCP covering Camio's capabilities and data (§11). Same authorization/scope/rate/approval checks as UI. |
| Automation & AI | Optional local or BYO-key assistant for summarizing project data and proposing actions, gated by the same policy engine. No external model/telemetry by default. |
| DAST/team/CI | Later track: headless scan API, scheduled scans, CI integration, team access control, centralized reports. |

Grounding: PortSwigger [tool reference](https://portswigger.net/burp/documentation/desktop/tools), [extensions](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions), [Collaborator](https://portswigger.net/burp/documentation/collaborator), [scope settings](https://portswigger.net/burp/documentation/desktop/settings/key-settings); recheck each release.

## 9. Browser-native request editing and pause

The managed-browser workflow controls traffic inside the browser, before TLS is sent and after it is received — preserving the browser's real connection and fingerprint. The operator can inspect/pause/edit method/URL/headers/body and continue; pause/inspect/edit/replace a response and deliver it; plus drop, resume, duplicate-to-Replay, and replay. A visible queue shows timestamps, timeout policy, and one-click resume-all/stop.

- **Prototype WebDriver BiDi network interception** on the pinned Camoufox build first (request/response interception + continuation/replacement per the [W3C draft](https://w3c.github.io/webdriver-bidi/#module-network)); measure actual Gecko support and edge cases, and **verify it introduces no automation tells** (`navigator.webdriver`, CDP/BiDi detectability).
- Validate body edits, compression, redirects, cache, service workers, WebSockets, HTTP/2, downloads, and auth in the feasibility phase. Store the browser-observed message and protocol metadata, clearly distinguished from raw socket bytes.
- If a required capability is unavailable without TLS termination, contribute it upstream or use a supported Gecko adapter — **do not silently switch the managed browser to MITM**, because that destroys the fingerprint-transparency property. Reserve raw-socket inspection for the optional external-client proxy, clearly labeled.

## 10. Payload catalog and automated input testing

### Payload source and provenance
- Payload-pack manager imports from local files and selected public GitHub repos. Candidate sources: [SecLists (MIT)](https://github.com/danielmiessler/SecLists), [PayloadsAllTheThings (MIT)](https://github.com/swisskyrepo/PayloadsAllTheThings), subject to per-repo/per-file license review and attribution.
- No "bundle all of GitHub." Pin each pack to a commit; record paths, hashes, license, attribution, import date, maintainer. Never update or execute downloaded content silently.
- Categorize by protocol, input context, content type, purpose, expected signal, impact (passive/low-impact/active/destructive). Default to safe checks; active/destructive require explicit enablement and lower rate/budget limits.
- Users can add/edit/filter/dedup/encode/version their own wordlists; preview packs with license/provenance manifests before import.
- Treat imported repos as untrusted data: import text payloads only by default, never run repo scripts/binaries, sandbox extraction, reject path traversal/symlinks, enforce file-count/size limits.
- Credential guessing, DoS, destructive uploads, and other high-impact categories stay disabled unless explicitly enabled for a specific authorized target.

### Automatic input discovery and test matrix
- Build campaigns from scope + observed traffic. Discover inputs in query strings, path segments, headers, cookies, URL-encoded/multipart forms, HTML controls, uploads, JSON/XML, GraphQL variables, WebSocket messages, browser `fetch()`/XHR, and imported OpenAPI/GraphQL.
- Run the configured method matrix per endpoint/input (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS/TRACE/CONNECT + approved custom tokens). `fetch()` is a request initiator, not a verb. Methods the browser forbids use the matched request engine and are reported as such. CONNECT/tunnel methods require separate target-specific opt-in and never turn Camio into an open proxy.
- One bounded test at a time per endpoint/input/method by default. Keep a baseline; correlate each result with input position, method, payload, profile, and scope; dedup equivalents. Wider combinations only after showing projected request count and getting approval.
- Respect per-project/per-host budgets, concurrency caps, delays, response-size limits, stop controls, in-scope-only redirects, and an auditable record of all traffic. Destructive tests require explicit target-specific opt-in.

### Results and filters
Store each exchange with campaign/payload metadata. Provide CamioQL-filterable "success hits," "error hits," and "interesting differences" using status-code groups, baseline status changes, body terms/regex (positive/negative), headers, content type, length, response-time delta, redirects, network errors/timeouts, payload reflections, and OAST interactions. Defaults are configurable (a `200` is not automatically "success"). Sort, save filters, export CSV/JSON, Send-to-Replay/Comparer/Organizer. Mirrors documented [Intruder results](https://portswigger.net/burp/documentation/desktop/tools/intruder/results/viewing-results) and [filters](https://portswigger.net/burp/documentation/desktop/tools/intruder/results/filtering-results).

## 11. Profiles and MCP coverage

### Saved browser profiles
- Create, name, duplicate, select, export, import, archive, delete. Persist across restarts; attachable to a project. Each carries its pinned Camoufox build, schema version, and **FingerprintProfile**.
- Save cookies, local storage, IndexedDB where supported, permissions, extensions, settings, locale/timezone/viewport, and network/fingerprint settings.
- Autosave on shutdown and at checkpoints; show last-saved time; named snapshots/restore points. Strict isolation: one profile cannot read another's cookies/storage.
- Protect session data with per-user filesystem permissions and a reviewed at-rest encryption design. Encrypt exported profiles; require explicit action to export cookies/auth state. Never put secrets in logs or default MCP results.
- Detect incompatible profiles on Camoufox update and offer a backed-up migration path.

### MCP coverage contract (reframed)
MCP exposes Camio's **capabilities and data**, not a 1:1 mirror of every UI toggle (rev. 1's "every UI action" rule was a per-feature tax). Concretely:
- **Read-only resources:** projects, profiles, history, sitemap, tasks, findings, saved items, fingerprint status.
- **Tools:** browse/control the browser, inspect/edit/pause traffic, save/restore profiles, send/replay (matched engine or browser), run scoped scans/campaigns, manage findings, run CamioQL queries and workflows, export reports.
- **Policy parity:** MCP uses the same policy engine as the UI. Mutating/active actions report preview, scope decision, request budget, and confirmation requirement before executing. Long tasks return IDs with status/cancel/results.
- **Local by default:** stdio mode works without accounts/keys/hosted services; any network transport is loopback-only and authenticated.
- Maintain a checklist mapping each capability (not each pixel) to its MCP surface, recording anything intentionally UI-only. No capability is paywalled or UI-only by accident.

## 12. Free feature policy and sustainability

- **No paid edition, subscription, feature lock, license key, or paywall.** All implemented capabilities — including Pro/DAST-equivalent items — are free to everyone. MCP is included and needs no hosted service.
- **Open source:** publish application source and build instructions. Choose the license after reviewing Camoufox (MPL-2.0) and dependency licenses; don't imply third-party components adopt Camio's license.
- **Sustainability model (new):** a free promise that outlives enthusiasm needs funding and governance. Options to decide before 1.0 and state publicly: donations/sponsorship (GitHub Sponsors/OpenCollective), optional *hosted conveniences* that never gate core features (e.g. a managed OAST endpoint), paid support/training, and a documented maintainership/governance model. Record which path is chosen and keep all testing capabilities free regardless.
- Optional third-party services (hosted OAST, proxy providers, remote AI) may charge their own fees; keep them off by default with local/self-hosted alternatives, never prerequisites. A free promise doesn't waive third-party license terms.

## 13. Architecture

Local-first, small auditable components:

1. **Rust desktop shell** — project/workspace UI, command palette, CamioQL bar, settings, task control, local API. No Electron / bundled JS runtime. Pick the Rust-native UI framework after a packaging + accessibility spike (dark mode, theming, dockable panes, density modes are requirements).
2. **Engine supervisor** — launch/monitor/update/shutdown the separately installed Camoufox binary; own persistent profiles, process isolation, crash recovery, control-channel config.
3. **Browser network adapter** — drives browser-native interception (WebDriver BiDi or verified Gecko interface); pause/edit/resume/cancel/record without MITM; preserves the browser's real fingerprint.
4. **Fingerprint-matched request engine (new, core)** — BoringSSL-based HTTP client for all tool-originated traffic, JA3/JA4/HTTP-2/header profile pinned to the active Camoufox build; supports raw bytes, arbitrary/malformed requests; shares the profile's `FingerprintProfile` with the browser.
5. **Optional Rust MITM proxy** — CONNECT handling, local CA lifecycle, protocol adaptation, WebSocket, event stream — for *external clients only*, disabled by default, with a prominent fingerprint-changing indicator.
6. **Core event and task model** — typed event stream connecting adapter, request engine, optional proxy, scanner, Replay, Automate, MCP, UI. Each event carries project/profile/task/scope/origin metadata.
7. **Storage** — SQLite (or equivalent embedded store) for metadata and indexes; content-addressed blobs for large bodies/artifacts; sized to the §5 history budget. OS file permissions + reviewed encryption for profiles/secrets; encrypted exports; redacted logs; deletion controls.
8. **Testing engines** — separate workers for crawl, passive analysis, active checks, fuzzing, OAST polling; all consume one scope/rate-limit policy service; all instantly stoppable; all send via the matched engine.
9. **MCP server** — local endpoint in the Rust app; stdio preferred; loopback + auth if networked.
10. **Extension host** — versioned ABI with capabilities, resource limits, permission prompts; Rust plugins in-process if isolation is adequate, else a small local RPC boundary; JS/TS SDK for UI/logic plugins.

### Core data objects
- `Project`, `Target`, `ScopeRule`, `BrowserProfile`, `ProfileSnapshot`, `FingerprintProfile`, `ProxyListener`
- `HttpExchange` (request, response, timings, protocol, source, scope result, **fingerprint-used**)
- `PayloadPack`, `PayloadEntry`, `InputPosition`, `TestCampaign`
- `Task`, `Finding`, `Annotation`, `SavedItem`, `Workflow`, `Extension`, `McpCapability`, `AuditEvent`

Preserve raw bytes and normalized structured representations separately; never silently rewrite stored evidence.

## 14. Rust and dependency policy

- Build app, request engine, proxy, scheduler, storage, scanner framework, and CLI in Rust.
- Minimize duplication: one async runtime, one embedded DB, one GUI framework. The matched request engine's BoringSSL/impersonation stack is a deliberate, documented exception (a stock TLS stack would defeat fingerprint transparency) — pin and justify it.
- Pin dependencies, generate an SBOM, audit licenses/advisories, record why each nontrivial dependency exists.
- Keep the browser engine and optional data packs outside the Rust dependency count; make optional features installable separately.
- No auto-update, telemetry, external OAST, or AI connection without explicit operator configuration. Core manual workflow runs fully offline.

## 15. Delivery phases (reordered to prove the differentiators early)

### Phase 0 — Feasibility, threat model, and the fingerprint spike (2–3 weeks)
- Obtain/pin `daijro/camoufox` (MPL-2.0); record commit, license, build, platforms, automation surface.
- **Fingerprint spike (gating):** stand up JA3/JA4/HTTP-2 reflection endpoints; measure (a) the real browser, (b) the browser under BiDi control (check for automation tells), and (c) the matched request engine (`rquest`/BoringSSL) configured from the browser's profile. Exit requires browser and engine fingerprints matching a real-browser baseline within defined tolerance.
- Prototype browser-native request/response pause/edit/continue/replace incl. body edits; verify no MITM/CA needed and no `navigator.webdriver` tell.
- Draft the capability-coverage matrix with edition labels; define payload manifest/provenance format; set performance budgets (§5); establish an opt-in feedback channel.
- **Exit:** working browser-native control *and* measured fingerprint parity between browser and tool engine, documented unsupported cases, platform list, dependency budget. If fingerprint parity fails, resolve before building — do not fall back to MITM-as-default.

### Phase 1 — Rust foundation, zero-config MVP, fingerprint transparency (4–6 weeks)
- Workspace/crates, CLI, desktop shell, command palette, CamioQL bar, config, structured logging, crash-safe supervision, dark mode.
- Zero-config launch of Camoufox with isolated persistent profiles; save/restore/duplicate/import/export/delete; `FingerprintProfile` pinned per profile.
- Browser-network adapter: scope rules (CamioQL), capture + history, pause/edit/resume/drop/replay, timeout/release controls.
- Matched request engine wired into a basic Replay surface; fingerprint status indicator; parity self-check command.
- Optional MITM proxy present but off, labeled.
- First MCP resources/tools alongside each capability.
- **Exit:** operator browses an authorized lab target with zero setup, edits browser traffic without MITM/CA, replays via the matched engine with measured fingerprint parity, resumes profiles after restart, and uses the same controls from desktop and MCP.

### Phase 2 — Manual testing workflow + modern UX (5–7 weeks)
- Discover (Target/site map, scope), unified Capture (history+intercept+Match&Replace), Replay, Convert (encode/decode), Comparer, Organizer, Logger, CamioQL search, keyboard model, Send-to grammar.
- WebSocket inspection, body/large-message handling, history persistence at the §5 scale, secret redaction.
- **Importers** for Burp/Caido projects and Match & Replace rules.
- Usability testing vs Burp/Caido on identical tasks; publish task-time and error-rate results.
- **Exit:** a tester completes a full manual discover→replay workflow through desktop or MCP, faster than Burp on measured tasks, state saved to profile/project.

### Phase 3 — Scope-aware discovery, fuzzing, and Workflows (5–8 weeks)
- Crawl controls, request queues, cancellation, rate limits, allow/deny scope, scope-decision audit log.
- Automate surface: payload positions/sources/attack modes, throttling, reproducible tasks, result filters (CamioQL) — all via the matched engine.
- Visual **Workflows** (node-based) with a text/MCP form; Convert steps reusable inside them.
- Payload-pack manager + automatic input discovery (traffic, forms, schemas, JSON/XML/multipart, GraphQL, fetch/XHR); bounded per-input campaigns across the method matrix with pre-launch request counts, tunnel-method gates, destructive opt-in.
- Sequencer sample capture/analysis.
- **Exit:** all automated requests are visible, bounded, scoped, stoppable, fingerprint-matched, and resumable without losing task state.

### Phase 4 — Scanner, findings, and OAST (8–12 weeks)
- Passive checks first, then opt-in active checks with per-check limits, evidence, dedup, severity/confidence, report export. This is where Camio can out-reach Caido.
- Login/session workflows and custom scan configs.
- Self-hosted OAST integration + safe local test service; external services opt-in.
- **Exit:** controlled lab targets yield reproducible findings with request/response evidence and zero out-of-scope requests.

### Phase 5 — Browser-assisted and extensibility features (6–10 weeks)
- DOM Invader, Clickbandit, Infiltrator equivalents as optional, inspectable instrumentation.
- Extension API (Rust ABI + JS/TS SDK), permissions, examples, management UI, docs; complete MCP capability coverage.
- API/schema import/testing, HTTP/2 behavior, remaining protocol coverage per the matrix.
- Feedback-backlog review before each milestone; publish what changed.
- **Exit:** documented workflows cover selected browser/extension features; plugins cannot bypass scope/task limits or the fingerprint engine.

### Phase 6 — Professional/DAST parity and deployment (ongoing)
- Scan scheduling, headless API, CI integrations, report templates, team/project access controls, centralized management, optional AI workflows, remaining edition-specific features.
- Review the matrix every release; publish `equivalent`/`partial`/`not supported`.
- **Exit:** each feature in the agreed versioned baseline is implemented to acceptance or has a documented exclusion rationale.

## 16. Security, privacy, and reliability requirements

- Bind management/MCP endpoints to loopback by default; require auth + explicit config for remote access.
- Treat imported cookies, client certs, request bodies, and profiles as secrets. Use OS key storage where available; redact exports/logs; support secure project deletion.
- Require confirmation for active scans, high-volume fuzzing, destructive checks, and external callbacks. Enforce scope and rate limits below the UI so plugins cannot bypass them — including the fingerprint engine (a plugin cannot send off-profile traffic).
- Protect against SSRF in scanner/import/plugin features; reject loopback, link-local, metadata, and out-of-scope destinations unless explicitly allowed in a lab profile.
- Sign updates/extensions, verify integrity, isolate untrusted extensions, provide offline mode.
- Make every automated action attributable: task ID, operator, target, scope decision, request count, rate, fingerprint profile used, stop reason.
- **Fingerprint claims are measured, not marketed.** Report observed JA3/JA4/H2 parity and limitations against controlled endpoints; never claim invisibility; warn on stale profiles.
- One canonical parser and scope-decision path per request so UI, MCP, proxy rules, matched engine, and browser cannot disagree about destination or message. Test request smuggling, parser differential, malformed headers, redirect-scope, DNS rebinding, SSRF.
- Protect the local API/MCP against unauthorized access, CSRF/cross-origin, confused-deputy, path traversal, unsafe deserialization, privilege escalation, secret leakage, resource exhaustion.
- Verify profile paths cannot escape the profile root, project/profile boundaries hold, exports are encrypted, stale copies are removed on delete.
- Require dependency/advisory review, signed artifacts, independent security review before stable release, and a published disclosure/patch process. Objective: no known unmitigated critical/high at release; no guarantee of zero defects or of never overlapping a Burp/Caido flaw.

## 17. Quality plan

- Protocol fixtures: HTTP/1.1, HTTP/2, WebSockets, TLS errors, compression, redirects, large bodies.
- **Fingerprint regression suite:** JA3/JA4/HTTP-2/header-order parity between browser and matched engine against a real-browser baseline, run in CI; drift fails the build; stale-profile detection.
- Controlled local apps with known vulns and benign rate-limit endpoints.
- Payload import/provenance/license checks; isolated campaign tests per input type and method (incl. `fetch()` traffic and controlled TRACE).
- Campaign safety: scope, projected counts, per-host limits, cancellation, destructive gates, success/error/difference classification accuracy.
- Browser-native interception checks: paused req/resp, body edits, response replacement, redirects, cache, service workers, auth, protocol versions — all without a CA; verify no automation tells.
- Proxy round-trip: raw evidence survives edit/replay (external-client mode).
- Profile save/restore: cookies, local storage, IndexedDB, crashes, migrations, isolation, encrypted exports, deletion.
- MCP-to-capability parity: mapped actions, authorization/confirmation, cancellation, rate/scope enforcement.
- Scope tests: excluded hosts never receive crawler/scanner/fuzzing traffic.
- Performance gates (§5) and cross-OS/arch regression.
- Storage recovery, migration, redaction, export/import, crash recovery.
- Extension permission/isolation tests; fuzz parsers and import boundaries.
- Manual parity reviews against the versioned matrix; security regression checks from public advisories.

## 18. Main risks and decisions

| Risk | Response |
|---|---|
| **Fingerprint parity fails** (browser ≠ matched engine, or profile drifts) | Gate it in Phase 0; CI regression suite; version profiles with the Camoufox build; warn on stale; never market invisibility. |
| **BiDi/CDP control introduces automation tells** | Verify `navigator.webdriver` and detectability during the spike; prefer a Gecko path that stays clean; upstream fixes if needed. |
| Camoufox may not expose every pause/edit capability via a stable protocol | Prototype before committing; upstream support rather than defaulting to MITM. |
| Browser-native data lacks exact raw socket bytes | Label browser-observed vs raw; reserve raw inspection for the optional external-client proxy. |
| Matched-engine impersonation stack adds maintenance/dependency weight | Pin and justify BoringSSL/`rquest`; track per browser release; it's core, not optional. |
| Camoufox is a large native engine | Manage independently; optimize the Rust app; explicit engine install/update. |
| Profiles contain auth secrets | Per-profile isolation, restrictive permissions, encrypted exports, reviewed at-rest design, explicit secret export. |
| "Free" confused with paid third-party infra | All Camio features free; identify optional provider charges; offer self-hosted; publish the sustainability model. |
| MCP exposes powerful operations to an agent | Shared policy engine, scoped tasks, audit, explicit approval for high-impact actions. |
| Rust doesn't prevent logic/protocol/config flaws | Parser hardening, threat modeling, fuzzing, review, advisories, independent review, patch process. |
| "Every feature" is open-ended and edition-specific | Freeze a versioned baseline + edition map before each parity release. |
| Scanner/fuzzing can cause damage | Scope enforcement, conservative defaults, per-task budgets, cancellation, operator approval. |
| Burp extension compatibility could dominate | Ship a stable native API + JS/TS SDK + importers first; third-party Burp-extension compat is a separate, partial project. |
| Platform-specific browser/UI behavior | Establish supported platforms in the Phase-0 spike; per-platform release gates. |

## 19. Definition of done

Camio may claim a given parity level only when: the versioned matrix has a verified disposition for every in-scope feature and the workflows pass acceptance; all implemented features are free; MCP covers the documented capability surface; **managed-browser and tool traffic achieve measured fingerprint parity with a real browser (the differentiator Burp lacks)**; managed-browser edits work with no MITM/CA; saved profiles persist safely; scope and rate limits are enforced below the UI; performance gates pass; and users can reproduce findings from saved evidence. Until then, describe it as an early Rust workbench with best-in-class fingerprint transparency, not a complete Burp replacement.

## 20. Project checklist

### Positioning, name, access
- [ ] Use **Camio** everywhere; standardize the engine name as **Camoufox** (`daijro/camoufox`, MPL-2.0).
- [ ] Maintain the versioned capability-coverage matrix with Community/Pro/DAST labels.
- [ ] Keep every feature free; publish source/build instructions; document optional third-party costs; publish the sustainability/governance model.
- [ ] Implement one shared authorization/scope/rate/confirmation/audit policy for UI, MCP, plugins, automation, and the request engine.
- [ ] Collect voluntary feedback across experience levels/editions/platforms/accessibility needs; publish triage.

### Fingerprint transparency
- [ ] Stand up JA3/JA4/HTTP-2 reflection endpoints and a CI parity suite.
- [ ] Ship the matched request engine (BoringSSL-based) pinned per Camoufox build; share one `FingerprintProfile` with the browser.
- [ ] Verify browser-native control adds no automation tells; preserve header order/casing on the wire.
- [ ] Surface a fingerprint status indicator; warn on stale profiles; never claim invisibility.

### UX / UI
- [ ] Zero-config first run: launch managed browser with live capture, no proxy/CA/extension step for the user.
- [ ] Command palette + documented keyboard model (any core action ≤2 keystrokes).
- [ ] CamioQL (HTTPQL-compatible) unifying search, filter, intercept, scope, workflows.
- [ ] Consolidated IA (Capture/Replay/Automate/Discover/Scan/OAST/Library); one message editor, one table, one Send-to grammar.
- [ ] Native dark mode, themes, WCAG 2.1 AA, density modes, dockable panes.
- [ ] Importers for Burp and Caido projects + Match & Replace rules.
- [ ] Validate UX vs Burp/Caido with task-time and error-rate; publish.

### Browser, traffic, profiles
- [ ] Launch/supervise Camoufox from Rust without a Node.js server.
- [ ] Browser-native pause/edit/continue/drop/replay for requests and responses with no MITM/CA; document unsupported cases.
- [ ] Keep external-client MITM proxy optional, separate, visibly marked as fingerprint-changing.
- [ ] Named, isolated, persistent profiles with save/restore/duplicate/import/export/migrate/archive/delete; encrypted exports; no secret leakage to logs/MCP.
- [ ] Deliver the capability matrix surfaces per the versioned plan.

### Payloads and campaigns
- [ ] Pinned, reviewed payload-pack manifests; record source/commit/path/hash/license/attribution/category/maintainer/date.
- [ ] Approved SecLists/PayloadsAllTheThings after license review; user-managed packs; no bulk GitHub scraping.
- [ ] Treat imports as untrusted: no script/binary execution; safe extraction with path/size limits.
- [ ] Discover inputs across forms/uploads/URLs/headers/cookies/WebSocket/JSON/XML/multipart/GraphQL/schemas/fetch-XHR.
- [ ] Method matrix incl. gated tunnel methods; show projected volume; enforce budgets/delays/concurrency/scope/cancellation/destructive gates.
- [ ] CamioQL result filtering by success/error/baseline/status/terms/length/time/redirects/reflection/OAST.

### MCP
- [ ] Local MCP server bundled free; stdio works without accounts/keys.
- [ ] Map every capability (and its data) to an MCP resource/prompt/tool; record anything intentionally UI-only.
- [ ] Same scope/rate/permissions/confirmations/audit/cancellation as the UI; loopback + auth for any network transport.

### Security and release quality
- [ ] Threat model + public-advisory review (Burp, Caido, Camoufox, Camio).
- [ ] Single canonical parser/scope path; cover smuggling, parser differential, SSRF, DNS rebinding, redirect scope, malformed inputs.
- [ ] Profile isolation, secret handling, API/MCP authorization, plugin-boundary, parser fuzzing, dependency vuln checks.
- [ ] SBOM, license audit, signed releases, responsible disclosure + patch process.
- [ ] Independent security review before stable; resolve known critical/high.
- [ ] Automated + manual parity checks; publish an honest supported-feature and fingerprint-parity table.
- [ ] Campaign tests against controlled apps; validate payload provenance and result filters.
- [ ] Review feedback before each milestone; record decisions in the public roadmap/changelog.
