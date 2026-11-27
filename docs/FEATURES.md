# Camio feature reference

Every capability Camio ships today, grouped by workflow. Each entry names the
**crate** that implements it, the **CLI command**, and the **native-app surface**
where present. All tool traffic goes through the fingerprint-matched engine, is
scope-decided and policy-gated, and is captured to one SQLite store.

> Authorized use only. Reads are free; sends require in-scope + `--confirm`;
> active/destructive checks are off by default.

---

## 1. Identity: engine, fingerprint & stealth

| Capability | Crate | CLI | App surface |
|---|---|---|---|
| **Managed Camoufox engine** — download, unpack, locate, launch a Firefox-fork browser; no Node/Playwright server | `camio-engine` | `camio launch` | Open-browser |
| **Fingerprint policy** — a Chameleon-inspired anti-detection policy rendered to Firefox `about:config` **and** Camoufox engine-level overrides, with consistent **OS personas** (`--os windows\|macos\|linux`) | `camio-core` | `camio fingerprint`, `--os` on traffic cmds | Fingerprint view |
| **Matched request engine** — tool traffic sent through a BoringSSL impersonating client (`wreq`) whose TLS/JA3/JA4 + HTTP/2 fingerprint is pinned to the browser profile; header order/casing preserved on the wire; **parity is measured, not asserted** | `camio-request` | used by every send | Fingerprint view |

See [STEALTH.md](./STEALTH.md) for the full Camoufox-feature coverage map and the
honest pref-level vs C++-level limits.

## 2. Intercepting proxy

| Capability | Crate | CLI | App surface |
|---|---|---|---|
| **Scope-gated capture** — a Burp-style HTTP/HTTPS proxy; every request runs the *same* `Scope`/`Policy` path; out-of-scope / SSRF-guarded destinations are refused and recorded | `camio-proxy` | `camio proxy` | Proxy |
| **Match & Replace in-flight** — request rules before the send, response rules after; no header reordering/recasing | `camio-core` + `camio-proxy` | `camio proxy` (+ rules) | Match & Replace |
| **HTTPS two ways** — default **blind-relay** (browser TLS stays end-to-end, fingerprint-true, only host recorded) or `--tls-intercept` **terminate** with Camio's operator-trusted CA (`--export-ca`, neutral `--ca-name`) — honestly tagged fingerprint-changing | `camio-proxy` | `camio proxy --tls-intercept` / `--export-ca` | Proxy (TLS toggle, CA export) |
| **Interactive intercept queue** — pause/edit/drop requests and responses (`QueueInterceptor`) | `camio-proxy` | — | Proxy (Forward/Drop) |
| **WebSocket** — `ws://` upgrades scope-gated, recorded, raw-relayed; `wss://` rides the blind-relay | `camio-proxy` | `camio proxy` | Proxy |
| **Auto-scan** — run the passive scanner on in-scope captures automatically | `camio-proxy` + `camio-scan` | `camio proxy --auto-scan` | Proxy (auto-scan) |

## 3. Scanning

| Capability | Crate | CLI | App surface |
|---|---|---|---|
| **Passive scanner (17 checks)** — security headers, insecure cookies, banner/version disclosure, directory listing, verbose errors, reflected input, CORS, secrets-in-URL, basic-auth-over-HTTP, mixed content, **plus API/JS/web-domain testing**: hard-coded secret leaks (redacted), JS endpoint discovery, exposed Swagger/OpenAPI, GraphQL introspection, source maps, sensitive JSON fields, sensitive path exposure (`.git`/`.env`/…) | `camio-scan` | `camio scan` | Scanner |
| **`analyze_js` helper** — extract secrets + endpoints from any JS blob | `camio-scan` | (via scan / MCP) | Analyze JS |
| **Active scanner (opt-in)** — reflected-XSS, error-based SQLi, open-redirect probes via the matched engine; pure (caller injects a scope/policy-gated sender) | `camio-active` | `camio activescan` | Active scan |
| **CVSS v3.1 scoring** — rank any finding from a CVSS vector (`Finding::apply_cvss`); pure base-metric calculator → score + `Severity` | `camio-core` (`cvss`) | (library / findings) | Findings |

## 4. Attack & fuzzing

| Capability | Crate | CLI | App surface |
|---|---|---|---|
| **Automate / Intruder** — `§…§` insertion points, the four attack types (Sniper, Battering Ram, Pitchfork, Cluster Bomb), built-in payload packs + file imports, **bounded campaigns** (projected request count, refuses to exceed budget), CamioQL result classification | `camio-automate` | `camio fuzz` | Intruder |
| **Input discovery** — enumerate injectable inputs (query/body/cookies/headers/JSON) | `camio-automate` | `camio inputs` | (Intruder prep) |
| **Payload database** — a pre-built catalog of payload sets | `camio-automate` | (payload packs) | Payloads |

See [PAYLOAD-DB.md](./PAYLOAD-DB.md).

## 5. Reconnaissance & out-of-band

| Capability | Crate | CLI | App surface |
|---|---|---|---|
| **Bounded crawler** — same-origin, budgeted crawl through the matched engine, feeding the site map | `camio-active` | `camio crawl` | (Target) |
| **Self-hosted OAST collector** — a local, free Burp-Collaborator analog; mints correlation tokens, records out-of-band callbacks (SSRF, blind XXE, webhooks, DNS-style exfil), ties each hit to its token | `camio-oast` | `camio oast` | (Findings) |
| **Subdomain enumeration** — passive OSINT via `subfinder` | `camio-integrations` | `camio subfinder` | — |
| **Nuclei** — run the external scanner against an authorized target; normalize into findings/assets | `camio-integrations` | `camio nuclei` | — |
| **httpx probing** — ProjectDiscovery's prober for reachability, titles, servers, TLS and technology observations; JSONL parser + bounded runner + `--import` for existing exports; results stored as `httpx` observations, never promoted to findings; a differently-named `httpx` binary is rejected instead of silently probing nothing | `camio-integrations` | `camio probe` | — |
| **Integrations status** — list external tools and whether each is installed | `camio-integrations` | `camio integrations` | Extensions |

## 6. Data, evidence & tooling

| Capability | Crate | CLI | App surface |
|---|---|---|---|
| **Storage** — indexed SQLite history with content-addressed, deduplicated body blobs; metadata queries never load body bytes | `camio-store` | `camio review`, `camio query` | HTTP history |
| **CamioQL** — an HTTPQL-compatible query language for search, filtering, scope | `camio-core` | `camio query` | CamioQL |
| **Scope + SSRF guard** — one scope-decision path; private/loopback blocked unless a lab profile opts in; **link-local and the cloud-metadata address need their own explicit opt-in** (`--allow-metadata`) even in lab mode | `camio-core` | `camio scope` | Scope |
| **Explicit targets for automation** — discovery/scan/fuzz/campaigns refuse to run when the project defines no include rule; an empty scope is never read as permission | `camio-core` | (all active cmds) | — |
| **Approval binding** — an approval is a sha-256 plan hash over targets, action class, tool version, session, request/time/rate limits and policy revision; any drift refuses reuse | `camio-core` | `camio fuzz --approve <hash>` | — |
| **Durable background tasks** — full task lifecycle with validated transitions and distinct outcomes (success/timeout/cancel/scope-denied/parser/tool/storage), persisted per state change; interrupted runs are reconciled at startup | `camio-core` + `camio-tasks` + `camio-store` | `camio tasks [--reconcile]` | Tasks |
| **Site map** — host→path tree built from history | `camio-core` | (via review) | Target |
| **Labels** — organize exchanges (add/remove/list/show) | `camio-store` | `camio label` | — |
| **Diff** — byte/line Comparer, and unified diff between two stored exchanges | `camio-convert` / `camio-core` | `camio diff` | Comparer |
| **Findings triage** — list findings, set status | `camio-store` | `camio findings` | Findings |
| **Workspace backup** — consistent DB backup to a new file | `camio-store` | `camio backup` | — |
| **Importers** — Burp item XML, HAR (browsers, Caido) into the one canonical model (header order/casing preserved) | `camio-import` | `camio import` | Import |
| **Convert / Decoder** — base64/base64url, URL, HTML, hex, gzip/deflate; md5/sha1/sha256/sha512; JWT decode (unverified) | `camio-convert` | `camio convert` | Decoder / JWT |
| **Sequencer** — Shannon-entropy / per-position randomness of tokens (a statistical estimate, honestly labelled) | `camio-sequencer` | `camio sequencer` | Sequencer |

## 7. AI & automation

| Capability | Crate | CLI | App surface |
|---|---|---|---|
| **AI assistant (optional, BYO key)** — OpenAI-compatible client for NVIDIA NIM / OpenAI / local Ollama; explain an exchange, suggest tests, NL→CamioQL; off by default, no telemetry, key never logged/persisted | `camio-ai` | `camio ai` | AI assistant |
| **AI-mediation guard** — bind a session, verify a binding, authorize an action chain, integrity manifest | `camio-core` | `camio aiguard` | — |
| **MCP server** — local stdio JSON-RPC exposing Camio's data + tools (query, scope, policy-gated send, convert, scan, sequencer, input discovery, site map, fuzz planning, import, payloads, `active_scan`, `analyze_js`, OAST `oast_new_token`/`oast_interactions`, `subfinder_enum`) under the same policy | `camio-mcp` | `camio mcp stdio` | — |

See [AI-SAFETY.md](./AI-SAFETY.md).

## 8. Interfaces

| Capability | Crate | CLI | Notes |
|---|---|---|---|
| **CLI** — every capability scriptably | `camio-cli` | `camio` | `camio --help` |
| **Native desktop app** — egui/eframe window (no Electron/JS runtime); Burp-style tool-tab bar reusing Burp's tool names; same storage/policy as the CLI | `camio-app` | `camio app` | Deep-link `CAMIO_SURFACE=`, theme `CAMIO_THEME=` |
| **Themes** — Sentinel Blue default (black canvas, blue accents, Reduce-motion), custom colours + background; persists to `~/.config/camio/theme.json` | `camio-app` | — | Settings |
| **Local web workbench** — loopback-only UI with local fonts | `camio-web` | `camio ui` | open the printed session URL |
| **Plugin system** — process-based plugins from `plugins/` (any language; stdin→stdout) | `camio-app` | — | [plugins/README.md](../plugins/README.md) |
| **Camio-browser fork** — a rebranded LibreWolf with the black/blue theme + hardening baked in, shipped as a `.tar.xz` + `.deb` | `browser/` | — | [browser/README.md](../browser/README.md) |

---

For the command-level detail of any CLI entry, run `camio <command> --help`.
