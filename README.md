# Camio

[![CI](https://github.com/s-b-repo/camio/actions/workflows/ci.yml/badge.svg)](https://github.com/s-b-repo/camio/actions/workflows/ci.yml)
[![Security audit](https://github.com/s-b-repo/camio/actions/workflows/security.yml/badge.svg)](https://github.com/s-b-repo/camio/actions/workflows/security.yml)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](./LICENSE)

A local-first, **fingerprint-transparent** web security testing workbench — the speed
and UX of Caido, the depth of Burp, and testing traffic that doesn't stand out
*because of the tool*. Built in Rust around the [Camoufox](https://github.com/daijro/camoufox)
anti-detect Firefox engine. See [`plan.md`](./plan.md) for the full product plan.

> Status: **workbench core + manual/automated testing toolchain**. The engine
> supervisor, fingerprint policy, matched request engine, query language, storage,
> scope/policy engine and MCP server are now joined by a passive **scanner**,
> **Intruder-class** fuzzing, **Convert/Decoder/Comparer**, **Burp/HAR importers**,
> a **Sequencer**, a **site map**, and **Match & Replace** — all driven from the
> CLI, a **native desktop app** (`camio app`, egui/eframe), an optional local web
> UI (`camio ui`), and the MCP server under the one shared scope/policy. The
> remaining frontier is browser-native WebDriver-BiDi request interception and
> node-based *visual* workflows — these need a running Camoufox build, so they are
> not built yet (see plan.md §15 phases).

## Camio vs Burp Suite and Caido

Camio is **free, local-first, and fingerprint-transparent** — the thing neither
Burp nor Caido offers. An honest comparison:

| | Burp Suite | Caido | **Camio** |
|---|---|---|---|
| Price | Paid (Pro/Enterprise) | Freemium (gated) | **Free, no locks** |
| Tool-traffic fingerprint | Proxy TLS/H2 — a known WAF tell | Proxy — tool tell | **Matched to the browser, measured** |
| Query language | Filters | HTTPQL | **CamioQL (HTTPQL-compatible)** |
| Automation | Intruder | Workflows | Intruder-class + MCP |
| AI / agents | Add-ons | Plugins | **Built-in MCP server** |
| Interface | JVM, heavy | Rust, light | **Rust native + web + CLI** |
| Scanner maturity | **Deep, mature** | Growing | Passive now; active opt-in |
| Extensions | **Huge (BApp Store)** | JS/TS SDK | Process plugins (early) |

Where Camio leads today: **fingerprint transparency, price, MCP-native
automation, and a native + web + CLI experience with one query language
everywhere.** Where Burp still leads: **scanner depth and a mature extension
ecosystem** — Camio treats those as a roadmap (plan.md §8, §15), not a solved
problem, and measures fingerprint parity rather than claiming undetectability.

## What works today

- **Managed Camoufox engine** (pinned `v158.0.1-beta.41`): download, unpack,
  locate, launch — no Node.js/Playwright server.
- **Fingerprint policy** (`camio-core`): a [Chameleon](https://github.com/sereneblue/chameleon)-inspired
  anti-detection policy rendered to Firefox `about:config` prefs **and** Camoufox
  engine-level overrides.
- **Matched request engine** (`camio-request`): tool traffic (Replay/Automate/
  Scanner/MCP) is sent through a **BoringSSL-based impersonating client**
  ([`wreq`](https://crates.io/crates/wreq), the maintained successor to `rquest`)
  whose TLS/JA3/JA4 and HTTP/2 fingerprint is derived from — and pinned to — the
  same profile the browser uses (plan §6.2). Header order and casing are
  preserved exactly on the wire; nothing is alphabetized. **Parity is measured,
  not asserted** — the engine never claims invisibility and surfaces a note when
  the emulation preset lags the Camoufox version.
- **CamioQL** (`camio-core`): an HTTPQL-compatible query language used for search,
  filtering, scope and (soon) intercept/workflows — one language everywhere.
- **Storage** (`camio-store`): indexed SQLite history with content-addressed,
  deduplicated body blobs, filtered by CamioQL; metadata-only queries never load
  body bytes.
- **Scope + policy** (`camio-core`): one scope-decision path with an SSRF guard
  (loopback/link-local/metadata/private are blocked unless a lab profile opts in),
  and one shared authorization policy (reads free; sends in-scope + confirmed;
  active/destructive disabled by default).
- **Passive scanner** (`camio-scan`): seventeen passive checks over captured
  history — security headers, insecure cookies, banner/version disclosure,
  directory listing, verbose errors, reflected input, CORS misconfig, secrets in
  the URL, basic-auth over HTTP, mixed content, **plus automated API/JS/web-domain
  testing**: hard-coded secret leaks in responses (redacted), JavaScript endpoint
  discovery, exposed Swagger/OpenAPI docs, GraphQL introspection, exposed source
  maps, sensitive JSON fields, and sensitive path exposure (`.git`/`.env`/…) —
  producing deduplicated, severity-ranked findings (plan §8, §15 Phase 4). The
  reusable `analyze_js` helper extracts secrets + endpoints from any JS blob.
- **Active scanner** (`camio-active`, opt-in): reflected-XSS, error-based SQLi and
  open-redirect probes that send through the matched engine. It is pure — the
  caller injects a scope- and policy-gated sender — so active testing stays
  in-scope, confirmed and bounded (plan §16). Run it with `camio activescan`.
- **AI assistant** (`camio-ai`, optional, BYO key): an OpenAI-compatible client
  for **NVIDIA NIM**, OpenAI, or a local Ollama — explain an exchange, suggest
  next tests, or translate natural language to CamioQL. Off by default, needs an
  explicit API key (from env), no telemetry; the key is never logged or persisted
  (plan §11).
- **Automate / Intruder** (`camio-automate`): `§…§` insertion points, built-in
  payload packs plus file imports, the four attack types (Sniper, Battering Ram,
  Pitchfork, Cluster Bomb), **bounded campaigns** that show a projected request
  count and refuse to exceed the budget, input discovery, and CamioQL-driven
  result classification — all requests go through the matched engine, in-scope,
  and only after `--confirm` (plan §10).
- **Convert / Decoder / Comparer** (`camio-convert`): reversible encodings
  (base64/base64url, URL, HTML, hex, gzip/deflate), one-way hashes
  (md5/sha1/sha256/sha512), JWT decode (unverified), and byte/line diff —
  reusable transforms (plan §8).
- **Importers** (`camio-import`): Burp Suite item XML exports and HAR archives
  (browsers, Caido) are ingested into the one canonical exchange model, header
  order and casing preserved (plan §7.4).
- **Sequencer** (`camio-sequencer`): Shannon-entropy and per-position randomness
  analysis of session tokens, honestly labelled a statistical estimate, not a
  proof (plan §8).
- **Site map + Match & Replace** (`camio-core`): a host→path tree built from
  history (Discover), and CamioQL-gated match-and-replace rules that rewrite
  outgoing requests without reordering or recasing headers (plan §7.2).
- **MCP server** (`camio-mcp`): a local stdio MCP server exposing Camio's data
  (fingerprint status, history, findings) and **16 tools** — CamioQL query, scope
  check, policy-gated send, convert, scan, sequencer, input discovery, site map,
  fuzz planning, file import, payload listing, a policy-gated **active_scan**, and
  **analyze_js** — all under the same policy as the CLI.
- **Native desktop app** (`camio-app`): `camio app` opens a real egui/eframe
  window (no Electron, no bundled JS runtime) with a grouped left rail of 24
  surfaces — Status, Fingerprint, History, Query, Site map, Replay, Discover,
  Automate/Fuzz, Scanner, **Active scan**, Findings, Convert, Comparer, JWT,
  Sequencer, Match & Replace, Scope, Payloads, Import, **Analyze JS**, **AI
  assistant**, Open-browser, Plugins, Settings — calling the same crates in-process
  under the same scope/policy gates as the CLI (AI calls run on a background thread
  so the window stays responsive). It adds:
  - **Customizable themes + background image**: seven presets (Midnight,
    Antigravity, LibreWolf, Carbon, Matrix, Daylight, High Contrast), a live
    editor (accent/window/panel/text colours, corner rounding) and an optional
    background image with opacity — persisted to `~/.config/camio/theme.json`.
  - **Open in browser**: launches a **LibreWolf / Camoufox** (Firefox-fork)
    browser with Camio's fingerprint profile written into its `about:config`, so
    browsing and tool traffic share one identity (plan §6.3), and with the
    Marionette automation channel enabled so the browser is agent-drivable (the
    WebDriver-BiDi control frontier, plan §9).
  - **Plugin system**: process-based plugins discovered from `plugins/` (any
    language; input on stdin, output on stdout), with two bundled demos. See
    [`plugins/README.md`](./plugins/README.md).
  - **Fingerprint view**: shows the exact JA3/JA4 · HTTP-2 · header-order profile
    ported onto every sent request.
  - Deep-link a surface with `CAMIO_SURFACE=<name>` and pick a theme with
    `CAMIO_THEME=<preset>`.
- **Local web UI** (`camio-web`, optional): `camio ui` serves the same workbench
  on loopback (`127.0.0.1`) for headless/remote use — a single-page app over a
  JSON API, same gates, no bundled JS runtime (plan §16).
- **No TLS MITM, no CA install** for browser traffic — the browser makes the real
  connection, so the server sees Camoufox's genuine fingerprint (plan §6).

## Workspace layout

```
crates/
  camio-core/      Domain model + CamioQL + scope + policy + fingerprint + match-replace + sitemap
  camio-engine/    Camoufox supervisor: unpack, locate, configure, launch
  camio-request/   Fingerprint-matched request engine (BoringSSL impersonation)
  camio-store/     Indexed history + content-addressed bodies (SQLite)
  camio-convert/   Convert/Decoder/Comparer: encodings, hashes, JWT, diff
  camio-scan/      Passive security scanner → findings
  camio-automate/  Intruder: insertion points, payload packs, attack types, campaigns
  camio-import/    Burp XML + HAR importers
  camio-sequencer/ Token randomness/entropy analysis
  camio-app/       Native desktop workbench (egui/eframe)
  camio-web/       Local loopback web UI (serves every capability)
  camio-mcp/       Local MCP server (stdio JSON-RPC)
  camio-cli/       `camio` command-line interface
vendor/camoufox/   Pinned engine (gitignored; download separately)
plan.md            Full product plan
```

## Install

Build from source (recent stable Rust; the first build compiles BoringSSL and
bundled SQLite, a few minutes):

```bash
# Debian / Kali / Ubuntu build deps for the native app + matched engine:
sudo apt-get install -y libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
                        libxkbcommon-dev libwayland-dev cmake clang

git clone https://github.com/s-b-repo/camio
cd camio
cargo build --release            # -> target/release/camio
./target/release/camio --help
```

Packaging for distributions: a man page (`man/camio.1`), a desktop entry
(`packaging/camio.desktop`), a Debian packaging skeleton (`debian/`), and a Kali
submission guide (`docs/KALI_SUBMISSION.md`) ship in the repo.

## Quick start

```bash
# Build everything (first build compiles BoringSSL — a few minutes)
cargo build

# Download + unpack the engine (once; ~1.3 GB)
curl -L -o vendor/camoufox/camoufox-lin-x86_64.zip \
  "$(cargo run -qp camio-cli -- engine info | awk '/download url/{print $4}')"
cargo run -p camio-cli -- engine unpack

# Inspect the anti-detection policy and the matched-engine fingerprint spec
cargo run -p camio-cli -- fingerprint show --preset hardened --format user-js
cargo run -p camio-cli -- fingerprint spec --preset balanced

# Launch the managed browser against an AUTHORIZED target
cargo run -p camio-cli -- launch --preset balanced --url https://example.org

# Send a request through the fingerprint-matched engine (preview first, then --confirm)
cargo run -p camio-cli -- send https://example.org
cargo run -p camio-cli -- send https://example.org --confirm -H "X-Test: 1"

# Query stored history with CamioQL
cargo run -p camio-cli -- query 'resp.code.gte:400 AND req.host.cont:"example"'
cargo run -p camio-cli -- history --limit 20

# Check the scope decision for a URL (SSRF guard demo)
cargo run -p camio-cli -- scope http://169.254.169.254/        # -> blocked

# Convert / Decoder / Comparer and JWT decode
cargo run -p camio-cli -- convert 'base64,gzip' --input "hello"
cargo run -p camio-cli -- convert --list
cargo run -p camio-cli -- jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig
cargo run -p camio-cli -- compare old.txt new.txt

# Import a Burp/HAR capture, run the passive scanner, see the site map
cargo run -p camio-cli -- import capture.har --db camio.db
cargo run -p camio-cli -- scan 'resp.code.lt:400' --db camio.db --save
cargo run -p camio-cli -- sitemap --db camio.db

# Discover inputs, then fuzz an AUTHORIZED target (preview first, then --confirm)
cargo run -p camio-cli -- discover 'https://example.org/s?q=1&id=2'
cargo run -p camio-cli -- payloads                              # list built-in packs
cargo run -p camio-cli -- fuzz 'https://example.org/item?id=§1§' \
  --attack sniper --payloads sqli                              # plan only (projected count)
cargo run -p camio-cli -- fuzz 'https://example.org/item?id=§1§' \
  --attack sniper --payloads sqli --budget 50 --confirm        # actually run (active)

# Analyse session-token randomness
cargo run -p camio-cli -- sequencer --file tokens.txt

# Opt-in ACTIVE scan of an authorized target (preview first, then --confirm)
cargo run -p camio-cli -- activescan 'https://example.org/item?id=1' --confirm

# Ask the optional AI assistant (BYO key via env)
export NVIDIA_API_KEY=nvapi-...                                # or OPENAI_API_KEY
cargo run -p camio-cli -- ai --provider nvidia-nim "explain the risks in a reflected 'next' param"
cargo run -p camio-cli -- ai --camioql "find 5xx responses from the api host"

# Rewrite an outgoing request (Match & Replace), then send
cargo run -p camio-cli -- send https://example.org --confirm \
  --rewrite 'header=User-Agent|curl|Mozilla/5.0'

# Launch the native desktop app — every capability in one window
cargo run -p camio-cli -- app

# …or the optional local web UI (headless/remote) — same workbench in a browser
cargo run -p camio-cli -- ui                                   # http://127.0.0.1:8787

# Serve MCP over stdio (for an agent / MCP client)
cargo run -p camio-cli -- mcp serve
```

## CamioQL

HTTPQL-compatible (Caido parity). Clauses are `namespace.field.operator:value`,
combined with `AND`/`OR`/`NOT` and parentheses; a bare word or quoted string is a
free-text search over the raw request and response.

```
req.ext.eq:".js" AND resp.code.gte:400
req.method.eq:POST AND req.host.cont:"api"
resp.body.cont:"stack trace" OR resp.code.eq:500
req.header.user-agent.cont:"curl"
```

Fields: `req.{method,url,host,port,path,query,ext,len,raw,body,version,header.<name>}`,
`resp.{code,len,raw,body,reason,version,roundtrip,header.<name>}`, and
`source`/`scope`/`fingerprint`/`id`/`created_at`. Operators: `eq ne cont ncont
like nlike regex nregex gt gte lt lte exists nexists`.

## Scope and honesty

Camio is for **authorized** testing only. "Fingerprint transparency" means Camio
does not add a tool tell on top of the browser — it is **not** a promise of
undetectability and does not defeat a specific target's bot defenses. Parity with
the real browser's fingerprint must be *measured* (plan §6.3, §17), not assumed;
the Camoufox engine-config key names and the emulation-preset mapping here are
provisional until verified against the pinned build in the Phase-0 spike.

## License

Provisional **MPL-2.0** (Camoufox is MPL-2.0); final choice per plan §12.
