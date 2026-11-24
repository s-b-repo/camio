# Camio

[![CI](https://github.com/s-b-repo/camio/actions/workflows/ci.yml/badge.svg)](https://github.com/s-b-repo/camio/actions/workflows/ci.yml)
[![Security audit](https://github.com/s-b-repo/camio/actions/workflows/security.yml/badge.svg)](https://github.com/s-b-repo/camio/actions/workflows/security.yml)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](./LICENSE)
[![M8ven Score](https://m8ven.ai/badge/mcp/s-b-repo-camio-4k9o1o)](https://m8ven.ai/mcp/s-b-repo-camio-4k9o1o?s=readme)
[![M8ven Score](https://m8ven.ai/badge/mcp/s-b-repo-camio-4k9o1o?v=0ca67e1f50fcc76503ae408d731bf1b3)](https://m8ven.ai/mcp/s-b-repo-camio-4k9o1o?s=readme)

A local-first, **fingerprint-transparent** web security testing workbench — the speed
and UX of Caido, the depth of Burp, and testing traffic that doesn't stand out
*because of the tool*. Built in Rust around the [Camoufox](https://github.com/daijro/camoufox)
anti-detect Firefox engine. See [`plan.md`](./plan.md) for the full product plan.

**📚 Documentation hub → [`docs/INDEX.md`](./docs/INDEX.md)** — install, the full
[feature reference](./docs/FEATURES.md), [architecture](./docs/ARCHITECTURE.md),
[configuration](./docs/CONFIGURATION.md), and security.

> Status: **workbench core + manual/automated testing toolchain**. The engine
> supervisor, fingerprint policy, matched request engine, query language, storage,
> scope/policy engine and MCP server are now joined by a passive **scanner**,
> **Intruder-class** fuzzing, **Convert/Decoder/Comparer**, **Burp/HAR importers**,
> a **Sequencer**, a **site map**, **Match & Replace**, and an **intercepting
> HTTP/HTTPS proxy** (`camio proxy`, with opt-in TLS MITM) — all driven from the
> CLI, a **native desktop app** (`camio app`, egui/eframe), an optional local web
> UI (`camio ui`), and the MCP server under the one shared scope/policy. Stored
> traffic can be reviewed with versioned offline workflows, evidence imports,
> and finding reports. Live managed-browser WebDriver-BiDi interception and a
> general-purpose workflow editor remain on the roadmap.

## Camio vs Burp Suite and Caido

Camio is **free, local-first, and fingerprint-transparent** — the thing neither
Burp nor Caido offers. An honest comparison:

| | Burp Suite | Caido | **Camio** |
|---|---|---|---|
| Price | Paid (Pro/Enterprise) | Freemium (gated) | **Free, no locks** |
| Tool-traffic fingerprint | Proxy TLS/H2 — a known WAF tell | Proxy — tool tell | **Matched to the browser, measured** |
| Intercepting proxy (TLS MITM) | Core | Core | **Yes — scope-gated, matched-engine upstream** |
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
  engine-level overrides, with consistent **OS personas** (`--os
  windows|macos|linux`). See [`docs/STEALTH.md`](./docs/STEALTH.md) for the full
  Camoufox-feature coverage map and the honest pref-level vs C++-level limits.
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
- **Intercepting proxy** (`camio-proxy`, `camio proxy`): a Burp-style
  HTTP/HTTPS proxy you point a browser at. Every request is **scope-decided and
  policy-gated** through the *same* `Scope`/`Policy` path as the rest of Camio
  (out-of-scope and SSRF-guarded destinations are refused and recorded as
  attempts), **Match & Replace** rewrites run in-flight (request rules before the
  send, response rules after), and every exchange is captured to the SQLite store
  tagged `source=proxy`. HTTPS is handled two ways: by default a CONNECT is
  **blind-relayed** so the browser's own TLS stays end-to-end (fingerprint-true;
  only the host is recorded), or with `--tls-intercept` it is **terminated** by
  Camio's own operator-trusted CA (`camio proxy --export-ca`) so the plaintext is
  inspected and re-sent through the fingerprint-matched engine — honestly tagged
  fingerprint-changing. **WebSocket:** a `ws://` upgrade is scope-gated, recorded,
  and raw-relayed so it works through the proxy; `wss://` rides the blind-relay.
  A UI-agnostic **intercept queue** (`QueueInterceptor`)
  lets a front-end pause/edit/drop requests and responses. The upstream send is
  the injected matched engine, so the proxy adds no second HTTP client and all
  destination policy stays in one place. **Hard to fingerprint:** the re-sent
  request keeps the matched JA3/JA4/H2 identity, proxy replies carry no
  identifying header, and the intercept CA is neutral by default and settable
  (`--ca-name`). **Scope-aware automation:** `--auto-scan` runs the passive
  scanner on in-scope captures automatically (out-of-scope is recorded, never
  tested). Available from the CLI (`camio proxy`) and a **Proxy** surface in the
  native app (Start/Stop, TLS toggle, auto-scan, CA export, live capture table,
  and **interactive intercept** — hold a request, edit it, Forward or Drop).
- **Self-hosted OAST collector** (`camio-oast`, `camio oast`): a local-first,
  free analog of Burp's paid cloud Collaborator. It mints correlation tokens,
  records out-of-band callbacks (SSRF, blind XXE, webhooks, DNS-style host
  exfil), and ties each hit back to the token you planted — path-style
  (`/<token>`) or DNS-style (`<token>.<base>`). Runs on infrastructure you
  control; it sees callbacks that can reach the address you bind.
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
  (fingerprint status, history, findings) and tools for CamioQL query, scope
  check, policy-gated send, convert, scan, sequencer, input discovery, site map,
  fuzz planning, file import, payload listing, a policy-gated **active_scan**,
  **analyze_js**, **OAST** (`oast_new_token` / `oast_interactions`, so an
  agent can plant a correlated callback and read the out-of-band hits), and
  **subfinder_enum** (passive subdomain recon) — all under the same policy as
  the CLI. Passive reviews also expose task IDs,
  paginated results, cancellation, and redacted finding reports.
- **Native desktop app** (`camio-app`): `camio app` opens a real egui/eframe
  window (no Electron, no bundled JS runtime) with a **Burp-style top tool-tab
  bar** — Dashboard, Target, **Proxy**, HTTP history, CamioQL, Repeater,
  Intruder, Sequencer, Scanner, Active scan, Findings, Decoder, Comparer, JWT,
  Analyze JS, Match & Replace, Scope, Payloads, Import, **AI assistant**,
  Open-browser, Extensions (plugins), Settings, and more — reusing Burp's tool
  names so the muscle memory carries over. The **Proxy** tab runs the
  intercepting proxy with interactive intercept. It uses the same storage and
  policy as the CLI.
  - **Customizable themes and background image.** Sentinel Blue is the default,
    with a black canvas, blue grid animation, and a Reduce motion setting. The
    other presets, custom colours, and background controls are available in
    Workspace settings. Save the theme to persist it to `~/.config/camio/theme.json`.
    The default palette and terminal styling draw on the Cyber Sec site. [Cyber Sec](https://cybersec.org.za/)
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
- **Local web UI** (`camio-web`): `camio ui` serves the workbench on loopback.
  Open the full session link printed by the command. The interface bundles its
  fonts locally and supports both browser-level and in-app reduced motion.
- **Browser capture needs no TLS MITM and no CA install** — in the managed-browser
  path the browser makes the real connection, so the server sees Camoufox's genuine
  fingerprint (plan §6). TLS interception is available only in the *optional*
  `camio proxy --tls-intercept` mode, is off by default, and is clearly tagged
  fingerprint-changing when you choose it.

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
  camio-active/    Opt-in active scanner (reflected XSS, error SQLi, open redirect)
  camio-ai/        Optional OpenAI-compatible assistant (BYO key)
  camio-proxy/     Intercepting HTTP/HTTPS proxy (scope-gated, TLS MITM, intercept queue)
  camio-oast/      Self-hosted OAST collector (out-of-band callback correlation)
  camio-integrations/ External-tool adapters (Nuclei, subfinder): bounded runner + normalizer
  camio-app/       Native desktop workbench (egui/eframe)
  camio-web/       Local loopback web UI (serves every capability)
  camio-mcp/       Local MCP server (stdio JSON-RPC)
  camio-cli/       `camio` command-line interface
vendor/camoufox/   Pinned engine (gitignored; download separately)
plan.md            Full product plan
```

## Install

### Quick install — prebuilt binaries

Linux/macOS (x86_64 or aarch64); installs the `camio` CLI and `camio-app` GUI to
`~/.local/bin` (or `/usr/local/bin` when writable):

```sh
curl -fsSL https://raw.githubusercontent.com/s-b-repo/camio/main/scripts/install.sh | sh
```

Pin a release with `CAMIO_VERSION=vX.Y.Z` or a location with `CAMIO_BIN_DIR=…`;
the script verifies the published SHA-256. For the **themed browser fork**,
install the `.deb` from the matching `browser-v*` release:

```sh
sudo apt install ./camio-browser_*_amd64.deb && camio-browser
```

### Build from source

Recent stable Rust; the first build compiles BoringSSL and bundled SQLite (a few
minutes):

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

> 📘 **Full build, feature-flag, debugging, and every-command reference →
> [`docs/BUILDING.md`](./docs/BUILDING.md).** Covers every per-crate feature,
> all CLI subcommands and combos, environment variables, LLDB/VS Code
> configurations, performance profiling, and troubleshooting.
>
> 🎯 **Payload database (1,568 base payloads × 5 encodings = 6,995 rows, 22
> categories including HTTP request smuggling, SSTI, Log4Shell, SSRF, XXE,
> NoSQLi, CRLF, JWT, Unicode-normalisation, auth-bypass and more) →
> [`docs/PAYLOAD-DB.md`](./docs/PAYLOAD-DB.md).** Transparent plain-text source
> under `payloads/DB/base/`, pre-built SQLite catalog at
> `payloads/DB/payloads.sqlite`, combined/chained generation via `camio combo`,
> and automated passive signature matching for in-scope captures when
> `camio proxy --auto-scan` is on.

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

# Crawl an AUTHORIZED target (bounded, same-origin), then build its site map
cargo run -p camio-cli -- crawl https://target.example.com --confirm --max-pages 50 --db camio.db

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

# Run the intercepting proxy; point your browser's HTTP/HTTPS proxy at it.
# Plain HTTP is intercepted; HTTPS is blind-relayed (fingerprint-true).
# --auto-scan passively tests every IN-SCOPE exchange and stores findings.
cargo run -p camio-cli -- proxy --listen 127.0.0.1:8080 --db camio.db --auto-scan \
  --scope-include 'host.eq:"target.example.com"'

# Decrypt HTTPS too: export the CA, import it into the browser, then intercept.
cargo run -p camio-cli -- proxy --export-ca camio-ca.pem
cargo run -p camio-cli -- proxy --tls-intercept --db camio.db \
  --scope-include 'host.eq:"target.example.com"' \
  --rewrite 'resp-header=Content-Security-Policy|*|'   # strip a response header in-flight

# Self-hosted OAST: run a collector for blind callbacks, or print sample URLs.
cargo run -p camio-cli -- oast --listen 0.0.0.0:8888 --base oast.your-host.tld:8888
cargo run -p camio-cli -- oast --tokens 3     # print correlation tokens + callback URLs

# Run Nuclei (external, optional) against an AUTHORIZED target; normalize + save.
cargo run -p camio-cli -- nuclei https://target.example.com --tag tech --confirm --save

# Enumerate subdomains with subfinder (external, passive OSINT).
cargo run -p camio-cli -- subfinder example.com --json

# Launch the native desktop app — every capability in one window
cargo run -p camio-cli -- app

# …or open the local web workbench using the session URL printed in the terminal
cargo run -p camio-cli -- ui

# Serve MCP over stdio (for an agent / MCP client)
cargo run -p camio-cli -- mcp serve
```

## Reviewing stored evidence

Use the same `--db` path in `camio app`, `camio ui`, and `camio workbench` to
share a workspace, or select a new path for an isolated project. Import HAR or
Burp items XML, filter traffic with CamioQL, and open a row to inspect ordered
headers and a bounded body preview. Save exchanges with notes and reuse named
filters from the Library. Use `Ctrl+K` or `Cmd+K` to open tool search.

Passive review tasks evaluate a snapshot of recent stored exchanges. For a
repeatable review, save the CamioQL filter, exchange limit, and triage option as
a version in **Review workflows**. Edit the fields or apply a schema-versioned
JSON document. Each task records the version it ran and exposes progress,
retained results, and cancellation.

Choose a subset of built-in passive checks in the workflow editor when a
review only needs selected checks. Each saved version records that selection,
and its run reports include the selected IDs. Use `camio workbench review-checks`
to list the IDs for a schema version 2 plan's `check_ids` field.

Attach a HAR or Burp items XML capture of up to 4 MiB in **Review workflows**
to import and review that capture in one run. The task records the capture
hash, import warnings, and review results. Running the same archive again
reuses its stored exchanges. From **Review tasks**, export a redacted report
for a finished run with its workflow version, capture hash, counts, and linked
evidence IDs.

Findings can be triaged and exported as Markdown, JSON, HTML, or SARIF 2.1.0.
Reports include check IDs, statuses, and local evidence IDs. Free text and
captured messages stay in the workspace. [SARIF format](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)

Use **Asset inventory** to group recorded HTTP and HTTPS origins and endpoints
across captured exchanges and imported httpx and Nuclei observations. Sources
retain their original exchange or artifact links. Add an origin label and note
to record triage context.

An evidence bundle combines a finished review report with redacted summaries
of linked exchanges. Its manifest contains SHA-256 checksums for the report and
each evidence item. Use `camio verify-bundle` to check integrity offline.

Integration evidence accepts existing ProjectDiscovery httpx and Nuclei JSONL
reports and stores the original text with its SHA-256 hash. Other tools' reports
can be kept as raw evidence. Import previews show unmapped or malformed rows,
and observed matches stay attributed to their source artifact.

```bash
camio workbench --db review.db import-evidence httpx observations.jsonl --preview
camio workbench --db review.db review --query 'resp.code.gte:400' --save
camio workbench --db review.db workflow save 'Error responses' review-plan.json
camio workbench --db review.db workflow run 1 --version 1
camio workbench --db review.db workflow run 1 --version 1 --archive capture.har
camio workbench --db review.db review-report 1 --format json > review-report.json
camio workbench --db review.db inventory --filter example
camio workbench --db review.db review-bundle 1 > review-evidence.json
camio verify-bundle review-evidence.json
camio workbench --db review.db report --format sarif > findings.sarif
camio workbench --db review.db backup review-backup.db
```

A review plan document can be exported from either interface. A minimal
example is `{"schema_version":1,"query":"resp.code.gte:400","limit":200,"save":true}`.

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
