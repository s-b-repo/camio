<div align="center">

<!-- Themed banner / badges — render as colored chips on GitHub -->

![Camio](https://img.shields.io/badge/CAMIO-fingerprint--transparent%20workbench-1e80ff?style=for-the-badge&labelColor=020508)

![Rust](https://img.shields.io/badge/rust-stable%201.80%2B-dea584?style=flat-square&logo=rust&logoColor=white&labelColor=020508)
![CI](https://img.shields.io/badge/CI-green-2ea043?style=flat-square&labelColor=020508)
![License](https://img.shields.io/badge/license-MPL--2.0-1e80ff?style=flat-square&labelColor=020508)
![Workspace](https://img.shields.io/badge/crates-20-6f42c1?style=flat-square&labelColor=020508)
![Tests](https://img.shields.io/badge/tests-525%2B-2ea043?style=flat-square&labelColor=020508)

# Building, Running & Debugging Camio

**The complete, color-coded reference for every build flag, every CLI subcommand,
every feature combo, and every supported debugging workflow.**

</div>

---

## Table of contents

> Use `Ctrl+F` on the headings — the file is intentionally one scrollable reference.

- [1. At-a-glance](#1-at-a-glance)
- [2. Prerequisites](#2-prerequisites)
- [3. Build matrix — every flag, every feature, every profile](#3-build-matrix--every-flag-every-feature-every-profile)
- [4. First run — bootstrap the engine](#4-first-run--bootstrap-the-engine)
- [5. Every CLI command, grouped and themed](#5-every-cli-command-grouped-and-themed)
- [6. Feature combos — recipes for common workflows](#6-feature-combos--recipes-for-common-workflows)
- [7. Environment variables](#7-environment-variables)
- [8. Debugging — step by step](#8-debugging--step-by-step)
- [9. Tests, lints, and supply-chain gates](#9-tests-lints-and-supply-chain-gates)
- [10. Packaging, distribution, release](#10-packaging-distribution-release)
- [11. Troubleshooting index](#11-troubleshooting-index)
- [12. Appendix — crate layout and feature graph](#12-appendix--crate-layout-and-feature-graph)

---

## 1. At-a-glance

<table>
<tr>
<td>

### 🟦 Build
```bash
cargo build --release \
  --all-features --workspace
```

</td>
<td>

### 🟩 Run
```bash
./target/release/camio --help
./target/release/camio app
```

</td>
<td>

### 🟪 Debug
```bash
RUST_LOG=camio=debug \
RUST_BACKTRACE=1 \
cargo run -p camio-cli -- app
```

</td>
</tr>
</table>

| Layer | Default | Notes |
|---|---|---|
| 🟦 **Toolchain** | `cargo 1.100.0` stable | Matches CI; older stables trip new clippy lints. |
| 🟦 **Rust edition** | 2021 (`rust-version = 1.80`) | Workspace-wide. |
| 🟪 **Debug profile** | `cargo build` | Fast builds, full symbols, large binary. |
| 🟨 **Release profile** | `cargo build --release` | `lto = "thin"`, `strip = true` — small, fast, no symbols. |
| 🟥 **Reset** | `rm -rf target/debug/incremental` | Frees disk when the tree hits ENOSPC. |

---

## 2. Prerequisites

### 🧰 System packages

<details open>
<summary><strong>Debian · Kali · Ubuntu</strong></summary>

```bash
sudo apt-get install -y \
  libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libxkbcommon-dev libwayland-dev cmake clang pkg-config
```

These are **required** for the native `camio-app` (egui/eframe winit + wayland)
and for compiling the bundled SQLite in `rusqlite`. `cmake` and `clang` are
needed by BoringSSL in the matched engine (`wreq`).
</details>

<details>
<summary><strong>Fedora · RHEL</strong></summary>

```bash
sudo dnf install -y \
  libxcb-devel libxkbcommon-devel wayland-devel \
  cmake clang pkgconf-pkg-config
```
</details>

<details>
<summary><strong>Arch · Manjaro</strong></summary>

```bash
sudo pacman -S --needed \
  libxcb libxkbcommon wayland cmake clang pkgconf
```
</details>

### 🦀 Rust toolchain

```bash
# Install rustup, then pin stable:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install stable
rustup default stable
rustc --version        # expect 1.100.0 or newer
```

> [!IMPORTANT]
> CI uses **stable 1.100.0** with `-D warnings`. A looser local toolchain will
> pass locally and fail on the server. Run `rustup update stable` before pushing.

### 💽 Disk budget

| Artifact | Size |
|---|---|
| 🟦 Debug build, cold | ~3 GB in `target/debug` |
| 🟨 Release build, cold | ~2 GB |
| 🟪 Camoufox engine zip | ~300 MB download / ~1.3 GB unpacked in `vendor/camoufox/` |
| 🟥 Incremental cache | up to 30 GB; `rm -rf target/debug/incremental` to reclaim |

---

## 3. Build matrix — every flag, every feature, every profile

### 3.1 Workspace-wide builds

```bash
# ── DEBUG — fast rebuilds, full symbols ───────────────────────────────
cargo build                                     # whole workspace, default features
cargo build --workspace                         # explicit
cargo check --workspace                         # type-only, no codegen (fastest)

# ── RELEASE — optimized, LTO, stripped ────────────────────────────────
cargo build --release                           # -> target/release/camio
cargo build --release --workspace

# ── EVERYTHING ON ─────────────────────────────────────────────────────
cargo build --release --workspace --all-features

# ── EVERYTHING OFF (library-only, no network, no TLS MITM) ────────────
cargo build --workspace --no-default-features
```

### 3.2 Per-crate feature flags

Two crates expose cargo features; everything else is default-only.

#### 📡 `camio-request` — the matched request engine

| Feature | Default? | What it enables |
|---|:---:|---|
| 🟢 `impersonate` | **yes** | Pulls `wreq` (BoringSSL impersonation) + `wreq-util` (browser presets) + `tokio`. Sends real HTTP(S). |
| ⚪ *(no default)* | — | Pure spec + dry-run engine, no network, no TLS. Embed-friendly. |

```bash
# Real matched engine (default):
cargo build -p camio-request

# Pure, no-network core:
cargo build -p camio-request --no-default-features
```

#### 🕳️ `camio-proxy` — the intercepting proxy

| Feature | Default? | What it enables |
|---|:---:|---|
| 🟢 `tls-intercept` | **yes** | `rustls` + `rcgen` + `time` — HTTPS MITM with Camio's CA. |
| 🟢 `engine` | **no** (enabled by CLI/app) | Pulls `camio-request` so the proxy has a ready-made upstream forwarder. |

```bash
# Default (TLS MITM available, no engine forwarder):
cargo build -p camio-proxy

# Plain-HTTP proxy only, no server TLS stack:
cargo build -p camio-proxy --no-default-features

# Full CLI/app configuration:
cargo build -p camio-proxy --features "tls-intercept,engine"
```

> [!TIP]
> `camio-cli` and `camio-app` already turn on `camio-proxy/engine` and
> `camio-request/impersonate`. You only tune features when **embedding** Camio
> as a library.

### 3.3 Targeted single-crate builds

```bash
cargo build -p camio-core          # pure domain model — no OS deps
cargo build -p camio-cli           # just the CLI binary
cargo build -p camio-app           # just the native workbench
cargo build -p camio-mcp           # just the MCP server
cargo build -p camio-web           # loopback web UI
```

### 3.4 Release-profile knobs

Already set in the root `Cargo.toml`:

```toml
[profile.release]
lto   = "thin"       # whole-program link-time optimization
strip = true         # strip debug symbols for a small binary
```

Override on the command line without editing files:

```bash
# Fat LTO (slower link, smaller binary):
CARGO_PROFILE_RELEASE_LTO=fat cargo build --release

# Keep debug symbols for perf/flamegraph:
CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=true \
  cargo build --release
```

---

## 4. First run — bootstrap the engine

The Camoufox engine ships separately so the Rust workspace stays small.

```bash
# 1 ─ discover the pinned build + its mirror URL
cargo run -qp camio-cli -- engine info

# 2 ─ download the zip into vendor/camoufox/ (gitignored)
curl -L -o vendor/camoufox/camoufox-lin-x86_64.zip \
  "$(cargo run -qp camio-cli -- engine info | awk '/download url/{print $4}')"

# 3 ─ unpack
cargo run -p camio-cli -- engine unpack
```

> [!NOTE]
> You do **not** need the engine for CLI subcommands that only act on stored
> history (`query`, `scan`, `findings`, `workbench …`, `backup`, `verify-bundle`)
> or for the matched engine's `send` (which uses `wreq`, not Camoufox). The
> engine is required only by `camio launch` and the browser button inside
> `camio app`.

---

## 5. Every CLI command, grouped and themed

Each command below shows: **purpose**, **active vs. passive**, **key flags**,
and a **one-liner you can paste**.

Legend:

![passive](https://img.shields.io/badge/passive-safe-2ea043?style=flat-square) read-only / no network
![send](https://img.shields.io/badge/send-authorized%20target-dea584?style=flat-square) sends through the matched engine, scope-gated
![active](https://img.shields.io/badge/active-destructive%20opt--in-d73a49?style=flat-square) requires `--confirm`

### 🧩 5.1 Engine & profile

<details open>
<summary><code>camio engine info|unpack</code> &nbsp;·&nbsp; <code>camio fingerprint show|spec</code> &nbsp;·&nbsp; <code>camio launch</code></summary>

```bash
camio engine info
camio engine unpack

camio fingerprint show --preset hardened --format user-js
camio fingerprint show --preset balanced --format engine-json
camio fingerprint show --preset balanced --format profile-json
camio fingerprint spec  --preset balanced        # the JA3/JA4/H2 spec

# OS persona flows into BOTH user.js AND Camoufox engine config:
camio launch --preset balanced --os windows --url https://example.org
camio launch --preset hardened --os macos   --headless
camio launch --preset balanced --os linux   --dry-run       # prints the command
```

**Key flags:** `--preset {hardened|balanced|off}`, `--os {windows|macos|linux}`,
`--install-root`, `--profile`, `--headless`, `--dry-run`.
</details>

### 📬 5.2 Send, query, history, scope

<details>
<summary><code>camio send</code> &nbsp;·&nbsp; <code>camio query</code> &nbsp;·&nbsp; <code>camio history</code> &nbsp;·&nbsp; <code>camio scope</code></summary>

```bash
# Preview → confirm pattern (every send is preview-first):
camio send https://example.org
camio send https://example.org --confirm -H "X-Test: 1" --body '{"a":1}'
camio send https://example.org --confirm \
    --rewrite 'header=User-Agent|curl|Mozilla/5.0' \
    --rewrite 'url|http:|https:' \
    --preset hardened --json

# CamioQL (HTTPQL-compatible) over stored history:
camio query 'resp.code.gte:400 AND req.host.cont:"example"'
camio query 'req.method.eq:POST AND req.ext.eq:".js"' --limit 20 --json
camio query --save "4xx+on example" 'resp.code.gte:400 AND req.host.cont:"example"'
camio query --list-saved
camio query --saved "4xx+on example"
camio query --delete-saved "4xx+on example"

camio history --limit 50
camio history --json

# Scope dry-run (SSRF guard demo):
camio scope http://169.254.169.254/           # → blocked
camio scope https://example.org --scope-include 'host.eq:"example.org"'
camio scope https://example.org --allow-private
```

**`send` flags:** `-X --method`, `-H --header`, `--body`, `--body-file`,
`--preset`, `--scope-include`, `--scope-exclude`, `--allow-private`,
`--rewrite PART|FIND|REPLACE` where `PART ∈ {url,method,body,header=NAME}`,
`--confirm`, `--db`, `--json`.
</details>

### 🧪 5.3 Convert / Decoder / Comparer / Diff / JWT

<details>
<summary><code>camio convert</code> &nbsp;·&nbsp; <code>camio jwt</code> &nbsp;·&nbsp; <code>camio compare</code> &nbsp;·&nbsp; <code>camio diff</code></summary>

```bash
camio convert --list                          # every transform
camio convert 'base64,gzip'              --input "hello"
camio convert 'base64-decode'            --input "aGVsbG8="
camio convert 'url,base64'               --input "a b&c=d"
camio convert 'md5'                      --input "pw"
camio convert 'sha256'                   --input-file secrets.txt --raw-out | xxd | head
camio convert 'gzip,base64'              --input "payload" --raw-out > b64.gz.txt

camio jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig

camio compare old.txt new.txt                 # unified line diff
camio compare --bytes old.bin new.bin         # byte-level summary
camio compare --context 10 a.html b.html

camio diff 1023 1024                          # diff two STORED exchanges' responses
camio diff 1023 1024 --request                # diff the requests instead
camio diff 1023 1024 --context 6 --db camio.db
```
</details>

### 🔎 5.4 Scanning — passive and active

<details>
<summary><code>camio scan</code> &nbsp;·&nbsp; <code>camio activescan</code> &nbsp;·&nbsp; <code>camio findings</code> &nbsp;·&nbsp; <code>camio label</code></summary>

```bash
# ── Passive (safe, no network) ────────────────────────────────────────
camio scan --list-checks
camio scan 'resp.code.lt:400' --db camio.db --save
camio scan 'req.host.cont:"api"' --only js-endpoints --only js-secrets --json
camio scan '' --exclude cookie-flags --min-severity medium
```

![active](https://img.shields.io/badge/active-destructive%20opt--in-d73a49?style=flat-square)

```bash
# ── Active (requires --confirm, scope-gated) ──────────────────────────
camio activescan 'https://example.org/item?id=1' --confirm --save

# Add OAST-driven blind-SSRF detection in one shot:
camio activescan 'https://example.org/url?next=http://x' --confirm --save \
  --oast-listen 0.0.0.0:8888 --oast-base oast.your-host.tld:8888 \
  --oast-settle-ms 2000

# Triage & organize:
camio findings --json
camio findings --set 42 --status confirmed --note "verified via repeater"
camio findings --set 42 --status false-positive

camio label --list
camio label --add 17 --label hot
camio label --remove 17 --label hot
camio label --show hot
```
</details>

### 🎯 5.5 Intruder / Discover / Payloads / Crawl

<details>
<summary><code>camio discover</code> &nbsp;·&nbsp; <code>camio payloads</code> &nbsp;·&nbsp; <code>camio fuzz</code> &nbsp;·&nbsp; <code>camio crawl</code></summary>

```bash
camio discover 'https://example.org/s?q=1&id=2'
camio discover 'https://example.org/api' -X POST \
   --body '{"name":"a","email":"b"}' --json

camio payloads                                # list packs
camio payloads sqli                           # show one pack's entries

# Four attack types — Burp-named:
camio fuzz 'https://example.org/item?id=§1§' \
   --attack sniper        --payloads sqli --budget 50 --confirm
camio fuzz 'https://example.org/l?u=§a§&p=§b§' \
   --attack battering-ram --payloads common --budget 100 --confirm
camio fuzz 'https://example.org/l?u=§a§&p=§b§' \
   --attack pitchfork     --payloads users --payloads passwords --budget 50 --confirm
camio fuzz 'https://example.org/l?u=§a§&p=§b§' \
   --attack cluster-bomb  --payloads users --payloads passwords --budget 500 --confirm

# Bounded same-origin crawler through the matched engine:
camio crawl https://target.example.com --max-pages 50 --confirm --db camio.db
camio crawl https://target.example.com --cross-origin --max-pages 200 --confirm
```
</details>

### 🧬 5.6 Sequencer / Sitemap

<details>
<summary><code>camio sequencer</code> &nbsp;·&nbsp; <code>camio sitemap</code></summary>

```bash
camio sequencer --file tokens.txt
seq 1 1000 | sha256sum | awk '{print $1}' | camio sequencer --json

camio sitemap --db camio.db
camio sitemap 'req.host.cont:"example"' --limit 10000 --json
```
</details>

### 📥 5.7 Import / Reporting / Backup

<details>
<summary><code>camio import</code> &nbsp;·&nbsp; <code>camio backup</code> &nbsp;·&nbsp; <code>camio verify-bundle</code></summary>

```bash
camio import capture.har             --db camio.db
camio import burp-export.xml         --db camio.db --dry-run --json

camio backup camio-backup.db         --db camio.db
camio verify-bundle review-evidence.json
```
</details>

### 🧑‍⚖️ 5.8 Workbench — review workflows and evidence

<details>
<summary><code>camio workbench …</code></summary>

```bash
# ── Reporting ─────────────────────────────────────────────────────────
camio workbench --db review.db summary
camio workbench --db review.db rename "ACME scope 2026-Q4"
camio workbench --db review.db backup review-backup.db

# ── History / inspection ──────────────────────────────────────────────
camio workbench --db review.db history --limit 100
camio workbench --db review.db inspect 42          # headers + 64 KiB body preview

# ── Imported evidence ─────────────────────────────────────────────────
camio workbench --db review.db import-evidence httpx observations.jsonl
camio workbench --db review.db import-evidence nuclei findings.jsonl --preview
camio workbench --db review.db import-evidence raw  anything.txt
camio workbench --db review.db artifacts
camio workbench --db review.db observations 12
camio workbench --db review.db endpoint-evidence 17

# ── Asset inventory ───────────────────────────────────────────────────
camio workbench --db review.db inventory --filter example
camio workbench --db review.db asset <id>

# ── Review tasks + versioned plans ────────────────────────────────────
camio workbench --db review.db review --query 'resp.code.gte:400' --save
camio workbench --db review.db review-checks
camio workbench --db review.db workflow list
camio workbench --db review.db workflow save 'Error responses' review-plan.json
camio workbench --db review.db workflow show 1 --version 1
camio workbench --db review.db workflow run  1 --version 1
camio workbench --db review.db workflow run  1 --version 1 --archive capture.har
camio workbench --db review.db tasks
camio workbench --db review.db task 1
camio workbench --db review.db cancel 1

# ── Report exports (Markdown, JSON, HTML, SARIF 2.1.0) ────────────────
camio workbench --db review.db review-report 1 --format markdown
camio workbench --db review.db review-report 1 --format html   > review.html
camio workbench --db review.db review-report 1 --format sarif  > findings.sarif
camio workbench --db review.db review-bundle 1 > review-evidence.json

# ── Triage ────────────────────────────────────────────────────────────
camio workbench --db review.db triage <id> --status confirmed --note "repro'd"
camio workbench --db review.db report --format markdown --status confirmed
```

A minimal review plan document:
```json
{"schema_version":1,"query":"resp.code.gte:400","limit":200,"save":true}
```
</details>

### 🌐 5.9 Proxy / OAST / External integrations

<details>
<summary><code>camio proxy</code> &nbsp;·&nbsp; <code>camio oast</code> &nbsp;·&nbsp; <code>camio nuclei</code> &nbsp;·&nbsp; <code>camio subfinder</code> &nbsp;·&nbsp; <code>camio integrations</code></summary>

```bash
# ── Plain HTTP intercept, HTTPS blind-relay (fingerprint-true) ────────
camio proxy --listen 127.0.0.1:8080 --db camio.db --auto-scan \
   --scope-include 'host.eq:"target.example.com"' \
   --rate-limit 10

# ── TLS MITM (fingerprint-changing — honestly tagged) ─────────────────
camio proxy --export-ca camio-ca.pem                       # one-shot CA export
camio proxy --tls-intercept --db camio.db \
   --scope-include 'host.eq:"target.example.com"' \
   --rewrite 'resp-header=Content-Security-Policy|*|' \
   --rewrite 'resp-header=X-Frame-Options|*|'              # strip framing header
camio proxy --tls-intercept --ca-name "Internal Root CA" --ca-dir /path/to/ca
camio proxy --tls-intercept --upstream-proxy http://127.0.0.1:8081 --quiet
camio proxy --tls-intercept --upstream-proxy socks5://127.0.0.1:1080

# ── Self-hosted OAST collector ────────────────────────────────────────
camio oast --listen 0.0.0.0:8888 --base oast.your-host.tld:8888
camio oast --tokens 3                                      # print sample tokens, exit

# ── Nuclei (external, bounded runner, normalized Findings) ────────────
camio nuclei https://target.example.com --tag tech --confirm --save
camio nuclei https://target.example.com --severity high --severity critical \
   --rate-limit 30 --timeout-secs 300 --confirm --save -- -t exposures/

# ── subfinder (external, passive OSINT) ───────────────────────────────
camio subfinder example.com --all --timeout-secs 180 --json
camio subfinder example.com --source crtsh --source hackertarget

# ── Which external tools are installed? ───────────────────────────────
camio integrations
```

**Proxy flag reference:**

| Flag | Default | Notes |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | Point browser here. |
| `--tls-intercept` | off | Terminates HTTPS with Camio's CA. Fingerprint-changing. |
| `--ca-dir` | `$XDG_CONFIG_HOME/camio` | Persisted `camio-ca.pem` / `camio-ca.key` (0600). |
| `--ca-name` | `Internal Root CA` | Neutral by default — doesn't announce the proxy. |
| `--export-ca PATH` | — | Write the CA and exit. Trust it in the browser/OS. |
| `--auto-scan` | off | Runs the passive scanner on in-scope captures. |
| `--upstream-proxy URL` | — | Chain through Burp/ZAP/SOCKS5 (engine traffic only). |
| `--rate-limit N` | 0 (unlimited) | Per-host req/s cap for engine-forwarded sends. |
| `--rewrite PART\|FIND\|REPLACE` | — | `PART ∈ {url,method,body,header=N,resp-header=N,resp-body,status-reason}`. |
| `--quiet` | off | Suppress per-exchange log line. |
</details>

### 🤖 5.10 AI assistant

<details>
<summary><code>camio ai</code></summary>

```bash
export NVIDIA_API_KEY=nvapi-...          # or OPENAI_API_KEY, or run Ollama locally
camio ai --provider nvidia-nim "explain the risks in a reflected 'next' param"
camio ai --provider openai   --model gpt-4o-mini "summarize this exchange"
camio ai --provider ollama   --model llama3 "what is JWT alg none?"
camio ai --camioql "find 5xx responses from the api host"
camio ai --system "You are a pentest coach." "triage this reflected XSS"
```

> [!WARNING]
> Keys are **read from the environment only** — never from a file, never
> logged, never serialized. `AiConfig` redacts its `Debug`.
</details>

### 🪟 5.11 UIs — native, web, MCP

<details>
<summary><code>camio app</code> &nbsp;·&nbsp; <code>camio ui</code> &nbsp;·&nbsp; <code>camio mcp serve</code></summary>

```bash
camio app                                 # native egui/eframe desktop app
camio app --db review.db --preset hardened --allow-active

camio ui                                  # local web workbench (loopback)
camio ui --addr 127.0.0.1:8787 --db review.db
# Open the session URL printed in the terminal.

camio mcp serve                           # stdio JSON-RPC for an agent
```

Native-app deep-links (env-var driven):

```bash
CAMIO_SURFACE=proxy       camio app       # open directly on the Proxy surface
CAMIO_SURFACE=repeater    camio app
CAMIO_THEME=sentinel-blue camio app       # force a theme preset
CAMIO_THEME=antigravity   camio app
CAMIO_THEME=librewolf     camio app
```
</details>

---

## 6. Feature combos — recipes for common workflows

> [!TIP]
> Copy-paste these as a starting point, then adapt the scope filters.

### 6.1 🟦 Full pentest kit, one shell

```bash
# terminal 1 — proxy w/ TLS MITM + auto-scan + match&replace
camio proxy --tls-intercept --auto-scan --db work.db \
  --scope-include 'host.eq:"target.example.com"' \
  --rewrite 'resp-header=Content-Security-Policy|*|'

# terminal 2 — OAST listener reachable from the target
camio oast --listen 0.0.0.0:8888 --base oast.your-host.tld:8888

# terminal 3 — native workbench on the same project DB
camio app --db work.db --preset balanced --allow-active
```

### 6.2 🟩 Reproducible CI-style passive review

```bash
camio import capture.har --db review.db
camio workbench --db review.db workflow save 'Baseline' review-plan.json
camio workbench --db review.db workflow run 1 --version 1
camio workbench --db review.db review-report 1 --format sarif > findings.sarif
camio workbench --db review.db review-bundle 1 > evidence.json
camio verify-bundle evidence.json
```

### 6.3 🟪 OAST-driven blind SSRF

```bash
camio oast --listen 0.0.0.0:8888 --base oast.your-host.tld:8888 &
camio activescan 'https://target.example.com/fetch?u=http://x' --confirm --save \
  --oast-listen 127.0.0.1:8888 --oast-base oast.your-host.tld:8888 \
  --oast-settle-ms 2000
```

### 6.4 🟨 Chained upstream proxy (Camio → Burp)

```bash
# Burp on :8081, Camio on :8080; browser points at Camio.
camio proxy --tls-intercept --listen 127.0.0.1:8080 \
  --upstream-proxy http://127.0.0.1:8081 --db work.db
```

### 6.5 🟥 Pure library embed (no network, no TLS)

```bash
# A downstream crate wants only CamioQL + scope + storage, no HTTP stacks:
cargo add camio-core camio-store --no-default-features
cargo add camio-request --no-default-features
cargo add camio-proxy   --no-default-features   # also drops tls-intercept
```

### 6.6 🧱 Library embed with engine but no TLS MITM

```bash
cargo add camio-proxy --no-default-features --features engine
# ⇒ HTTP proxy + blind HTTPS CONNECT tunnel, upstream through the matched engine,
#   no server-side TLS stack pulled in.
```

---

## 7. Environment variables

| Variable | Scope | Effect |
|---|---|---|
| 🟦 `RUST_LOG` | runtime | Tracing filter. Try `camio=debug`, `camio_proxy=trace`, `camio_request=info`. |
| 🟦 `RUST_BACKTRACE` | runtime | `1` prints short backtraces on panic, `full` prints everything. |
| 🟪 `CAMIO_SURFACE` | `camio app` | Open the app directly on a surface (`proxy`, `repeater`, `intruder`, …). |
| 🟪 `CAMIO_THEME` | `camio app` | Force a theme preset (`sentinel-blue`, `antigravity`, `librewolf`, `midnight`, `mono`, `terminal`, `light`). |
| 🟨 `CAMIO_AI_PROVIDER` | `camio ai` | `nvidia-nim` · `openai` · `ollama` · `custom`. |
| 🟨 `CAMIO_AI_MODEL` | `camio ai` | Overrides the provider default. |
| 🟨 `NVIDIA_API_KEY` | `camio ai` | For `--provider nvidia-nim`. |
| 🟨 `OPENAI_API_KEY` | `camio ai` | For `--provider openai`. |
| 🟨 `OLLAMA_HOST` | `camio ai` | Non-default Ollama endpoint. |
| 🟥 `XDG_CONFIG_HOME` | storage | Where the proxy CA + `theme.json` + `prefs.json` live. Defaults to `~/.config`. |
| 🟥 `DISPLAY` / `WAYLAND_DISPLAY` | GUI | A real GL display is required (Xvfb's software GL does not work). |

---

## 8. Debugging — step by step

### 8.1 🧱 Local backtraces and logging

```bash
# Verbose traces, full backtrace, run from source for incremental rebuilds:
RUST_LOG=camio=debug,camio_proxy=trace RUST_BACKTRACE=full \
  cargo run -p camio-cli -- proxy --tls-intercept --db work.db

# Target a single crate:
RUST_LOG=camio_request=trace cargo run -p camio-cli -- send https://example.org --confirm
```

### 8.2 🧪 Reproduce a flaky test under a debugger

```bash
# 1. Build the test binary without running it:
cargo test -p camio-proxy --no-run

# 2. Find the exact executable (path is printed above):
test_bin=$(cargo test -p camio-proxy --no-run --message-format=json \
            | jq -r 'select(.profile.test==true) | .executable' | head -n1)

# 3. Run it under rust-gdb (install with `rustup component add rust-src`):
rust-gdb --args "$test_bin" tls_intercept::minted_leaf_valid_window --nocapture
```

### 8.3 🐞 VS Code / `codelldb` launch config

Drop this in `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "lldb",
      "request": "launch",
      "name": "Debug camio proxy",
      "cargo": { "args": ["build", "--bin=camio", "--package=camio-cli"] },
      "args": ["proxy", "--tls-intercept", "--db", "work.db"],
      "env": { "RUST_LOG": "camio=debug", "RUST_BACKTRACE": "1" },
      "cwd": "${workspaceFolder}"
    },
    {
      "type": "lldb",
      "request": "launch",
      "name": "Debug camio app",
      "cargo": { "args": ["build", "--bin=camio", "--package=camio-cli"] },
      "args": ["app"],
      "env": {
        "RUST_LOG": "camio_app=debug",
        "CAMIO_SURFACE": "proxy",
        "CAMIO_THEME": "sentinel-blue",
        "RUST_BACKTRACE": "1"
      },
      "cwd": "${workspaceFolder}"
    }
  ]
}
```

### 8.4 🖼️ GUI debugging on Linux

The native app needs a **real GL display**. On Kali the user's session is
usually `DISPLAY=:1` (Xvfb's software GL does NOT work — the window never
appears). To capture a screenshot of the running window:

```bash
# Find the window id by title:
wid=$(DISPLAY=:1 xwininfo -root -tree | awk '/"Camio"/ {print $1; exit}')

# Dump the window and convert to PNG:
DISPLAY=:1 xwd -id "$wid" -out camio.xwd
convert camio.xwd camio.png
```

> [!CAUTION]
> Never `pkill -f camio` from inside the shell — the pattern self-matches and
> kills the shell. Use the PID (`pidof camio` → `kill <pid>`) or stop the task
> from the harness.

### 8.5 📡 Debugging the proxy end-to-end

```bash
# 1. Export and trust the CA:
camio proxy --export-ca camio-ca.pem

# 2. Start the proxy with full trace + rewrite rules:
RUST_LOG=camio_proxy=trace camio proxy --tls-intercept --db dbg.db

# 3. Drive it with curl against the loopback proxy:
curl -x http://127.0.0.1:8080 --cacert camio-ca.pem -v https://example.com/

# 4. Inspect what landed in the project DB:
camio history --db dbg.db --limit 5
camio workbench --db dbg.db inspect <id>
```

### 8.6 🔥 Performance profiling

```bash
# Build with symbols, then flamegraph a hot path:
CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=true \
  cargo build --release -p camio-cli

cargo install flamegraph       # requires `perf` on Linux
sudo flamegraph -- ./target/release/camio scan --db big.db
```

### 8.7 🧯 Rescue recipes

| Symptom | Fix |
|---|---|
| ENOSPC during build | `rm -rf target/debug/incremental` |
| `cargo` not found | `export PATH="$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"` |
| `libxkbcommon` missing | Install system packages from §2 |
| SQLite busy / locked | Close the app; try `camio backup`, then operate on the backup |
| Proxy CA rejected by browser | Delete `~/.config/camio/camio-ca.*`, re-export, re-trust |
| MCP client cannot see tools | Launch with `camio mcp serve` on **stdio only** (no TCP wrapper) |

---

## 9. Tests, lints, and supply-chain gates

```bash
# ── Full test matrix (workspace, all features) ────────────────────────
cargo test --workspace --all-features

# ── Single-crate tests ────────────────────────────────────────────────
cargo test -p camio-proxy
cargo test -p camio-core -- --nocapture

# ── Lints (CI uses -D warnings) ───────────────────────────────────────
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

# ── Supply-chain gates ────────────────────────────────────────────────
cargo fetch                                   # populates the FULL cross-platform graph
cargo deny check                              # licenses, advisories, bans, sources
```

> [!IMPORTANT]
> `cargo-deny` needs every platform's manifests in `Cargo.lock` (egui pulls
> macOS/Windows crates). Always run `cargo fetch` **before** `cargo deny check`
> or the graph is incomplete.

---

## 10. Packaging, distribution, release

```bash
# ── Debian / Kali package ─────────────────────────────────────────────
dpkg-buildpackage -us -uc -b                  # consumes debian/

# ── Man page ──────────────────────────────────────────────────────────
man man/camio.1

# ── SBOM regeneration ─────────────────────────────────────────────────
scripts/gen-sbom.sh                           # → docs/SBOM.md

# ── Release tag flow ──────────────────────────────────────────────────
# See docs/RELEASING.md — the version is auto-bumped by a CI workflow
# (`chore(release): vX [skip ci]`). Don't pin internal path deps to an
# exact version; keep them as `version = "0"` so the bot's bump survives.
```

---

## 11. Troubleshooting index

<details>
<summary><strong>🔴 "linking with cc failed" or missing <code>-lxcb-*</code></strong></summary>

Install the system packages in §2. On headless servers you still need the
`-dev` packages even if you don't plan to run the GUI — `eframe` is a workspace
dep.
</details>

<details>
<summary><strong>🔴 "SQLite is locked" / "database is locked"</strong></summary>

Only one writer at a time. Close `camio app`, `camio ui`, and any running
`proxy` on that `--db`. If it persists, take a backup:

```bash
camio backup locked.db.copy --db locked.db
```
</details>

<details>
<summary><strong>🟡 Proxy is intercepting but TLS pages break</strong></summary>

You must trust `camio-ca.pem` in the browser (or OS trust store). Export it
fresh:

```bash
camio proxy --export-ca camio-ca.pem
```

Then import into Firefox → **Preferences → Privacy & Security → Certificates
→ View → Authorities → Import**. Mark it trusted for web sites.
</details>

<details>
<summary><strong>🟡 Native window never appears</strong></summary>

You're on a software-GL `Xvfb`. Switch to a real display — `DISPLAY=:1` on Kali
sessions, or run on the user's actual X/Wayland display.
</details>

<details>
<summary><strong>🟠 cargo-deny flags a RUSTSEC id you can't fix</strong></summary>

Add it to `deny.toml` with a reason:

```toml
[advisories]
ignore = [{ id = "RUSTSEC-YYYY-NNNN", reason = "transitive, no patched upstream yet" }]
```

cargo-deny 0.20+ needs `{ id = ... }` — not `{ crate = ... }`.
</details>

<details>
<summary><strong>🟠 Release bot broke resolution after a push</strong></summary>

It bumped `[workspace.package].version` but didn't touch internal path pins.
They're pinned to `version = "0"` for exactly this reason. Pull with rebase:

```bash
git pull --rebase
git push
```
</details>

---

## 12. Appendix — crate layout and feature graph

```
camio (binary, from camio-cli)
├── camio-core         ─ domain model + CamioQL + scope + policy + fingerprint + match-replace + sitemap
├── camio-engine       ─ Camoufox supervisor (download / unpack / locate / launch)
├── camio-request      ─ matched request engine  ◼ feature: impersonate (default)
├── camio-store        ─ SQLite history + content-addressed bodies
├── camio-convert      ─ Convert / Decoder / Comparer
├── camio-scan         ─ passive scanner (17 checks)
├── camio-automate     ─ Intruder: positions · packs · attack types · campaigns
├── camio-import       ─ Burp items XML + HAR importers
├── camio-sequencer    ─ token randomness / entropy
├── camio-active       ─ opt-in active scanner (XSS / SQLi / open redirect / OAST SSRF)
├── camio-ai           ─ OpenAI-compatible assistant (BYO key)
├── camio-proxy        ─ intercepting proxy  ◼ features: tls-intercept (default) · engine
├── camio-oast         ─ self-hosted OAST collector
├── camio-integrations ─ bounded runners for nuclei / subfinder / integration registry
├── camio-tasks        ─ thread-backed TaskManager (progress / cancel / result)
├── camio-app          ─ native desktop workbench (egui / eframe)
├── camio-web          ─ local loopback web UI
└── camio-mcp          ─ local MCP server over stdio
```

<div align="center">

---

**See also:**
[`README.md`](../README.md) · [`plan.md`](../plan.md) · [`docs/STEALTH.md`](./STEALTH.md) · [`docs/RELEASING.md`](./RELEASING.md) · [`docs/SBOM.md`](./SBOM.md) · [`docs/KALI_SUBMISSION.md`](./KALI_SUBMISSION.md)

![Camio](https://img.shields.io/badge/camio-fingerprint--transparent-1e80ff?style=for-the-badge&labelColor=020508)

</div>
