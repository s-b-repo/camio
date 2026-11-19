# Camio architecture

Camio is a Rust workspace of focused crates behind one workbench. The design
holds to a few invariants, and everything else follows from them.

## Design invariants

1. **One identity.** Tool traffic (Repeater, Intruder, Scanner, crawler, MCP) is
   sent through the **matched request engine** (`camio-request`), whose
   TLS/JA3/JA4 + HTTP/2 fingerprint is derived from and pinned to the *same*
   profile the managed browser uses. Header order and casing are preserved on the
   wire — nothing is alphabetized.
2. **One gate.** Every destination passes a single `Scope` + `Policy` path in
   `camio-core`: reads are free, sends require in-scope + confirmed,
   active/destructive is off by default, and an SSRF guard blocks
   loopback/link-local/metadata/private unless a lab profile opts in. The proxy,
   CLI, app, and MCP server all call the same path.
3. **One store.** All exchanges land in one SQLite store (`camio-store`) with
   content-addressed, deduplicated bodies; metadata queries never load body bytes.
4. **Honesty over claims.** Parity is **measured, not asserted**; TLS
   interception is optional, off by default, and tagged fingerprint-changing;
   statistical results (Sequencer) are labelled as estimates.
5. **Local-first.** No accounts, no telemetry, no cloud dependency. OAST,
   AI keys, and the web UI are self-hosted / BYO / loopback.

## Crate map

```
                         ┌──────────────── interfaces ────────────────┐
  camio-cli   camio-app (egui)   camio-web (loopback)   camio-mcp (stdio JSON-RPC)
                         └──────────────────┬──────────────────────────┘
                                            │  (all share one storage + policy)
        ┌───────────────── capabilities ────┴───────────────────────────┐
  camio-proxy   camio-scan   camio-active   camio-automate   camio-oast
  camio-convert camio-sequencer   camio-import   camio-integrations   camio-ai
        └───────────────────────────┬───────────────────────────────────┘
                                    │
            ┌────────── engine + transport ──────────┐
       camio-engine (managed browser)   camio-request (matched engine)
            └───────────────┬────────────────────────┘
                            │
      ┌──────────── foundation ─────────────┐
   camio-core (fingerprint, scope, policy,   camio-store (SQLite history +
   CamioQL, model, match&replace, cvss,       content-addressed bodies)
   rate limiter, AI-guard)                    camio-tasks (background runtime)
      └──────────────────────────────────────┘
```

| Layer | Crates | Role |
|---|---|---|
| **Foundation** | `camio-core`, `camio-store`, `camio-tasks` | Shared types (fingerprint, scope, policy, CamioQL, model, Match & Replace, CVSS, rate limiter, AI-guard); indexed storage; the background-task runtime (states, progress, cooperative cancel, results) |
| **Engine + transport** | `camio-engine`, `camio-request` | Supervise/launch the managed Camoufox browser; send tool traffic through the matched BoringSSL engine |
| **Capabilities** | `camio-proxy`, `camio-scan`, `camio-active`, `camio-automate`, `camio-oast`, `camio-convert`, `camio-sequencer`, `camio-import`, `camio-integrations`, `camio-ai` | Proxy, passive/active scanning, Intruder, OAST, decode/diff, entropy, importers, external-tool adapters, the optional AI assistant |
| **Interfaces** | `camio-cli`, `camio-app`, `camio-web`, `camio-mcp` | The same capabilities over a CLI, a native egui window, a loopback web UI, and an MCP server |

The `browser/` directory is a separate build: a Camio-branded **LibreWolf fork**
compiled in CI (see [browser/README.md](../browser/README.md)).

## Data flow

```
  sources ───────────────▶ matched engine ──▶ store ──▶ analysis ──▶ review
  • managed browser          (camio-request)    (SQLite)   • passive scan   • CamioQL
  • proxy capture            scope + policy      dedup      • active scan    • site map
  • Repeater / Intruder      gate (camio-core)   bodies     • sequencer      • findings
  • crawler / import                                        • CVSS rank      • labels / diff
```

A request originates from a source, is scope-decided and policy-gated, is sent
with the matched fingerprint (or blind-relayed for browser TLS), is captured to
the store tagged by `source`, and becomes available to the analysis tools and the
review surfaces — all keyed by the same CamioQL.

## Feature flags

Defaults enable everything; constrained builds can trim:

- `camio-proxy`: `default = ["tls-intercept", "engine"]` — drop with
  `--no-default-features` for a pure HTTP proxy + blind HTTPS tunnel.
- `camio-request`: `default = ["impersonate"]` — the BoringSSL backend; drop for
  a no-network spec/dry-run core.

## Build, CI & release

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | push / PR | fmt, clippy (`-D warnings`), tests — all `--all-features` |
| `security.yml` | push / schedule | `cargo-deny` (advisories/licenses/bans/sources) + SBOM |
| `release.yml` | push to main | version bump + tag via the reusable release workflow |
| `release-binaries.yml` | release published / dispatch | compile `camio` + `camio-app` **`--all-features`** for linux/macOS × x86_64/aarch64 and attach to the release |
| `browser.yml` | manual dispatch | compile the LibreWolf fork → rebrand to `camio-browser` → `.deb` → `browser-v*` release |
| `maintenance.yml` | weekly / dispatch | `cargo clippy --fix` + `fmt`, opening a PR with any source fixes |

See [RELEASING.md](./RELEASING.md) and [SBOM.md](./SBOM.md).
