# Changelog

All notable changes to Camio are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project uses semantic
versioning once it reaches 1.0.

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
