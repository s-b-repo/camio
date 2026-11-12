# Camio

A local-first, **fingerprint-transparent** web security testing workbench — the speed
and UX of Caido, the depth of Burp, and testing traffic that doesn't stand out
*because of the tool*. Built in Rust around the [Camoufox](https://github.com/daijro/camoufox)
anti-detect Firefox engine. See [`plan.md`](./plan.md) for the full product plan.

> Status: **early scaffold**. The engine supervisor and fingerprint policy work
> end-to-end against the real browser. The proxy/capture layer, matched request
> engine, UI, and MCP server are not built yet (see plan.md §15 phases).

## What works today

- **Managed Camoufox engine** (pinned to `v158.0.1-beta.41`): download, unpack,
  locate, launch — no Node.js/Playwright server.
- **Fingerprint policy** (`camio-core`): a [Chameleon](https://github.com/sereneblue/chameleon)-inspired
  anti-detection policy that renders to Firefox `about:config` prefs **and**
  Camoufox engine-level overrides. Because Camio drives the browser (unlike a
  WebExtension), it can set real `about:config` prefs — strictly more powerful
  than the Chameleon extension.
- **No TLS MITM, no CA install** — the browser makes the real connection, so the
  server sees Camoufox's genuine fingerprint (plan §6).

### Anti-detection coverage (presets: `hardened` / `balanced` / `off`)

| Capability | Mechanism |
|---|---|
| Resist Fingerprinting (canvas/timezone/fonts/pointer) | `privacy.resistFingerprinting` (+ letterboxing) |
| First-party isolation | `privacy.firstPartyIsolation` |
| WebRTC leak protection / disable | `media.peerconnection.*` |
| Media-device hiding | `media.navigator.enabled` |
| WebGL vendor/renderer spoof | Camoufox engine config |
| Tracking protection (incl. fingerprinting/cryptomining) | `privacy.trackingprotection.*` |
| Do Not Track | `privacy.donottrackheader.enabled` |
| Referer trim / disable | `network.http.referer.*` |
| Cookie policy | `network.cookie.cookieBehavior` |
| **Hide `navigator.webdriver` without breaking automation** | `dom.webdriver.enabled=false` |
| Telemetry / phone-home silence | `toolkit.telemetry.*`, `app.normandy.*`, … |
| Tab-history limit | `browser.sessionhistory.max_entries` |
| UA / navigator / screen / timezone persona | `general.useragent.override` + Camoufox config |

## Quick start

```bash
# Build
cargo build

# Download the engine (once; ~1.3 GB) — or let `engine info` print the URL
curl -L -o vendor/camoufox/camoufox-lin-x86_64.zip \
  "$(./target/debug/camio engine info | awk '/download url/{print $4}')"

# Unpack it
cargo run -p camio-cli -- engine unpack

# Inspect the anti-detection policy
cargo run -p camio-cli -- fingerprint show --preset hardened --format user-js
cargo run -p camio-cli -- fingerprint show --preset balanced --format camoufox

# Launch the managed browser against an AUTHORIZED target
cargo run -p camio-cli -- launch --preset balanced --url https://example.org
```

## Workspace layout

```
crates/
  camio-core/     Fingerprint profiles + policy (Chameleon features, hardening)
  camio-engine/   Camoufox supervisor: unpack, locate, configure, launch
  camio-cli/      `camio` command-line interface
vendor/camoufox/  Pinned engine (gitignored; download separately)
plan.md           Full product plan
```

## Scope and honesty

Camio is for **authorized** testing only. "Fingerprint transparency" means Camio
does not add a tool tell on top of the browser — it is **not** a promise of
undetectability and does not defeat a specific target's bot defenses. Parity with
the real browser's fingerprint must be *measured* (plan §6.3, §17), not assumed;
the Camoufox engine-config key names here are provisional until verified against
the pinned build in the Phase-0 spike.

## License

Provisional **MPL-2.0** (Camoufox is MPL-2.0); final choice per plan §12.
