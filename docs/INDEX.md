# Camio documentation

Camio is a **fingerprint-transparent web security workbench** — a Burp/Caido-class
toolkit (intercepting proxy, scanner, intruder, repeater, recon, OAST) built on a
managed anti-detection browser and a matched request engine, so that **tool
traffic shares one identity with the browser** and every destination passes one
scope-and-policy gate.

This index is the map. Start with **Install** and the **Quickstart**, then dive
into the area you need.

---

## Getting started

| Doc | What it covers |
|-----|----------------|
| [Install](#install) | One-line install, the `.deb` browser, build-from-source |
| [Quickstart](../README.md#quick-start) | The first commands to run (CLI + app + web) |
| [Features](./FEATURES.md) | **Every capability**, with its crate, CLI command, and app surface |

### Install

**Quickest — prebuilt binaries** (Linux/macOS, x86_64/aarch64):

```sh
curl -fsSL https://raw.githubusercontent.com/s-b-repo/camio/main/scripts/install.sh | sh
```

Installs the `camio` CLI (and `camio-app` GUI) to `~/.local/bin` (or
`/usr/local/bin` when writable). Pin a version with `CAMIO_VERSION=vX.Y.Z` or a
location with `CAMIO_BIN_DIR=/path`. The script verifies the release SHA-256.

**The themed browser fork** — install the `.deb` from the matching `browser-v*`
release (adds `/usr/bin/camio-browser` + a desktop entry):

```sh
sudo apt install ./camio-browser_*_amd64.deb && camio-browser
```

**From source** — see [the README Install section](../README.md#install) and
[`BUILDING.md`](./BUILDING.md).

---

## User guide

| Doc | What it covers |
|-----|----------------|
| [Features](./FEATURES.md) | Full capability catalog by workflow |
| [Anti-detection / stealth](./STEALTH.md) | Camoufox coverage map; pref-level vs C++-level limits |
| [Payload database](./PAYLOAD-DB.md) | The built-in payload catalog + how to extend it |
| [CamioQL](../README.md#camioql) | The HTTPQL-compatible query language used everywhere |

## Architecture & internals

| Doc | What it covers |
|-----|----------------|
| [Architecture](./ARCHITECTURE.md) | The 19-crate map, the single scope/policy path, data flow, CI/release |
| [Browser fork](../browser/README.md) | Building the Camio-branded LibreWolf fork (and the Camoufox-source caveat) |

## Operations & configuration

| Doc | What it covers |
|-----|----------------|
| [Configuration](./CONFIGURATION.md) | Environment variables, workspace/DB, scope & policy, theming, proxy & CA |
| [Releasing](./RELEASING.md) | How versions, tags, and release artifacts are produced |
| [SBOM](./SBOM.md) | Software bill of materials and how it is generated |

## Security & safety

| Doc | What it covers |
|-----|----------------|
| [AI safety](./AI-SAFETY.md) | The AI-mediation guard: session binding, action authorization, integrity |
| [Security policy](../SECURITY.md) | How to report a vulnerability |
| [Scope & honesty](../README.md#scope-and-honesty) | What Camio claims, and what it does not |

## Project

| Doc | What it covers |
|-----|----------------|
| [Contributing](../CONTRIBUTING.md) | How to build, test, and submit changes |
| [Changelog](../CHANGELOG.md) | Release history |
| [Kali submission](./KALI_SUBMISSION.md) | Packaging criteria mapping for Kali inclusion |

---

## Authorized use only

Camio is for **authorized** security testing — your own assets, or targets you
have explicit written permission to assess. Reads are free; sends require the
destination to be in scope and confirmed; active/destructive checks are off by
default. The SSRF guard blocks loopback/link-local/metadata/private destinations
unless a lab profile opts in. See [Scope & honesty](../README.md#scope-and-honesty).
