# Suggesting Camio for Kali Linux

This document makes Camio turnkey to propose for inclusion in Kali Linux. It
covers Kali's inclusion criteria, how Camio meets them, the packaging that ships
in this repo, and a ready-to-send request.

> Kali's exact submission mechanism changes over time. Always confirm the current
> process at <https://www.kali.org/docs/> ("Submitting tools to Kali" / the Kali
> policy pages) and on Kali's packaging GitLab at
> <https://gitlab.com/kalilinux/packages>. As of writing, new-tool requests are
> made by opening an issue / packaging request on Kali's GitLab, ideally with the
> requester helping with packaging.

## 1. Does Camio qualify?

Kali accepts tools that are free/open-source, useful for security work, actively
maintained, and reasonably packageable. Camio's fit:

| Kali criterion | Camio |
|---|---|
| **Free / open source (DFSG)** | MPL-2.0 (see `LICENSE`), a DFSG-free license already used in Debian/Kali (Firefox, Camoufox). |
| **Security relevance** | A web-security testing workbench (Repeater/Intruder/Scanner/Decoder/Comparer/Sequencer-class tools, Burp/HAR import, MCP) — core offensive-web tooling. |
| **Not a duplicate / adds value** | Unique differentiator: fingerprint-transparent tool traffic (matched BoringSSL engine pinned to the browser), plus a native UI, a web UI, and a built-in MCP server. |
| **Maintained** | Active repo, CI (build/test/clippy) and a weekly security audit (`cargo-deny`); pinned, audited dependencies. |
| **Packageable** | Rust workspace producing a single `camio` binary; ships a man page, a `.desktop` entry, and a `debian/` skeleton. |
| **Lawful / honest** | Authorized-use framing throughout; measures fingerprint parity, never claims undetectability; safe defaults (SSRF guard, confirmations, active checks off by default). |

## 2. What ships for packaging

- `LICENSE` — full MPL-2.0 text.
- `man/camio.1` — manual page for the `camio` binary (Debian policy requires one).
- `packaging/camio.desktop` — menu entry launching `camio app` (Development;Security).
- `debian/` — a packaging skeleton: `control`, `rules` (cargo build), `changelog`,
  `copyright` (DEP-5), `source/format`, `camio.manpages`, `camio.install`.
- `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- CI: `.github/workflows/ci.yml` and `security.yml`.

## 3. Packaging notes (the honest parts)

- **Vendoring.** Debian/Kali package builds are network-isolated. Camio is a Rust
  workspace, so package it with vendored crates: run `cargo vendor` and add a
  `.cargo/config.toml` pointing at the vendor directory, or build in a
  registry-enabled environment. The `debian/rules` here builds `--locked`; wire in
  the vendored source for an offline build.
- **Native build deps.** The desktop app needs `libxkbcommon-dev`, `libwayland-dev`,
  and the `libxcb-*-dev` set; the matched engine needs `cmake`/`clang` to build
  BoringSSL; `rusqlite` bundles SQLite. These are in `debian/control` Build-Depends.
  (A minimal package could ship only the CLI/MCP and make the GUI a separate
  binary/feature to reduce the dependency surface — a reasonable first package.)
- **The browser engine is separate.** Camoufox/LibreWolf is a large native engine
  managed outside the Rust dependency set; `Recommends: camoufox | librewolf`.
- **MSRV.** Current dependencies (rusqlite 0.42) need a recent `rustc`; Kali's
  toolchain satisfies this. Adjust the `rustc` Build-Depends version to match.

## 4. Pre-submission checklist

- [ ] A tagged release exists (`v0.1.0`) with a source tarball / git tag.
- [ ] `cargo build --release -p camio-cli` produces a working `camio`.
- [ ] `cargo test --workspace`, `cargo clippy -D warnings`, `cargo deny check` pass.
- [ ] `LICENSE`, man page, `.desktop`, and `debian/` are present.
- [ ] README states authorized-use scope and the measured-not-asserted claim.

## 5. Draft request (copy/paste)

> **Tool suggestion: Camio — fingerprint-transparent web security workbench**
>
> **Homepage / source:** https://github.com/s-b-repo/camio
> **License:** MPL-2.0 (DFSG-free)
> **Language:** Rust (single `camio` binary; optional native GUI)
>
> Camio is a free, local-first web security testing workbench built around the
> Camoufox anti-detect Firefox engine. Its differentiator is *fingerprint
> transparency*: tool-originated traffic (Replay, Intruder-class fuzzing,
> Scanner, MCP) is sent through a BoringSSL-based client whose JA3/JA4 and HTTP/2
> fingerprint is derived from and pinned to the same profile the managed browser
> uses — so authorized testing isn't blocked or distorted *because of the tool*.
>
> It includes a CamioQL (HTTPQL-compatible) query language, a passive scanner,
> bounded Intruder-class campaigns, Convert/Decoder/Comparer, Burp items XML and
> HAR import, a sequencer, a native desktop app and a loopback web UI, a plugin
> system, and a built-in MCP server — all under one shared scope + authorization
> policy with an SSRF guard and off-by-default active checks.
>
> It is FOSS, actively maintained, has CI plus a weekly `cargo-deny` security
> audit, and ships a man page, a `.desktop` entry, and a `debian/` packaging
> skeleton. I'm happy to help with packaging.

*Author's note:* before sending, confirm Camio builds from a clean checkout on the
target Kali release and that you are comfortable maintaining it, since Kali
expects tools to be kept current.
