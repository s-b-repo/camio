# Security policy

Camio is a web-security testing workbench, so we hold it to a high bar — both in
how it is built and in how it must be used.

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue:

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on this
  repository, or
- open a minimal issue asking for a private contact if advisories are
  unavailable.

Include a description, affected version/commit, and a minimal reproduction.
We aim to acknowledge within a few days and to coordinate a fix and disclosure.
Please give us reasonable time to release a fix before public disclosure.

Do **not** include working exploits against third-party targets, credentials, or
other people's data in a report.

## Supported versions

Camio is pre-1.0; security fixes land on `main` and in the latest tagged release.

## Supply chain

- Dependencies are pinned via `Cargo.lock` and audited in CI by
  [`cargo-deny`](./deny.toml) (advisories, licenses, bans, sources) on every push
  and weekly, so newly published advisories are caught.
- The one deliberate heavy dependency is the BoringSSL-based impersonation stack
  (the matched request engine) — a stock Rust TLS stack would defeat Camio's
  fingerprint-transparency property. It is pinned and justified.
- No telemetry, auto-update, or external network calls happen without explicit
  operator action. The core manual workflow runs fully offline.

## Using Camio safely and lawfully

Camio is for **authorized testing only** — systems you own or have explicit,
documented permission to test.

- "Fingerprint transparency" means Camio does not add a *tool* tell on top of the
  browser. It is **not** a promise of undetectability, does not defeat a specific
  target's defenses, and does not rotate identities or proxies for evasion.
- Active/destructive checks, high-volume fuzzing, and external callbacks are
  **off by default** and require explicit confirmation and in-scope targets.
- An SSRF/safety guard blocks loopback, link-local, cloud-metadata and private
  destinations unless a lab profile explicitly opts in.
- The plugin system runs **arbitrary local commands** you configure; treat
  third-party plugins as untrusted code and review their manifest before running.

You are responsible for complying with all applicable laws and authorizations.
