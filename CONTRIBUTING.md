# Contributing to Camio

Thanks for your interest! Camio is a local-first, fingerprint-transparent web
security workbench in Rust. Contributions are welcome.

## Build and test

```bash
# First build compiles BoringSSL + bundled SQLite — a few minutes.
cargo build --workspace
cargo test  --workspace
```

The native app (`camio app`) needs a few system libraries for egui/eframe; on
Debian/Kali/Ubuntu:

```bash
sudo apt-get install -y libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
                        libxkbcommon-dev libwayland-dev cmake
```

## Checks that must pass (enforced in CI)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check          # advisories, licenses, bans, sources (see deny.toml)
```

- **Zero warnings.** `clippy -D warnings` is the gate; keep it clean.
- **New dependencies** must pass `cargo deny` (allowed license, no advisory) and
  be justified — Camio keeps a small, auditable dependency set (plan.md §14).
- **Tests next to code.** Each module carries a `#[cfg(test)] mod tests`; match the
  existing density and style.
- **One canonical model.** Route scope/policy decisions through `camio-core`
  (`Scope::decide`, `Policy::gate`) — never add a second path.
- **Header order and casing** are preserved on the wire everywhere; never sort or
  canonicalize HTTP headers.

## Scope and honesty

Camio measures fingerprint parity; it never claims invisibility. Keep that framing
in code, docs, and UI. See [SECURITY.md](./SECURITY.md) and [plan.md](./plan.md).

## Pull requests

Small, focused PRs with tests. Describe the behavior change and link the plan.md
section it advances. By contributing you agree your contribution is licensed under
the project's [MPL-2.0](./LICENSE).
