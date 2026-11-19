# camio-browser — a LibreWolf fork with Camoufox stealth + Camio branding

This directory is the **source-level scaffold** for Camio's own browser fork:

- **Base:** [LibreWolf](https://librewolf.net) (a privacy-hardened Firefox fork).
- **Stealth:** the [Camoufox](https://camoufox.com) C++ anti-fingerprinting
  patches (navigator/screen/WebGL/AudioContext/WebRTC/fonts spoofed below the JS
  layer — see [`../docs/STEALTH.md`](../docs/STEALTH.md)).
- **Branding/theme:** Camio's **black & blue** chrome (`branding/userChrome.css`,
  `branding/theme.json`) — black toolbars, light-blue text, `#1e80ff` blue
  buttons/accents, customizable by editing the palette.

## Honest status

This is **tooling + branding**, not a prebuilt binary and not a pre-merged tree.
Building a Firefox-family browser needs a machine with **~40 GB free disk and
hours of CPU** (plus a `mach bootstrap` toolchain). It is **not** built in the
Camio dev environment (which is disk-constrained), and no browser binary is
committed. Camio itself does **not** require this fork: it drives any
Firefox-family binary (LibreWolf preferred, then Camoufox) and applies the
`user.js` + `userChrome.css` from `camio-app/src/browser.rs` at launch, so you
get the black/blue theme + pref-level stealth on a stock LibreWolf today, and the
full C++-level stealth when you point it at a Camoufox (or this) build.

Merging two Firefox forks is not a one-click operation — LibreWolf and Camoufox
patch the *same* Firefox tree differently, so `build.sh` pins compatible versions
and applies patches in order, but expect to **reconcile a conflict or two** per
Firefox uplift. Treat `build.sh` as an automated runbook, not a guarantee.

## Build

```sh
# Requires: git, python3, a Firefox build toolchain (mach bootstrap), ~40 GB disk.
./build.sh            # fetch LibreWolf + Camoufox, apply patches + branding, build
./build.sh --help     # options (versions, jobs, branding-only)
```

Output: a branded `camio-browser` under `build/` that Camio can launch via its
usual `--install-root` / browser-binary path.

## Files

| File | Purpose |
|---|---|
| `build.sh` | Fetch LibreWolf + Camoufox, apply patches, inject branding, build |
| `branding/userChrome.css` | The black/blue chrome theme (fork default) |
| `branding/theme.json` | The color palette (edit to recolor; same values as the app's "Sentinel Blue") |
| `branding/camio.cfg` | `autoconfig` defaults (enable userChrome, set theme) |
