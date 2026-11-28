# camio-browser — a LibreWolf fork with Camoufox stealth + Camio branding

This directory is the **source-level scaffold** for Camio's own browser fork:

- **Base:** [LibreWolf](https://librewolf.net) (a privacy-hardened Firefox fork).
- **Stealth:** the [Camoufox](https://camoufox.com) C++ anti-fingerprinting
  patches (navigator/screen/WebGL/AudioContext/WebRTC/fonts spoofed below the JS
  layer — see [`../docs/STEALTH.md`](../docs/STEALTH.md)).
- **Branding/theme:** Camio's **black & blue** chrome (`branding/userChrome.css`,
  `branding/theme.json`) — black toolbars, light-blue text, `#1e80ff` blue
  buttons/accents, customizable by editing the palette.

## Camoufox source availability (important)

As of **2026-11**, the upstream Camoufox source repo (`github.com/daijro/camoufox`)
is **unavailable** — the maintainers' GitHub accounts were suspended (appeal
pending), and only **prebuilt binaries** remain (archived at
`github.com/jo-inc/camofox-browser/releases`). So the Camoufox **C++ patches can't
be fetched** right now. Two consequences:

- This fork builds **LibreWolf + Camio branding** (black/blue theme + pref-level
  stealth). Set `CAMOUFOX_REPO=<a reachable source mirror>` if/when one exists to
  merge the C++ patches.
- For Camoufox's **C++-level** stealth today, download a prebuilt Camoufox binary
  and point Camio at it (`camio launch --install-root …`, or the app's browser
  binary field) — Camio applies the same `user.js` + black/blue `userChrome.css`
  to it. See [`../docs/STEALTH.md`](../docs/STEALTH.md).

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

### In the cloud (recommended — "use GitHub to compile") ✅ proven

A dev laptop rarely has ~40 GB spare, so build it on GitHub Actions instead:
**Actions ▸ "Build camio-browser (fork)" ▸ Run workflow**
([`.github/workflows/browser.yml`](../.github/workflows/browser.yml)). It frees
the runner's disk, adds swap, installs the toolchain, runs `build.sh --full`, and
uploads the `camio-browser` artifact.

This **builds end-to-end in ~1h35m** on a stock `ubuntu-latest` runner and
produces **`camio-browser-<version>.en-US.linux-x86_64.tar.xz`** (~103 MB) plus a
**`camio-browser_<version>_amd64.deb`** — a rebranded LibreWolf with the
black/blue theme and extra hardening **baked in** (see "What's baked in" below).
It then **publishes a `browser-v<version>` GitHub release** with both files and
auto-generated notes (sizes + SHA-256 + install steps). The raw
`librewolf-*.tar.xz` is kept too. Two things make it fit a 16 GB / 4-core runner:
a **16 GB swapfile** and
**`--disable-debug-symbols`** — Firefox's `dom/bindings` / `dom/canvas` TUs OOM
the runner otherwise. Download from the run's **Artifacts**, or:

```sh
# Easiest: install the .deb from the browser-v<version> release
sudo apt install ./camio-browser_*_amd64.deb   # adds /usr/bin/camio-browser + menu entry
camio-browser

# Or the portable tarball
gh run download <run-id> -n camio-browser      # grabs the .tar.xz / .deb
tar xf camio-browser-*.tar.xz && ./camio-browser/librewolf
```

The `.deb` installs to `/opt/camio-browser`, puts a `camio-browser` launcher on
PATH (which the Camio app's own browser launcher now prefers), and registers a
`.desktop` entry + icon so it shows up as a real app.

### What's baked in

The product name is rebranded at the **source** level: before compile,
`inject_branding` overwrites the LibreWolf brand strings
(`browser/branding/*/locales/*/brand.ftl` + `brand.properties`) with
`branding/brand.ftl` / `brand.properties`, so the compiled binary reports
**"Camio Browser"** natively — About dialog, window title, menus and
notifications — not just in a renamed `application.ini`. (For a *prebuilt*
LibreWolf tarball that was never compiled here, `rebrand.sh` performs the same
swap inside `omni.ja` and clears the startup cache.)

The build's post-package step then turns the tarball into the Camio fork by
editing loose config files:

- `camio-userChrome.css` at the app root — the black/blue chrome.
- `camio-user.js` at the app root — the per-profile stealth baseline.
- `defaults/pref/camio-autoconfig.js` — disables the autoconfig *sandbox* so the
  `.cfg` can do file I/O.
- appended to LibreWolf's `librewolf.cfg`: `lockPref` enabling userChrome
  stylesheets + hiding the automation tell, extra `defaultPref` hardening (RFP,
  timer jitter, battery/netinfo/gamepad/beacon/DNS prefetch/predictor off), and
  a guarded snippet that copies `camio-userChrome.css` **and** `camio-user.js`
  into each profile on startup.

So the fork is rebranded + themed + stealth-preconfigured out of the box. (If a
profile-copy ever fails, Camio's launcher still applies the same theme +
per-persona fingerprint at run time, so there's no regression.)

Camoufox's C++ patches are skipped (upstream suspended), so this is a
**Camio-branded LibreWolf**; set the `camoufox_repo` input to a reachable source
mirror to merge them when one exists.

### Locally (needs the disk + hours)

```sh
# Requires: git, python3, a Firefox build toolchain (mach bootstrap), ~40 GB disk.
./build.sh              # prepare the scaffold (fetch LibreWolf + Camoufox + branding)
./build.sh --full       # best-effort end-to-end build (LONG)
./build.sh --help       # options (versions, jobs, branding-only)
```

Output: a branded `camio-browser` under `build/` that Camio can launch via its
usual `--install-root` / browser-binary path.

## Files

| File | Purpose |
|---|---|
| `build.sh` | Fetch LibreWolf + Camoufox, apply patches, inject branding, build, package, `.deb` |
| `rebrand.sh` | Rebrand LibreWolf → Camio in an unpacked tree: `application.ini` + `omni.ja` brand strings (idempotent) |
| `branding/brand.ftl` | Camio product-name strings (Fluent) compiled into the binary — About dialog, title bar, menus |
| `branding/brand.properties` | Same brand strings for legacy `.properties` consumers |
| `branding/userChrome.css` | The black/blue chrome theme (toolbar, tabs, popups, sidebar, findbar) |
| `branding/theme.json` | The color palette (edit to recolor; same values as the app's "Sentinel Blue") |
| `branding/camio.cfg` | `autoconfig` defaults — baked stealth prefs + `userChrome` enable (locked) |
| `branding/camio-user.js` | Per-profile `user.js` baseline; the `.cfg` copies it into every new profile |
| `branding/newtab.html` | Camio-branded start page (stage via `about:home → file://…/newtab.html`) |
| `branding/camio-browser.desktop` | Application-menu entry for the `.deb` |
| `branding/camio-browser.svg` | Icon used by the `.desktop` entry |
