# Configuration

Camio is configured by command-line flags and a small set of environment
variables — no config-file sprawl. Run `camio <command> --help` for the complete,
authoritative flags of any command; this page documents the cross-cutting ones.

## Workspace & storage

- **Database** — the SQLite workspace. Every command that touches history takes
  `--db <path>` (default **`camio.db`** in the working directory). Point multiple
  tools at the same file to share one workspace:

  ```sh
  camio --db ~/engagements/acme.db proxy --port 8080
  camio --db ~/engagements/acme.db scan
  camio --db ~/engagements/acme.db backup ~/engagements/acme.backup.db
  ```

- **Backups** — `camio backup <dest>` writes a consistent copy (safe while in use).

## Scope & policy

The single gate that governs every send (see [ARCHITECTURE.md](./ARCHITECTURE.md)):

- **Scope** — CamioQL include/exclude rules. With no includes, all non-guarded
  hosts are in scope. Repeatable `--scope-include` / `--scope-exclude` on traffic
  commands; check a URL with `camio scope <url>`.
- **SSRF guard** — loopback / link-local / cloud-metadata / private destinations
  are refused unless a lab profile opts in. Refusals are recorded as attempts.
- **Confirmation** — sends preview by default and require `--confirm` to go out;
  active/destructive checks are additionally off by default.

## Fingerprint & engine

- **OS persona** — `--os windows|macos|linux` renders a consistent identity
  across the browser prefs, engine overrides, and the matched request engine.
- **Engine overrides** — the managed browser receives Camoufox's engine-level
  config through chunked `CAMOU_CONFIG_*` environment variables (set by Camio;
  you do not set these by hand). Inspect the resulting spec with
  `camio fingerprint show` / `camio fingerprint spec`.
- **Install root** — `camio launch --install-root <dir>` points at a managed
  browser install; `--browser-binary` (or the app's field) selects an explicit
  LibreWolf / Camoufox / `camio-browser` binary.

## Proxy & CA

- `camio proxy --port <n>` — bind the intercepting proxy.
- `--tls-intercept` — terminate HTTPS with Camio's CA (off by default,
  fingerprint-changing). `--export-ca <file>` writes the CA to import into the
  browser; `--ca-name <name>` sets a neutral issuer name.
- `--auto-scan` — passively scan in-scope captures as they arrive.
- `--upstream-proxy <url>` — chain through another proxy; `--rate-limit <rps>`
  throttles.

## AI assistant (optional, BYO key)

Off by default; enabled only when a key is present in the environment. Nothing is
logged or persisted, and there is no telemetry.

| Variable | Purpose |
|---|---|
| `CAMIO_AI_PROVIDER` | `openai` \| `nvidia` \| `ollama` (OpenAI-compatible) |
| `CAMIO_AI_MODEL` | model id for the provider |
| `OPENAI_API_KEY` | key for the OpenAI provider |
| `NVIDIA_API_KEY` | key for NVIDIA NIM |

A local Ollama needs no key. See `camio ai --help` and
[AI-SAFETY.md](./AI-SAFETY.md) for the mediation guard.

## Native app & web UI

| Variable | Purpose |
|---|---|
| `CAMIO_SURFACE=<name>` | deep-link the app straight to a tool tab (e.g. `Proxy`, `Scanner`) |
| `CAMIO_THEME=<preset>` | pick a theme preset at launch (default `Sentinel Blue`) |
| `CAMIO_PAYLOADS_DIR=<dir>` | override where Intruder/payload packs are read from |

- **Theme file** — saved themes persist to `~/.config/camio/theme.json`
  (honours `XDG_CONFIG_HOME`). Edit colours/background in Workspace settings, or
  the file directly.
- **Web UI** — `camio ui` serves on loopback only; open the full session URL it
  prints (it carries the session token).

## External tools

`camio integrations` lists adapters (`nuclei`, `subfinder`, `httpx`, …) and
whether each is found on `PATH`. Install them separately; Camio runs them as
bounded subprocesses and normalizes their output into findings/assets.

---

For anything not listed here, `--help` on the command is the source of truth.
