# Camio — Feature Completion, Framework Integrations, and UX Plan

**Status:** Proposed implementation roadmap; no feature is marked complete by this document.

**Prepared:** 2026-11-17, against repository commit `3a88d02`.

**Scope:** Finish the capabilities in [plan.md](./plan.md), integrate Nuclei, ProjectDiscovery httpx, and `s-b-repo/rustploit`, and improve the native and local web interfaces.

This document turns the existing product vision into an implementation backlog with dependencies and acceptance criteria. Keep [plan.md](./plan.md) as the product/design reference. Use this file to sequence delivery and track completion. The baseline below comes from source inspection; runtime behavior and performance have not been validated as part of this planning change.

## 1. Intended outcome

Camio should provide one continuous workflow: create a project, define authorized targets, capture browser traffic, discover endpoints and inputs, prepare bounded tests, run native or external tools, inspect evidence, reproduce findings, and export a report.

The operator should be able to start a saved workflow from the GUI, CLI, local API, or MCP and receive the same task IDs, results, scope decisions, limits, and cancellation behavior. Integration output should become searchable project data rather than terminal text pasted into a panel.

All implemented Camio features remain free and local-first. External binaries remain optional. Existing manual tools must work when no external framework, cloud account, or AI provider is installed.

## 2. Source-reviewed baseline and concrete gaps

| Area | Present in the repository | Work still needed |
|---|---|---|
| Native application | `camio-app` has 24 surfaces, themes, browser launch, and process plugins. | Cohesive navigation, shared editors, selectable result rows, background jobs, task controls, and persisted workspaces. |
| Local web UI | `camio-web` serves a static interface and JSON endpoints. | Long operations currently run in the sequential server loop; task streaming and several desktop capabilities need API/UI coverage. |
| Request engine | `camio-request` provides an impersonating transport and a dry-run fallback. Automatic redirects are disabled. | Measured browser parity, bounded response handling, centralized destination enforcement, and explicit send failure when the real transport is unavailable. |
| Browser | `camio-engine` and the desktop browser launcher configure and launch browser processes. | Working BiDi capture/control, interception queues, named profiles, lifecycle recovery, and a tested protocol capability matrix. |
| Scope and policy | `Scope::decide` and `Policy::gate` centralize include/exclude and action-class decisions. | Empty include lists currently permit public destinations; automation needs explicit project targets. DNS/connect-time checks, shared rates, approval records, and audits are still needed. |
| History/storage | `camio-store` persists exchanges, deduplicated bodies, and findings in SQLite. | Versioned migrations, projects/profiles/tasks/assets/workflows, cursor pagination, indexed query planning, and retention controls. |
| Query performance | Metadata queries avoid reading stored body blobs. | Queries still walk records and evaluate CamioQL in Rust; metadata reads allocate zero-filled bodies of the original length. Replace this with body-length metadata and lazy body access. |
| Native campaigns | Four attack modes, payload sets, projected counts, input discovery, and result classification exist. | Shared execution service, incremental generation, pacing, global/per-host limits, streaming, cancellation, checkpoints, and durable results. |
| Discovery | Query/form parameters, cookies, selected headers, and top-level JSON scalar fields are parsed. | Nested JSON, paths, XML, multipart/uploads, GraphQL, WebSocket messages, schemas, and browser-observed inputs. |
| Scanning/findings | Passive checks and three opt-in active checks exist; findings can be stored. | Scan profiles, session handling, cross-run/tool deduplication, finding lifecycle, reproducibility, OAST, and report exports. |
| Extensions | Desktop plugins run configured commands with stdin/stdout. | Time/output limits, cancellation, explicit permissions, diagnostics, isolation, and a reusable integration host. Process separation alone does not restrict network/filesystem access. |
| MCP/AI | MCP exposes 16 tools and three resources; optional AI assistance exists. | Asynchronous task capabilities, workflow/integration coverage, project/profile controls, redaction, and consistent policy handling. |
| External integrations | No dedicated Nuclei, httpx, or Rustploit adapter appears in the reviewed workspace. | Build and validate the integration layer and each adapter. |

Primary implementation references: [desktop](./crates/camio-app/src/lib.rs), [web server](./crates/camio-web/src/lib.rs), [storage](./crates/camio-store/src/lib.rs), [scope](./crates/camio-core/src/scope.rs), [policy](./crates/camio-core/src/policy.rs), [campaigns](./crates/camio-automate/src/campaign.rs), [input discovery](./crates/camio-automate/src/discover.rs), [plugins](./crates/camio-app/src/plugins.rs), and [MCP](./crates/camio-mcp/src/lib.rs).

## 3. Delivery priorities and complete capability register

- **P0:** Dependencies and correctness required before unattended execution.
- **P1:** Requested integrations and the everyday testing workflow.
- **P2:** Remaining desktop, browser, protocol, and extension capabilities.
- **P3:** Headless/team deployment and final release readiness.

Priority determines order; it does not remove a feature from this roadmap.

Track each capability as `planned`, `in progress`, `partial`, `verified`, or `blocked`, with an implementation reference and acceptance evidence. The rows below start as `partial` when a source implementation exists and `planned` otherwise; neither status establishes runtime correctness.

| ID | Capability and completion scope | Baseline | Priority | Milestone |
|---|---|---|---|---|
| F01 | Projects, targets, settings, workspace persistence, backups, schema migrations | Partial | P0 | M0–M1 |
| F02 | Shared scope, destination validation, action policy, approvals, rates, budgets, audit | Partial | P0 | M1 |
| F03 | Durable background jobs, progress, cancellation, checkpoints, restart recovery | Planned | P0 | M1 |
| F04 | Managed browser lifecycle, isolated named profiles, snapshots, encrypted exports | Partial | P1 | M2, M6 |
| F05 | Browser-native capture, request/response pause/edit/continue/drop/replay | Planned | P1 | M2 |
| F06 | Measured fingerprint parity, profile versioning, truthful transport status | Partial | P0 | M0, M2 |
| F07 | Unified history/logger, indexed CamioQL, saved searches, large-history navigation | Partial | P1 | M1–M2 |
| F08 | Shared raw/structured/binary message editor and protocol-aware inspector | Partial | P1 | M2, M6 |
| F09 | Replay tabs/history, baselines, diff, session selection, redirect controls | Partial | P1 | M2 |
| F10 | Site map, crawl, annotations, full input discovery, OpenAPI/GraphQL imports | Partial | P1 | M2, M5–M6 |
| F11 | Payload catalog/provenance, campaign controls, classification and exports | Partial | P1 | M1, M5 |
| F12 | Visual workflows plus versioned text representation, validation and execution | Planned | P1 | M5 |
| F13 | Passive/active scanner profiles, sessions, exclusions, reproducible evidence | Partial | P1 | M4–M6 |
| F14 | Findings triage, cross-run/tool correlation, notes, retest, reports | Partial | P1 | M3–M5 |
| F15 | Self-hosted OAST collection, interaction correlation and retention | Partial | P2 | M6–M7 |
| F16 | Integration registry, httpx, Nuclei, Rustploit, compatibility fixtures | Planned | P1 | M3–M5 |
| F17 | Convert, Comparer, JWT, Sequencer sampling/reporting, reusable transforms | Partial | P2 | M2, M6 |
| F18 | Organizer/Library: saved exchanges, labels, notes, packs, profiles, extensions | Partial | P2 | M2, M6 |
| F19 | Burp/HAR migration, rule import, format-supported Caido migration | Partial | P2 | M6 |
| F20 | Permissioned extension host, versioned SDK, transforms/checks/actions/panels | Partial | P2 | M1, M7 |
| F21 | MCP capability coverage and optional AI-assisted explanations/planning | Partial | P1 | M1–M7 |
| F22 | Optional external-client proxy, CA lifecycle, upstream proxy, HTTP/2/WebSocket | Partial | P2 | M7 |
| F23 | Browser-assisted DOM inspection, clickjacking proof artifacts, visible instrumentation | Planned | P2 | M7 |
| F24 | Native GUI and web capability parity, onboarding, accessibility, layout/density | Partial | P1 | M2–M8 |
| F25 | Headless DAST, schedules, CI, deployment API, team/project access controls | Planned | P3 | M9 |
| F26 | Packaging, signed releases, SBOM/licenses, supported platforms, governance/docs | Partial | P3 | M0, M8–M9 |

Coverage includes every area in [plan.md §8](./plan.md#8-capability-coverage-matrix-parity-as-a-checklist-not-the-spine). A technical limitation must have a documented disposition and review; an unchecked item must not disappear behind an “all features complete” claim.

## 4. Shared architecture before adding tool buttons

Retain the Rust workspace and native egui/eframe application. Extract execution behavior from desktop event handlers, web routes, CLI commands, and MCP handlers into shared services. Start with modules; split into crates when dependencies and ownership justify the boundary.

| Proposed boundary | Responsibility | Existing code to reuse |
|---|---|---|
| `camio-service` | Project context, capability APIs, session selection, common planning/execution paths | `camio-core`, current shell handlers |
| `camio-tasks` | Scheduler, event stream, counters, checkpoints, cancellation, supervision | Existing core task types and storage |
| `camio-integrations` | Tool discovery, compatibility, adapters, subprocess management, result normalization | Process plugin mechanics, strengthened before reuse |
| `camio-workflows` | Typed workflow document, compiler, validator, executor | Campaign planner, transforms, CamioQL |
| `camio-browser` | Browser control channel, capture/intercept events, lifecycle integration | `camio-engine`, desktop browser launcher |
| Report module | Evidence bundles, Markdown/HTML/JSON/SARIF exports and templates | Findings, exchanges, artifact storage |

The native UI, web API, CLI, MCP, workflow executor, and extensions call the same capability service. Native requests pass through one authorized request gateway around `RequestEngine`. External adapters must declare and enforce their own transport boundary as described below.

### 4.1 Canonical persisted records

- Extend the current `Project`, `Target`, `Task`, `Finding`, and exchange models rather than creating unrelated integration-only versions.
- Add versioned records for browser profiles/snapshots, assets/endpoints, campaigns, workflow versions/runs, tool installations, integration runs, approval grants, annotations, and audit events.
- Every result carries project/run/task IDs, source adapter, tool version, timestamps, normalized target, scope-policy revision, and evidence references.
- Preserve raw external artifacts separately with hashes, parser/schema versions, retention settings, and access restrictions. Parse again without rerunning a scan.
- Add an external-tool source/provenance representation and separate transport metadata. A metadata-only asset observation is not a fabricated HTTP exchange; missing request/response data stays explicitly absent.
- Use additive, versioned SQLite migrations with backup/recovery tests. Add indexes and cursor pagination for the actual access patterns before performance claims.
- Preserve ordered/duplicate headers and body bytes when available; mark reconstructed or browser-observed data with its fidelity and source.

### 4.2 Task lifecycle and responsiveness

- [ ] Implement persisted states for queued, awaiting approval, running, paused, cancelling, cancelled, completed, failed, and interrupted tasks, with validated transitions.
- [ ] Return a task ID immediately for long operations; stream ordered progress/results through a bounded event channel. Provide pagination and reconnect cursors so clients do not load the whole run into memory.
- [ ] Move sends, campaigns, scans, imports, browser startup, and plugin/tool execution off the egui event thread and the web request loop. Reuse the existing background-AI pattern only as an interim step.
- [ ] Share project-wide and per-host concurrency/rate accounting across simultaneous native and external jobs. Include baselines, retries, redirects, and auxiliary probes in the appropriate counters.
- [ ] Generate campaign requests incrementally instead of materializing the complete request set before execution.
- [ ] Cancel cooperatively first, then terminate the supervised process tree after a short grace period. Prevent orphan grandchildren; use platform-appropriate process groups/job objects.
- [ ] Expose pause only when a real checkpoint exists. A tool without safe pause/resume support gets stop/restart controls and an honest capability label.
- [ ] On restart, reconcile interrupted jobs and retain partial output. Resume only unexecuted work with a still-valid plan/policy; never blindly replay uncertain mutating steps.
- [ ] Record success, timeout, cancellation, parser failure, scope denial, tool failure, and storage failure distinctly. Remove silent error swallowing from execution paths.

### 4.3 Scope, approvals, and enforceable limits

These requirements extend the existing [policy](./crates/camio-core/src/policy.rs) and [security policy](./SECURITY.md), and apply to all entry points.

- [ ] Require explicit project target selection before automated network tasks; do not treat the current empty-scope public-host default as permission for discovery or scanning.
- [ ] Use structured target descriptors for HTTP URLs and, when required, non-HTTP host/port/protocol targets. Extend the central scope evaluator rather than introducing tool-specific permission rules.
- [ ] Validate URL normalization, hostname boundaries, scheme, port, resolved IPv4/IPv6 addresses, connection destinations, and every redirect. Recheck queued work after scope changes; stop affected work when permission is revoked.
- [ ] Keep private/loopback labs available through explicit project configuration. Test allowed lab targets and blocked metadata/unapproved destinations separately.
- [ ] Bind approval to the plan hash, exact target set, action class, tool/template versions, session reference, maximum requests, rates, time limits, and policy revision. Reuse that approval only inside those bounds; changing them invalidates it.
- [ ] Preview counts as exact, bounded estimates, or unknown. An unknown count must not be displayed as a guaranteed limit. Enforce total attempts/time/bytes independently at the execution boundary.
- [ ] Keep high-impact modules, writes, credential testing, external callbacks, and arbitrary code execution outside default profiles. Reuse target-specific impact controls instead of enabling an entire framework indiscriminately.
- [ ] For external processes, combine reviewed configuration with a tested egress boundary or a mediated transport that actually enforces the project's restrictions. Input filtering and CLI rate flags alone are insufficient.
- [ ] Document limitations of that boundary: a TCP/CONNECT tunnel cannot enforce HTTP path rules or count encrypted requests. If required scope/budget controls cannot be enforced for a tool mode, offer artifact import and keep that execution mode unavailable.

## 5. Framework integration contract

### 5.1 Adapter and installation model

Each adapter exposes discovery/health, supported capabilities, input validation, plan generation, start, progress parsing, result parsing, cancel, and optional resume. Keep a versioned adapter manifest and a compatibility table; select flags and parsers from verified tool capabilities.

- [ ] Locate a user-configured executable or an explicitly installed/pinned distribution. Record its resolved path, version, checksum where available, supported platforms, and adapter version.
- [ ] Detect missing/incompatible tools and give actionable setup diagnostics. Do not install or update a framework merely because a project opens.
- [ ] Spawn with `std::process::Command` and structured argument arrays. Never pass target strings or imported data through a shell.
- [ ] Isolate each run's working/config/state/cache directories using tool-supported settings. Use a minimal environment with explicitly permitted credentials; do not repurpose the application's home/environment variables.
- [ ] Prevent inherited personal tool settings from enabling uploads, reporting providers, callbacks, or extra templates. Test effective configuration precedence for every supported version.
- [ ] Keep binary updates and template/catalog updates separate from scan execution. Pin revisions and invalidate affected saved plans when content changes.
- [ ] Bound stdout/stderr, line length, JSON nesting, artifact size, memory, CPU, open files, runtime, and disk usage. Apply backpressure while draining both output streams.
- [ ] Keep structured results separate from diagnostics. Preserve partial valid records and show malformed records as parser errors with redacted context.
- [ ] Use least-privilege sandboxing where supported. Display execution/isolation capabilities in integration settings; fail closed when a required restriction is unavailable.
- [ ] Add an integration contract suite using fake binaries and recorded output fixtures before running any real framework in a controlled lab.

### 5.2 Transport identity and evidence

External tools generally create their own connections. Passing browser headers or a proxy URL does not establish Camoufox TLS/HTTP-2 parity.

- Show `Browser`, `Camio matched engine`, `External tool`, and `External-client proxy` as distinct transport sources.
- Store measured fingerprint status independently from the tool name. Default external-tool parity to `unverified`; never inherit a green Camio parity badge.
- Record when an enforcing proxy changes transport behavior. A mediated run needs its own measured status and documented protocol limitations.
- Preserve evidence from the original run. A later Replay send is a new validation exchange with its own transport/session metadata.

## 6. ProjectDiscovery httpx integration

**Purpose:** Probe approved web targets and enrich the project inventory with reachability, response metadata, and technology observations. This is ProjectDiscovery's Go tool, not the Python HTTPX library. Its documented interface includes JSONL output, metadata probes, request-rate controls, redirect options, and update-check controls. Select the exact flags from the pinned version's help. [Official httpx usage](https://docs.projectdiscovery.io/opensource/httpx/usage).

- [ ] Accept targets from explicit project targets, imported lists, selected site-map nodes, saved CamioQL results, or upstream workflow outputs. Normalize and deduplicate while preserving explicit schemes and ports.
- [ ] Provide a Probe configuration panel for status, title, content type/length, server, technology observations, latency, IP/TLS metadata, and per-host/project limits.
- [ ] Stream JSONL into `Asset`/`Endpoint` observations and run results. Store tool observations separately from confirmed vulnerabilities.
- [ ] Disable automatic host expansion, scheme fallback, redirect following, and optional browser/screenshot activity unless those destinations/actions are in the approved plan. Expose supported modes explicitly.
- [ ] Revalidate every discovered URL before it can become a downstream network task. A redirect or certificate name does not expand scope automatically.
- [ ] Map available evidence faithfully; link to raw artifacts and offer Send to Replay, Scan, Nuclei, Workflow, and Organizer.
- [ ] Show unreachable targets, DNS/TLS failures, rate-limit responses, and cancellations as outcomes. Empty results alone do not mean a successful clean run.
- [ ] Apply explicit concurrency, rate, retry, timeout, response-size, and total-probe controls. Restrict auth forwarding to the selected origins.
- [ ] Provide an import-only path for existing httpx JSONL when execution is unavailable.

**Acceptance:** A controlled target set containing reachable, unreachable, redirected, excluded, and lab-private hosts produces the expected asset records. Excluded destinations receive zero traffic; progress remains live; cancel stops the process tree; reruns update inventory without duplicating assets.

## 7. Nuclei integration

**Purpose:** Run selected template checks against approved targets, retain evidence, and feed findings into Camio's triage workflow. Nuclei documents target-list input, template selection, JSONL output, statistics, and independent rate/concurrency controls. [Official Nuclei usage](https://docs.projectdiscovery.io/opensource/nuclei/running).

### 7.1 Template catalog and planning

- [ ] Inventory a pinned template directory/revision and record each selected template ID, content hash, source, protocol, tags, severity, references, and review status.
- [ ] Add search/filter controls for template ID, tag, severity, protocol, and observed technology, with a precise selection preview. Technology matching proposes templates; it does not silently execute them.
- [ ] Create project scan profiles with an explicit reviewed template set and impact classification. Severity is a finding property, not a measure of execution safety.
- [ ] Start with reviewed HTTP detection checks. Gate code, headless, file access, arbitrary networking, fuzzing, and OAST capabilities separately; classify unsupported template constructs as unsupported rather than assuming they are harmless.
- [ ] Validate templates and their dependencies before planning. Verify integrity/signatures when supported, while treating signing and operational review as separate checks.
- [ ] Estimate targets × template requests with retries/redirects/workflow expansion accounted for. Review unbounded/dynamic templates before unattended use and require enforceable runtime caps.
- [ ] Keep template browsing, validation, import, and explicit updates distinct from execution. Preserve the exact catalog revision for replayable plans.

### 7.2 Run management and results

- [ ] Build a structured invocation with explicit targets, selected templates, output mode, rates, host/template concurrency, retry/timeout settings, and redirect behavior.
- [ ] Isolate config and disable unapproved update/cloud/callback behavior. Keep a separate opt-in connector for a configured self-hosted OAST endpoint.
- [ ] Support origin-bound authenticated scans using project session references and tool-supported protected configuration. Avoid secrets in command previews, logs, and ordinary exports; remove temporary secret material on exit and startup recovery.
- [ ] Parse JSONL findings and progress into task events. Normalize template/matcher ID, target/location, severity, references/CWE/CVE when present, extracted evidence, timestamps, and available request/response artifacts.
- [ ] Make absent confidence/evidence explicit. A template match remains an external-tool observation until the project's validation/triage rules establish its status.
- [ ] Deduplicate repeated matches within a run and across reruns using stable rule/location identifiers. Correlate related native/Nuclei results without deleting their separate evidence or validation status.
- [ ] Support scan profiles, saved plans, cancellation, compatible checkpoints, raw artifact import, and retest. Retesting never launches unrelated templates.
- [ ] Show template validation errors, unsupported protocols, authentication failures, incomplete scans, and parser errors separately from “no findings.”

**Acceptance:** A small pinned lab template pack yields expected positive and negative results, preserves evidence/provenance, supports retest/import, and produces stable deduplication. Multi-request templates, redirects, callbacks, and retries remain inside approved limits. Cancellation and UI updates work during a run.

## 8. `s-b-repo/rustploit` integration

**Requested upstream:** [s-b-repo/rustploit](https://github.com/s-b-repo/rustploit). On 2026-11-17, public web retrieval failed and `gh repo view s-b-repo/rustploit` could not resolve the repository with the current access. This does not establish that the repository is absent. Its branch, CLI/API, modules, license, output schemas, and unattended-execution controls remain unverified. Do not invent command flags or claim working integration.

### 8.1 Discovery prerequisite

- [ ] Resolve upstream access/name and inspect README, license, manifests, source, releases, and documented invocation modes at a pinned commit.
- [ ] Record platform/build requirements, version/health commands, input/output schemas, module discovery, interaction requirements, cancellation behavior, and available network/resource restrictions.
- [ ] Determine whether a machine-readable CLI or local API exists. Prefer a stable subprocess/RPC boundary; share Rust code only if upstream offers a supported library with compatible licensing and lifecycle guarantees.
- [ ] If structured automation is missing, define a versioned bridge/schema against the reviewed upstream source. Prepare any upstream contribution locally; publication remains a separate action.
- [ ] Commit sanitized positive, negative, malformed, interrupted, and version-drift fixtures before exposing an execution action.

### 8.2 Planned operator workflow

- [ ] Expose verified modules in Integrations with descriptions, required options, supported target types, prerequisites, and impact labels.
- [ ] Provide typed option forms and validation; permit only adapter-supported options in unattended workflows. Persist presets with the upstream commit/module version.
- [ ] Let the operator send a selected target or finding to a compatible module, preview its complete scope/impact/limits, and run it as a supervised task.
- [ ] Automate approved verification/test modules within project policy. Import output into findings, evidence, and audit records with the exact module/version/target relationship.
- [ ] Keep interactive-only or unenforceable modes visibly unavailable for unattended execution. Preserve an import path for supported result artifacts.
- [ ] Keep high-impact operations separately gated; do not use a generic “run any command” field as the Rustploit adapter.

**Acceptance:** Once upstream is accessible, at least one reviewed module completes a controlled lab workflow through GUI, CLI/API, and MCP with reproducible evidence, bounded execution, denied out-of-scope targets, cancellation, and compatible-version tests. Until then, F16 remains partial even if Nuclei and httpx ship.

## 9. Additional frameworks through the same adapter system

Ship the three requested integrations first. Expand using the shared contract and actual workflow demand; a new tool should not require another execution engine or a separate result database.

| Candidate | Planned role | Initial boundary | Target milestone |
|---|---|---|---|
| [Katana](https://github.com/projectdiscovery/katana) | Crawl approved web applications and import discovered endpoints | Explicit crawl scope/depth/request limits; separate browser/headless capability review | M7 |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Obtain candidate subdomains for an approved project | Provider configuration and data-sharing consent; candidates do not become authorized targets automatically | M7 |
| [ffuf](https://github.com/ffuf/ffuf) | Optional external fuzzing runs and artifact import | Reuse campaign budgets, payload provenance, filters, and finding/evidence models | M7 |
| [Interactsh](https://github.com/projectdiscovery/interactsh) | OAST interaction collection/correlation | Self-hosted configuration first, protected project tokens, explicit callback approval | M6–M7 |
| Other tools | Versioned adapter SDK and import-only connectors | Verify upstream CLI/schema/license and pass the same contract suite before execution support | After M7 |

The roles above are proposed Camio integrations. Exact supported versions, flags, and formats must be confirmed in each adapter's discovery task.

## 10. Automated campaigns and visual workflows

### 10.1 Shared workflow representation

- [ ] Define a versioned, typed workflow document usable by the native node editor, text editor, CLI, API, and MCP. Keep execution independent of the visual layout.
- [ ] Initial node types: project targets/query, scope filter, deduplicate, httpx probe, discover inputs, native passive scan, approved Nuclei run, approved Rustploit module, bounded native campaign, classify, findings upsert, and report export.
- [ ] Add variables, typed input/output mappings, bounded fan-out, explicit conditions, timeouts, error branches, and per-node/run budgets. Reject incompatible edges and unbounded cycles.
- [ ] Compile and preview the complete plan before sending traffic. Distinguish offline transforms from network nodes; show external data transfers and credential references where relevant.
- [ ] Allow a saved workflow approval to cover its bounded child actions. New targets, modules/templates, greater limits, or changed scope require a revised plan.
- [ ] Persist workflow versions, node state, counters, inputs/outputs, artifact references, and stop reasons. Make dependency failures and skipped branches visible.
- [ ] Support scheduling only after resumability, duplicate-run prevention, policy revalidation, and durable task execution pass acceptance.

### 10.2 Campaign completeness

- [ ] Extend discovery to nested JSON/arrays, URL path segments, XML, multipart forms/uploads, GraphQL inputs, WebSocket messages, imported schemas, and browser fetch/XHR observations.
- [ ] Preserve input location/type so mutations round-trip correctly; add per-context encodings and payload previews.
- [ ] Finish built-in/file payload management with filtering, deduplication, transforms, source/commit/hash/license manifests, safe extraction, and explicit updates.
- [ ] Add method selection with separate controls for state-changing or tunnel methods; retain browser method/header limitations and show the chosen transport.
- [ ] Classify against saved baselines using status/body/header/length/timing/redirect/reflection/network-error/OAST signals. A `200` response alone is not a confirmed vulnerability.
- [ ] Stream results into filterable/sortable tables, with saved CamioQL filters, CSV/JSON export, and Send to Replay/Comparer/Organizer.

### 10.3 Starter workflows

1. **Inventory:** selected project targets → scope check → httpx → deduplicate → asset inventory.
2. **Detection:** selected inventory → approved Nuclei profile → normalize evidence → findings triage.
3. **Traffic review:** captured exchanges → passive checks → candidate findings → operator review.
4. **Input testing:** selected exchange/schema → input discovery → campaign preview → bounded campaign → baseline comparison.
5. **Verification:** selected finding → compatible reviewed Rustploit module → bounded verification task → evidence and finding update.
6. **Reporting:** selected findings/run → redact → evidence bundle → Markdown/HTML/JSON/SARIF export.

Discovery and tool output never authorize new targets by themselves. Verification runs only after its required module and target approval is represented in the plan.

## 11. GUI, UI, and UX redesign

### 11.1 Navigation and layout

Consolidate the current surfaces into a project-oriented shell while preserving direct access to existing tools.

| Primary destination | Contents |
|---|---|
| Overview | Project context, target scope, capture status, recent work, tasks, findings summary |
| Capture | Live history, shared CamioQL bar, intercept queue, Match & Replace, exchange inspector |
| Replay | Request tabs, send history, baselines, response comparison, session/transport selection |
| Discover | Asset/site-map views, inputs, schemas, crawl, httpx results, annotations |
| Automate | Native campaigns, payload selection, visual/text workflows, scheduled runs when available |
| Scan & Findings | Native checks, Nuclei profiles, triage, evidence, validation, reporting |
| Integrations | Tool/module catalog, installed versions, health, configuration, run history, diagnostics |
| Library | Saved requests, notes, queries, transforms, payload packs, profiles, extensions, OAST |

Keep settings/help in secondary navigation and a persistent task/status area. Surface the active project, scope, session, and transport source without requiring the user to open internal configuration screens.

### 11.2 Shared interaction components

- [ ] Build one virtualized results table with column controls, stable row identity, sorting, multi-select, keyboard navigation, copy/export, and context actions.
- [ ] Build one message editor with raw/structured/hex views, headers, cookies, parameters, JSON/forms/multipart, search, syntax highlighting, inline transforms, byte counts, and diff. Lazy-load large bodies and show truncation explicitly.
- [ ] Provide one persistent CamioQL bar with autocomplete, inline parse errors, examples, saved queries, and contextual scope indicators.
- [ ] Use consistent Send to actions carrying a selected exchange/asset/finding reference. Preserve bytes/session provenance and avoid manually copying between forms.
- [ ] Add resizable/dockable panes, comfortable/compact density, persisted layouts, and reset-to-default. Keep existing themes/background preferences compatible.
- [ ] Add a command palette and visible shortcut help. Core navigation, query, send, inspect, and task controls must work without a mouse.
- [ ] Show loading, empty, offline, tool-missing, running, partial, cancelled, denied, and failed states with a useful next action. Preserve drafts and selections after recoverable errors.
- [ ] Prefer structured result summaries, task progress, and evidence links over a single shared text-output area. Redacted diagnostic logs remain available in task details.

### 11.3 First run and task controls

- [ ] First-run flow: create/open project → define targets → select/install managed browser explicitly if needed → start capture. Capture completion depends on the verified BiDi implementation.
- [ ] Integration setup shows installed/missing/incompatible status, resolved version, required components, and setup guidance. No shell command execution is hidden behind an unexplained button.
- [ ] Run preview summarizes targets/exclusions, selected checks/modules, estimated volume, upper bounds, transport/session, and applicable limits. Avoid repetitive confirmations inside an unchanged approved run.
- [ ] Show active jobs across surfaces with progress, elapsed time, result count, stop reason, cancel, supported pause/resume, and project-wide stop-all.
- [ ] Let users inspect partial results immediately, send an item to Replay, and return to the same task/table selection.

### 11.4 Accessibility, web coverage, and performance

- [ ] Verify text/controls against WCAG 2.1 AA goals: contrast, visible focus, labels, error announcements, scalable text, and status conveyed through text/icons as well as color.
- [ ] Test actual keyboard and assistive-technology behavior in egui and the browser. Resolve native framework limitations explicitly before claiming accessibility compliance.
- [ ] Make the local web interface usable on common laptop/tablet widths with semantic controls and the same capability service. Record intentionally desktop-only behavior, such as opening a local OS browser.
- [ ] Add web/API parity for active scans, JS analysis, transforms/comparison, rules, project/profile management, tasks, workflows, integrations, findings, and reports as those services land.
- [ ] Protect the local API with authenticated session/bootstrap handling, validated Host/Origin, CSRF defenses, strict schemas/body limits, output escaping, and a restrictive content policy. Remote access needs explicit configuration and authenticated transport.
- [ ] Measure responsiveness under large histories and active jobs. Keep large bodies, artifact parsing, and result pagination out of UI rendering paths.

## 12. Remaining feature completion tracks

### Browser, profiles, and protocols — F04–F06, F08–F10

- [ ] Spike the pinned Camoufox build's BiDi support before committing to unsupported request/response editing. Record behavior for auth, redirects, compression, cache, service workers, downloads, streaming, HTTP/2, and WebSockets.
- [ ] Ship live capture with browser-observed metadata/body fidelity labels and a durable intercept queue with timeouts, continue/drop, resume-all, and shutdown recovery.
- [ ] Complete browser-native request/response edits only for verified protocol capabilities; do not silently switch the managed browser to MITM.
- [ ] Add named isolated profiles, snapshots, save/restore/duplicate/archive/delete, protected session storage, encrypted import/export, and backed-up version migrations.
- [ ] Distinguish pinned Camoufox, LibreWolf, and Firefox capabilities. Applying preferences to another browser does not establish equivalent engine behavior or fingerprint parity.
- [ ] Measure TLS/HTTP-2/header behavior against controlled endpoints; publish build/profile-specific parity and stale/mismatched status.
- [ ] Finish Replay tabs/history, session-aware sends, in-scope redirect handling, compare-to-baseline, and export. Keep malformed/raw protocol modes separate from structured-client limitations.

### Findings, reports, utilities, and migration — F13–F19

- [ ] Add finding states, severity/confidence, annotations, labels, affected assets, evidence chains, suppression rationale, and scoped retesting.
- [ ] Preserve distinct tool claims while grouping likely duplicates; record first/last seen and validation history across runs.
- [ ] Generate deterministic redacted reports and hashed evidence bundles with scope, versions, completed/skipped/failed checks, limitations, and reproduction exchanges.
- [ ] Complete scanner session/login handling, per-check configuration, exclusions, and controlled positive/negative fixtures; expand checks through reviewed rules/templates.
- [ ] Add Sequencer token sampling/extraction and reproducible statistical reports; retain the current limits on what randomness estimates establish.
- [ ] Make Convert/Comparer/JWT operations reusable from editors, workflows, CLI, web, and MCP. Preserve byte/binary handling and unverified-JWT labeling.
- [ ] Implement Organizer items, notes, labels, collections, saved queries, and links to original exchanges/tasks/findings.
- [ ] Finish versioned HAR/Burp export/rule imports and documented Caido-supported interchange. Treat proprietary/unsupported project formats honestly; do not promise full project migration from a HAR importer.
- [ ] Protect imports against malformed archives/XML/JSON, traversal, huge/decompression-heavy inputs, and secret leakage. Show a preview and a partial-error report.

### OAST, extensions, and specialist tools — F15, F20, F22–F23

- [~] Self-hosted OAST. **Delivered (`camio-oast`, `camio oast`):** an HTTP collector that mints opaque correlation tokens, records inbound interactions (method/target/host/source/headers/body), and correlates each to its token via path (`/<token>`) or leftmost host label (`<token>.<base>`); verified end-to-end. **Still to do:** a DNS responder for pure-DNS exfil, durable storage + retention, polling/evidence-linking into findings, and wiring tokens into the active scanner so blind-injection probes auto-correlate.
- [ ] Version the extension SDK and manifest permissions for transforms, checks, actions, and panels. Enforce filesystem/network/task limits rather than relying on process separation.
- [ ] Make plugin discovery errors visible and add timeouts, cancellation, output limits, integrity checks, explicit update handling, and examples.
- [~] External-client MITM proxy as a separate opt-in transport. **Delivered (`camio-proxy`, `camio proxy`):** scope/policy-gated HTTP/HTTPS proxy; a persisted operator-trusted CA (`--export-ca`, key `0600`) that mints per-host leaves on demand; in-flight Match & Replace (request + response) and capture to the store as `source=proxy`; a blind-relay path that keeps the browser's own TLS fingerprint-true for non-intercepted HTTPS and a `--tls-intercept` path that re-sends the decrypted request through the fingerprint-matched engine (honestly tagged fingerprint-changing); and a UI-agnostic intercept queue (`QueueInterceptor`) for pause/edit/drop. **WebSocket (delivered):** a plain `ws://` upgrade is scope-gated, recorded as metadata, and raw-relayed to the origin (verified end-to-end); `wss://` is preserved by blind-relay, and under `--tls-intercept` a WebSocket is refused with a clear 501 rather than broken. **Still to do:** CA removal/rotation UX, upstream (chained) proxy support, HTTP/2 interception and WebSocket *frame* decoding/editing, the background-task controls from §4.2 (the proxy currently serves thread-per-connection and blocks the CLI foreground), and a native-app/web transport-change status surface.
- [ ] Add optional browser-assisted DOM/source-to-sink inspection, operator-built local clickjacking proof artifacts, and visible page instrumentation with cleanup and saved evidence.

### MCP, AI, deployment, and release — F21, F25–F26

- [ ] Publish a capability-to-UI/CLI/API/MCP matrix. Add project/profile management, integration discovery/planning, task status/results/cancel, workflows, findings updates, browser control, and report export.
- [ ] Keep long MCP operations asynchronous and subject to the same plan/approval/limits as the GUI. Return structured errors and paginated/redacted data.
- [ ] Let optional AI explain evidence, suggest queries, and draft plans. Treat imported text/tool output as untrusted data; AI suggestions cannot grant permissions or authorize executions.
- [ ] Add headless project/workflow runs, machine-readable exit/result contracts, CI artifacts, schedules, overlap prevention, and incremental comparison.
- [ ] Add deployment authentication, project/team roles, tenant/project separation, audit, backup/restore, and centralized reporting before exposing shared services remotely.
- [ ] Finish platform packaging, signed artifacts/checksums, SBOM/license review, upgrade/migration paths, offline operation, supported-feature documentation, governance, and independent release review.

## 13. Sequenced milestones and exit gates

Dates should be estimated after M0 establishes browser and upstream feasibility. Complete each dependency gate before exposing dependent unattended execution.

| Milestone | Deliverables | Depends on | Exit evidence |
|---|---|---|---|
| M0 — Baseline and feasibility | Register F01–F26, baseline checks, browser/fingerprint spike, Rustploit access/interface review, platform support decisions | Source review | Reproducible baseline report and explicit supported/blocked/unsupported capability records |
| M1 — Shared runtime | Service boundary, persisted tasks/projects/migrations, destination enforcement, budgets/rates/approvals, cancellation, query/storage foundations, API hardening | M0 | Same bounded task behavior through UI/CLI/API/MCP; restart/cancel/scope tests pass |
| M2 — Everyday workbench | Cohesive shell, shared editors/tables, Replay, search, initial browser capture, parity status, profile basics | M1 and successful browser spike | End-to-end capture → filter → Replay → compare → save with responsive UI |
| M3 — httpx and integration foundation | Registry, health/configuration, supervised runner, parser fixtures, httpx probing/import, inventory, normalized evidence | M1; M2 components | Controlled inventory workflow with scope/limit/cancel/partial-output tests |
| M4 — Nuclei | Pinned template catalog, profiles/preview, bounded runs, JSONL findings/import, dedup/retest, session support | M3 | Pinned lab template pack produces expected findings and complete provenance |
| M5 — Rustploit and automation | Verified Rustploit adapter/bridge, campaign completion, typed workflow runtime, visual/text editor, starter workflows, reports | M3–M4; Rustploit discovery prerequisite | Probe → detection → approved verification → report; all nodes stoppable and attributable |
| M6 — Browser and testing completeness | Profile lifecycle, supported intercept edits, complete input/schema discovery, session/scanner controls, utilities, Organizer/imports, OAST foundation | M2, M5 | Accepted browser/protocol and migration matrices plus reproducible findings |
| M7 — Ecosystem and specialist coverage | Katana/Subfinder/ffuf adapters, OAST connector, extension SDK, optional proxy, browser-assisted tools, MCP coverage | M5–M6 | Contract suites and documented workflows for every supported capability |
| M8 — Desktop release quality | Accessibility/usability reviews, native/web parity, performance gates, platform packaging, security/recovery review | M1–M7 | Measured acceptance report, supported-feature table, signed candidate artifacts |
| M9 — Headless/team completion | Scheduling, CI/headless API, deployment auth/roles, shared reporting, final roadmap audit and docs | M8 | Full F01–F26 disposition with passing workflow, isolation, upgrade and release checks |

Rustploit discovery is an explicit dependency for its adapter, not for shipping the shared runtime, httpx, or Nuclei. Keep it visibly pending if upstream remains unavailable. Do not mark the requested integration complete based on a placeholder panel.

## 14. Validation and measurable acceptance

### 14.1 Repository checks

Preserve the existing contribution/CI gates and add locked release checks as appropriate:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```

These are implementation validation gates, not checks executed by this documentation-only change.

### 14.2 Integration and workflow tests

- [ ] Unit/fixture tests cover plan/schema validation, argument construction, secret redaction, JSONL chunk boundaries, malformed/oversized output, deduplication, version drift, and error mapping.
- [ ] Fake executables cover missing binaries, hangs, noisy output, broken pipes, nonzero exits, partial success, child processes, cancellation, and restart recovery without contacting live targets.
- [ ] Pinned real-tool tests run only against controlled fixtures/lab apps. Record binary/template versions and all requested destinations.
- [ ] Scope tests include redirects, excluded paths/ports, DNS changes, IPv4/IPv6, auxiliary requests, tool configuration inheritance, and callback destinations. Verify zero prohibited traffic at the lab egress boundary.
- [ ] Budget tests include native baselines/retries, Nuclei multi-request templates, httpx probes/fallbacks, concurrent jobs, and workflow fan-out.
- [ ] UI/API/MCP tests demonstrate equivalent planning, approval binding, limits, task states, cancellation, errors, and persisted results.
- [ ] Test no-result runs separately from failed/incomplete scans. Negative findings require evidence that the selected checks actually ran.
- [ ] Test schema upgrades, rollback/recovery procedure, disk-full/locked databases, interrupted writes, artifact cleanup, and backup/restore.

### 14.3 Provisional product budgets

Confirm these targets against a published Linux reference machine/dataset in M0 and record changes with measured rationale. They are acceptance targets, not current claims. Browser installation/download time is measured separately.

| Measurement | Initial target |
|---|---|
| Native cold launch to interactive shell | p95 ≤ 2 seconds with an installed engine and normal local project |
| Immediate action acknowledgement/task ID | p95 ≤ 100 ms while jobs are active |
| Common indexed metadata query/page | p95 ≤ 250 ms over 1,000,000 exchanges; report body-search budgets separately |
| First inspector view for a normal exchange | p95 ≤ 200 ms with lazy body loading |
| Visible progress freshness | Updates at least once per second while progress is available; time-based heartbeat otherwise |
| Cancel to no additional work scheduled | ≤ 250 ms; in-flight work tracked separately |
| Supervised subprocess termination | ≤ 2 seconds after grace/force-stop begins, with no surviving child processes |
| UI input/render latency during active jobs | p95 ≤ 50 ms; no blocking network/tool work on UI thread |
| Memory/disk growth | Publish fixed idle/active budgets and verify bounded paging, queues, bodies and output independently of total history |

### 14.4 End-to-end release exercise

From a clean local install: create a lab project, set explicit scope, launch the managed browser, capture an exchange, filter and replay it, probe selected targets with httpx, run an approved Nuclei profile, verify one finding with a reviewed Rustploit module when available, inspect live task output, cancel a separate run, triage findings, export redacted evidence, restart Camio, and recover the project/workspace without duplicate execution.

Repeat the equivalent supported workflow through CLI/API/MCP. Exercise missing-tool, unavailable-browser, denied-scope, rate-limited, interrupted, and no-finding paths. Record any remaining capability limitation in the release matrix.

## 15. First implementation backlog

These tasks start the roadmap; dependent integrations must reuse their results.

1. [ ] Record baseline build/test status and produce the versioned F01–F26 capability matrix with source and acceptance links.
2. [ ] Complete the pinned-browser interception/parity spike and resolve Rustploit upstream access/interface details.
3. [ ] Add storage migrations and typed project/target/task/run/artifact/audit records; back up existing databases before migration.
4. [ ] Introduce shared capability services and move one Replay send onto a cancellable background task end to end through native UI, CLI, web API, and MCP.
5. [ ] Implement explicit automation scope, connection-time destination checks, approval binding, and shared budget/rate counters; verify denied lab destinations receive zero traffic.
6. [ ] Generalize the supervised subprocess runner with environment/config isolation, structured arguments, output bounds, process-tree cancellation, and fake-tool fixtures.
7. [ ] Ship the first shared virtualized results table/message inspector and persistent task panel; retain current tools during incremental migration.
8. [ ] Implement httpx plan/run/import → inventory → Send to Replay with controlled integration tests.
9. [ ] Implement pinned Nuclei catalog/plan/run/import → evidence/findings → retest using the same runner and task service.
10. [ ] Implement the verified Rustploit adapter, then typed workflows and GUI composition around the three integrations and native campaign/scanner services.

## 16. Definition of complete

The requested work is complete when the full agreed capability register has acceptance evidence, Nuclei/httpx/Rustploit have real tested adapters, automated workflows remain bounded and cancellable across interfaces, browser/profile features match their published support matrix, users can reproduce findings from preserved evidence, and native/web UX, accessibility, performance, recovery, and packaging gates pass.

A completed plan file is a planning deliverable. Working integrations, finished product features, and measured release claims require the implementation and validation work listed above.
