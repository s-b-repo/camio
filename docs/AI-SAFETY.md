<div align="center">

![Camio AI Safety](https://img.shields.io/badge/CAMIO-AI%20safety%20layer-1e80ff?style=for-the-badge&labelColor=020508)

![HMAC](https://img.shields.io/badge/signature-HMAC--SHA256-2ea043?style=flat-square&labelColor=020508)
![Bound](https://img.shields.io/badge/scope-hash--bound-6f42c1?style=flat-square&labelColor=020508)
![Targets](https://img.shields.io/badge/targets-hash--pinned-6f42c1?style=flat-square&labelColor=020508)
![Auto-correct](https://img.shields.io/badge/tool--calls-fuzzy%20%2B%20binding--gated-dea584?style=flat-square&labelColor=020508)

# Camio AI safety

**Designed from the AI's perspective — easy to use, hard to escape.**

</div>

## 1. Why this exists

Camio lets AIs drive Repeater/Scanner/Chains/Proxy through MCP. A rogue or
confused model could try to:

- Send traffic to a host that was never authorized.
- Broaden the scope mid-session (inject a new include rule).
- Escalate from `read` to `active`/`destructive`.
- Replay a stale binding from another session.
- Repoint a chain step via a response-derived variable.
- Name a tool wrong on purpose and hope the server picks the closest
  thing regardless of class (e.g. `scan` → `active_scan`).

The AI safety layer closes all of those paths with a single HMAC-signed
**session binding** plus an AI-aware **tool resolver**.

## 2. The binding — what the AI carries

```json
{
  "session_id": "ai-abc123",
  "created_at_ms": 1795102522684,
  "expires_at_ms": 0,
  "scope_hash": "e3b0c4...b855",
  "target_hashes": ["100680...09ce9"],
  "allowed_actions": ["read", "mutating"],
  "tag": "1bd5f7...025bc"
}
```

| Field | What it commits to |
|---|---|
| 🟦 `scope_hash` | SHA-256 of the canonical scope-rule list. Any reorder/edit of rules invalidates the tag. |
| 🟦 `target_hashes` | SHA-256 of each `scheme://host[:port]` the AI may hit. Path is intentionally not hashed — the AI is free to hit any path on an authorized host, subject to the scope rules. |
| 🟦 `allowed_actions` | Lowercase action classes: `read`, `mutating`, `active`, `destructive`. |
| 🟨 `tag` | HMAC-SHA256 of all of the above, keyed by a 32-byte per-session **SessionKey** the server keeps. |

The server holds the `SessionKey` and never shares it with the AI. The
`SessionKey` struct in `camio-core` has no `Serialize` impl, prints
`<redacted>` on `Debug`, and zeroes itself on `Drop`.

## 3. CLI workflow

```bash
# Bind a session (server-side): writes the key to ~/.config/camio/ai-keys/ at 0600
# and prints the binding JSON on stdout for the AI to carry.
camio ai-guard bind \
    --target 'https://authorized.example.com' \
    --scope-include 'host.eq:authorized.example.com' \
    --allow read --allow mutating \
    --ttl-secs 3600 --pretty  > binding.json

# Verify a binding later (uses the saved key automatically):
camio ai-guard verify binding.json
# -> ok  session=ai-abc  targets=1  actions=[mutating,read]

# Authorize a chain spec BEFORE running it — every step URL (including
# values pulled from the chain state) is checked against target_hashes.
camio ai-guard authorize-chain --binding binding.json --chain chain.json
```

Chain spec shape (JSON):

```json
{
  "state": { "csrf": "abc-xyz" },
  "steps": [
    { "label": "login",  "method": "POST", "url": "https://authorized.example.com/login",
      "headers": [["Content-Type","application/x-www-form-urlencoded"]],
      "body": "u=admin&t=${csrf}" },
    { "label": "fetch",  "method": "GET",  "url": "https://authorized.example.com/me" }
  ]
}
```

## 4. What the guard refuses

| Scenario | Outcome |
|---|---|
| 🟥 AI added a new action class (`read → read,destructive`) | `binding tag did not verify — refusing operation` |
| 🟥 AI swapped the scope hash | `binding tag did not verify` |
| 🟥 AI appended a new host hash | `binding tag did not verify` |
| 🟥 Chain step targets an out-of-scope host | `target `…` is not in this session's authorized set` |
| 🟥 Chain state injects a rogue URL into `${next}` → step `url: "${next}"` | Rechecked on substitution; same refusal |
| 🟥 Binding expired | `binding expired at … ms (now … ms)` |
| 🟩 AI uses the binding as issued | All operations proceed; scope/policy gate still runs |

## 5. Programmatic API

```rust
use camio_core::{SessionKey, SessionBinding, ActionClass, ScopeRule};
use camio_core::{bind_session, verify_binding, verify_and_authorize_target,
                 verify_and_authorize_action, authorize_findings};

let key = SessionKey::generate();
let binding = bind_session(
    "s1",
    &[ScopeRule::include("host.eq:example.com")?],
    &["https://example.com".into()],
    &[ActionClass::Read, ActionClass::Mutating],
    0, // no expiry
    &key,
)?;

// Any AI-mediated operation re-verifies first:
verify_binding(&binding, &key)?;

// Before sending:
verify_and_authorize_target(&binding, &target_url, &key)?;

// Before invoking a tool class (read / mutating / active / destructive):
verify_and_authorize_action(&binding, ActionClass::Mutating, &key)?;

// Before returning findings to the AI, filter to the session's authorized hosts:
let safe = authorize_findings(&binding, all_findings, |ex_id| store.host_of(ex_id));
```

Chain authorization:

```rust
use camio_automate::{Chain, ChainStep, ChainState, authorize_chain_steps, authorize_next_url};
use camio_core::HttpRequest;

let chain = Chain::new()
    .push(ChainStep::new("login", HttpRequest::post("https://example.com/login")))
    .push(ChainStep::new("hit",   HttpRequest::get("https://example.com/me")));

let steps = authorize_chain_steps(&chain, &ChainState::new(), &binding, &key)?;
// `steps` is the ready-to-send request plan; every URL passed the host-hash check.

// Between steps, when a value lands in ChainState from an extractor:
authorize_next_url(&next_url_from_extractor, &binding, &key)?;
```

## 6. AI tool-call auto-correction (`camio-core::ai_tools`)

When the AI asks for a tool it may use a slightly-wrong name, an alias,
or a short phrase (`"perform port scan"`, `"enumerate subdomains"`). The
resolver returns one of three verdicts:

| Verdict | When |
|---|---|
| 🟩 `AutoApply(tool)` | Top match's score ≥ 6.5, gap over runner-up ≥ 2.0, token coverage ≥ 0.6, and the binding grants the tool's action class. |
| 🟨 `Suggest([tool, …])` | Up to 3 candidates passed the SUGGEST threshold — the server asks the AI to pick one by exact name. |
| 🟥 `Refused(reason)` | No candidate above threshold, or the top candidate requires an action class the binding does not grant. |

**The resolver never invents a tool.** For the user's example "perform
port scan" (Camio has no port-scanner registered) the resolver returns
`Refused("no tool matches")` — it refuses to pick a near-miss like
`scan_passive`.

```rust
use camio_core::{resolve_tool_call, default_catalog, ResolveRequest, ToolResolution};

let catalog = default_catalog();
let result = resolve_tool_call(
    &catalog,
    &binding,
    &key,
    &ResolveRequest { name_or_phrase: "enumerate subdomains", provided_args: None },
)?;
match result {
    ToolResolution::AutoApply(sugg) => dispatch(&sugg.tool),
    ToolResolution::Suggest(choices) => return_choices_to_ai(choices),
    ToolResolution::Refused(why) => return_error_to_ai(why),
}
```

Scoring signals (each adds to the score; all feed into the verdict):

| Signal | Weight |
|---|---|
| Exact name match | 10.0 |
| Exact alias match | 8.0 |
| Substring (name or alias) | 3.0 / 2.5 |
| Prefix-keyword hit per phrase token | 1.2 |
| Jaro similarity to best-of {name, aliases} | up to 3.0 |

## 7. Integrity lockdown — the AI cannot edit the code

When a binding is issued with `--lock`, Camio hashes the running
binary, the `~/.config/camio` tree (including `ai-keys/`), and the
`plugins/` directory, folds the combined SHA-256 into the signed
binding, and refuses any subsequent operation if those paths change.

```bash
# Issue a locked binding (pins /proc/self/exe, ~/.config/camio, plugins/):
camio ai-guard bind --target https://example.com --allow read --lock \
   > binding.locked.json

# Add extra paths to the lock (repeatable):
camio ai-guard bind --target https://example.com --allow read \
   --lock-path /opt/camio-plugins --lock-path /etc/camio.conf \
   > binding.locked.json

# Re-check at any time (fast — just rehashes the pinned paths):
camio ai-guard check-integrity binding.locked.json
# -> ok  integrity matches (3 paths)

# If the AI somehow drops a plugin, swaps the binary, or edits the config,
# the next check-integrity refuses with:
#   AI-guard: integrity-locked path changed during session:
#     pinned-hash mismatch over N path(s); re-bind or alert the operator
```

Defenses the lock closes:

| Attack vector | What the lock catches |
|---|---|
| 🟥 AI drops a new plugin into `plugins/` | Directory manifest hash changes → `IntegrityBreach` |
| 🟥 AI replaces `/proc/self/exe` (binary swap) | File hash changes → `IntegrityBreach` |
| 🟥 AI overwrites `~/.config/camio/ai-keys/<id>.key` | File hash changes → `IntegrityBreach` |
| 🟥 AI edits `~/.config/camio/theme.json` or other config | File hash changes → `IntegrityBreach` |
| 🟥 AI points a symlink at a different file | Symlink target string is hashed → `IntegrityBreach` |
| 🟥 AI deletes a locked path to reset it | Hash flips from file-digest to literal `"(absent)"` → `IntegrityBreach` |

The `integrity_hash` is covered by the binding's HMAC, so an AI cannot
remove or replace the lock without invalidating the tag — it has to
either break HMAC-SHA256 or steal the key from disk. The key file is
0600 and the integrity lock includes the ai-keys directory, so key
tampering is also caught.

## 8. Tamper-resistance properties

The binding's `tag` is HMAC-SHA256 over a canonical length-prefixed
encoding of every public field. Length prefixes prevent boundary
collision attacks. `ct_eq` compares in constant time. The resolver reads
the binding with `verify_binding` **before** any scoring runs, so a
tampered binding never even reaches catalog lookup.

Specifically, these attacks are refused by test (`cargo test -p
camio-core`):

- `verify_fails_with_wrong_key`
- `verify_fails_when_scope_hash_tampered`
- `verify_fails_when_target_added`
- `verify_fails_when_action_escalated`
- `expiry_is_enforced`
- `tampered_binding_rejected_even_at_resolver_entry`
- `unauthorized_host_refuses_the_whole_chain`
- `chain_with_variable_url_still_checks_the_substituted_value`
- `bind_with_integrity_signs_the_hash_into_the_tag`
- `integrity_hash_changes_when_file_bytes_change`
- `integrity_hash_changes_when_new_file_dropped_into_dir`
- `verify_integrity_catches_post_bind_drop`

## 9. Honesty

- This is defense-in-depth on top of `camio-core::scope::Scope` and
  `camio-core::policy::Policy`. The scope/policy gate is the one that
  refuses out-of-scope sends; the binding adds a second lock the AI
  boundary can't pick.
- The resolver never upgrades action class. A `read`-only session with
  the AI asking for `activescan` returns `Refused`, not a promoted
  dispatch.
- Target hashing is at the host level (not path), so the AI can hit any
  path on an authorized host — the scope rules (which live in the
  `scope_hash`) decide which paths are legal.
- Nothing here protects against a side-channel on the server itself —
  the key must stay server-side. Running `camio-mcp` on a shared host
  with a weak home-directory umask weakens the model.
