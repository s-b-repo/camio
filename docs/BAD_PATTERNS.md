# BAD_PATTERNS — regex audit matrix

Machine-readable companion to `scripts/audit-bad-patterns.sh`. The script scans
every `.rs` file under the source tree and reports hit counts per section.

**Hits are candidates, not verdicts.** Each pattern is a grep-level heuristic and
is known to have false positives (e.g. `unwrap()` in a `#[test]`, `let _ =` in a
deliberate drop, `Box<dyn Trait>` which is idiomatic). Triage every hit by
reading the code; only promote it to a defect after you understand the context.

Run it:

```bash
scripts/audit-bad-patterns.sh                       # full report
scripts/audit-bad-patterns.sh --section A --verbose # per-line detail, one section
scripts/audit-bad-patterns.sh --strict             # CI gate for A/B/C/L/M/N/O
scripts/audit-bad-patterns.sh --zero "C L M"       # gate only these sections
scripts/audit-bad-patterns.sh --files files.txt    # subset of files
scripts/audit-bad-patterns.sh --src crates         # explicit source root
scripts/audit-bad-patterns.sh --include-tests      # count #[cfg(test)] code too
```

By default test code is excluded: a file under `tests/` (or named `test_*` /
`*_test`), and everything from the first `#[cfg(test)]` onward. `unwrap()`,
`expect()` and `assert*` are idiomatic there, and counting them makes every
report and every `--strict` run useless — on this repo it was 3,208 of 3,880 raw
hits. Use `--include-tests` when you are auditing test code deliberately.

`--zero` is the mode to wire into CI: pick the sections that must always be
zero and leave the rest informational, because a hit is a *candidate* that
still has to be read. Camio's CI gates `C L M` (lint suppression, weak
crypto, injection) — 0 today, so any new one fails the build. `--strict`
covers A/B/C/L/M/N/O and is a review tool: it reports a few hundred hits on
this repo that are documented accepted risks (per-section notes below).

Counts are *matches*, not matching lines: `a().unwrap().expect()` on one
line scores 2. Comments and doc comments never count — the filter tests the
text after `path:lineno:`, so a `//!` example mentioning `.unwrap()` is not
a hit.

Suppressing a false positive: put `// audit-allow: <SECTION><n>` on the same
line or the line immediately above the hit (e.g. `// audit-allow: M1`) and
record why. A marker excuses exactly one line.

## Sections

| Section | Name | `--zero` (CI) | `--strict` |
|---------|------|------------|-----------|
| A | Panicking error handling | | yes |
| B | Silent error swallowing | | yes |
| C | Lint suppression | **yes** | yes |
| D | Panic vectors (index/slice) | | |
| E | Numeric / unsafe | | |
| F | Async / blocking | | |
| G | Logging | | |
| H | HTTP layer | | |
| I | Iterator glitches | | |
| J | Style / secrets | | |
| L | Crypto | **yes** | yes |
| M | SQL & command injection | **yes** | yes |
| N | UB / concurrency | | yes |
| O | Performance | | yes |
| P | API hygiene | | |

The `--zero` column is Camio's CI gate: those three sections must be empty, and
they are. Everything else is advisory — `--strict` exists so you can review the
full set on demand, not so merges block on it.

(Section K is unused; the letters match the original matrix numbering so
historical reports stay comparable.)

## What each section is looking for

- **A — Panicking error handling.** `unwrap`/`expect`/`panic!`/`todo!`/
  `unreachable!`/`assert!` on non-test paths. In a long-running server any of
  these aborts a task (or the process) instead of returning an error. The
  poison-pill cases are `.lock().unwrap()` (kills every request after one
  panicking holder) and `.unwrap()` on I/O (`read_to_string`, `parse`).
- **B — Silent error swallowing.** `Err(_)`, `let _ =`, `.map_err(|_| ...)`,
  `.ok()`. Failures disappear: no log, no metric, no retry. Underscore-prefixed
  parameters/bindings (B10/B11) hide the same problem at the compiler level.
- **C — Lint suppression.** `#[allow(...)]`/`#[deny(...)]`/`#[ignore]` must each
  carry a comment stating what is suppressed and why.
- **D — Panic vectors.** Constant indexing and half-open slicing (`&v[a..b]`)
  panic when bounds are wrong. Prefer `get()`/`get(a..b)` and `split_at` with a
  checked bound.
- **E — Numeric / unsafe.** `as` casts silently truncate and wrap; `unsafe`,
  `transmute`, raw pointer casts, `extern "C"` need a safety comment each.
- **F — Async / blocking.** Blocking stdin/std::fs/`thread::sleep`/`Command`
  inside async contexts starves the executor.
- **G — Logging.** `dbg!` in shipped code, `format!("{:?}", err)` (leaks internal
  detail, no structured fields), empty `.context("")`.
- **H — HTTP layer.** Fresh `reqwest::Client::new()` per call (skips pooling,
  loses TLS session reuse), `?` on `.send()`/`.text()` without status checks.
- **I — Iterator glitches.** `collect::<Result<...>>().unwrap()` re-panics what
  `?` would have propagated; `.zip(...).unwrap()` assumes equal lengths.
- **J — Style / secrets.** Hard-coded credentials, bearer tokens, `sk-`/
  `AKIA` key shapes, `&*format!(...)` (dangling temporary), debug-only
  workarounds left in.
- **L — Crypto.** MD5/SHA-1/3DES/RC4/ECB and weak RNG *for security purposes*.
  Non-security uses (checksums, payload variety) are legitimate — annotate them.
- **M — Injection.** `format!`-built SQL, and `sh -c` with interpolated strings.
  Use parameterised queries and argument vectors.
- **N — UB / concurrency.** `static mut`, `mem::transmute`/`forget`/`zeroed`,
  raw `ptr::read`/`write`, and `Result<T, String>` error types (unstructured,
  unfilterable, and lose the error source chain).
- **O — Performance.** `.iter().count()`, redundant clones in `map`, `to_string`
  then `as_str`, zero-capacity preallocation, `Regex::new(...).unwrap()` inside
  a hot path.
- **P — API hygiene.** `pub const ... &str = "http://..."` (plaintext HTTP in a
  public constant, and a common MITM-injection point) and `#[derive(Debug)]` on
  public structs with password/secret/token fields — `Debug` output ends up in
  logs, panics and `{:?}` traces.

## Triage status of the remaining hits

Every remaining hit was read, not filtered. What is left, and why:

| Section | Remaining | Verdict |
|---|---|---|
| A (panics) | 41 | All `unwrap_or_default()` — absent-means-default on an `Option`, not a swallowed failure. `.unwrap()` and `.expect()` are **zero** in production code. |
| B (silent) | 44 | Either logged, propagated, or a `// audit-allow: B4/B5/B7` marker with the reason on the line above. Every marker is a judgement call you can review. |
| C, G, H, I, L, M, P | 0 | Clean, and gated in CI. |
| D (index/slice) | 93 | **Verified guarded.** Every constant index or slice is preceded by a length check in the same function (`bytes.len() < 2` in `incomplete_frame_len`, `query.len() >= 12` in `parse_query`, `cmd.is_empty()`/`parts.len() != 3` before indexing). Worth re-reading when that code changes — that is what the section is for. |
| E (casts) | 142 | Width-safe by construction. The dangerous shapes were fixed: DB count columns now reject negatives instead of wrapping (`count_column`, `non_negative`), and every user-supplied row limit goes through `bounded_limit`. |
| F (blocking) | 48 | The workspace is synchronous outside `camio-ai`/`camio-request`; `thread::sleep`/`std::fs` there are in blocking code by design, not inside a tokio runtime. |
| J (style) | 15 | `Box<dyn Trait>` (idiomatic) and `.len() == 0` inside `is_empty()` implementations (the standard spelling). |
| N (error type) | 97 | `Result<T, String>` is systemic across the workspace. Converting it means a new error type per crate plus a source chain everywhere; that is a deliberate, reviewable refactor, not a bug fix. |
| O (perf) | 5 | `Box::new(Box::new(…))` in the CamioQL AST constructors — that is what a recursive enum is. |

## Known limitations

- Patterns are unanchored and regex-only: they cannot judge *intent*, so a
  deliberate `let _ = drop(...)` reads the same as an accidental one, and they
  see nothing through macros or `include!`.
- `--verbose` caps output at `MAX_DETAIL` (default 25) lines per pattern.