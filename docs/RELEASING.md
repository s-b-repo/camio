# Releasing

Releases are **fully automated**. You never bump a version or cut a release by
hand — you just write good commit messages.

## How it works

Every push to `main` runs [`.github/workflows/release.yml`](../.github/workflows/release.yml):

1. [`scripts/compute-release.sh`](../scripts/compute-release.sh) reads every
   commit since the latest `vX.Y.Z` tag and derives the next version from
   [Conventional Commits](https://www.conventionalcommits.org/).
2. [`scripts/bump-manifest.py`](../scripts/bump-manifest.py) writes that version
   into `Cargo.toml` (`[workspace.package]`) and commits it as
   `chore(release): vX.Y.Z [skip ci]`.
3. The commit is tagged `vX.Y.Z` and a GitHub Release is published with
   **auto-generated notes** (grouped per [`.github/release.yml`](../.github/release.yml)).

## What bump you get

The **highest** signal across all commits since the last tag wins:

| Commit subject / footer                          | Bump  | Example            |
| ------------------------------------------------ | ----- | ------------------ |
| `feat!: …` or a `BREAKING CHANGE:` footer        | major | `0.4.1` → `1.0.0`  |
| `feat: …`                                         | minor | `0.4.1` → `0.5.0`  |
| `fix:`, `perf:`, `refactor:`, `chore:`, `docs:` … | patch | `0.4.1` → `0.4.2`  |
| anything else (non-conventional subject)          | patch | `0.4.1` → `0.4.2`  |

Every push with new commits ships **at least a patch** — releases are per-change
by design. Keep the `Fxx` feature tags in the subject; they don't affect the
bump: `feat: intercepting proxy (F11)` → minor.

## Opting out / overriding

- Put `[skip release]` (or `[release skip]`) in a commit message to suppress the
  release for that push.
- Run the workflow manually (**Actions → Release → Run workflow**) and set
  `release_as` to `patch`/`minor`/`major`, or `explicit_version` to e.g.
  `v0.2.0`, to force a specific release.

## Requirements

- The workflow uses the built-in `GITHUB_TOKEN` (`contents: write`). No extra
  secrets are needed.
- If `main` is a protected branch that rejects Action pushes, the manifest bump
  is skipped (a warning is logged) but the tag + release still go out. To keep
  the manifest in sync under branch protection, allow `github-actions[bot]` to
  push, or set `SYNC_MANIFEST: off` in the workflow.
