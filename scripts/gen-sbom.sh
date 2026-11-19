#!/usr/bin/env bash
# Generate a dependency SBOM (name, version, license) for the Camio workspace
# from `cargo metadata`, written to docs/SBOM.md (plan §F26).
#
# This is the resolved dependency graph for the host platform. Licenses are
# additionally audited across all shipped platforms in CI by cargo-deny
# (deny.toml). Regenerate after dependency changes and commit the result.
set -euo pipefail
cd "$(dirname "$0")/.."

out="docs/SBOM.md"
mkdir -p docs

meta="$(cargo metadata --format-version 1 --all-features 2>/dev/null)"
count="$(printf '%s' "$meta" | jq '.packages | length')"
date="$(date -u +%Y-%m-%d)"

{
  echo "# Camio — Software Bill of Materials (SBOM)"
  echo
  echo "Generated from \`cargo metadata --all-features\` on ${date} (UTC, host platform)."
  echo "**${count}** packages in the resolved dependency graph."
  echo
  echo "Regenerate with \`scripts/gen-sbom.sh\`. Licenses are audited across all"
  echo "shipped platforms in CI by [cargo-deny](../deny.toml); this file is the"
  echo "human-readable inventory."
  echo
  echo "| Package | Version | License |"
  echo "|---|---|---|"
  printf '%s' "$meta" \
    | jq -r '.packages
             | sort_by(.name|ascii_downcase)
             | .[]
             | "| \(.name) | \(.version) | \((.license // .license_file // "—")|gsub("\\|";"/")) |"'
} > "$out"

echo "wrote ${out} (${count} packages)"
