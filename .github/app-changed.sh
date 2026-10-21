#!/usr/bin/env bash
# Prints app=true to $GITHUB_OUTPUT unless every changed file is website,
# deploy or prose only, so the app build, tests and installer checks can be
# skipped for those. Anything unclear counts as an app change.
set -euo pipefail

answer() { echo "app=$1" >> "$GITHUB_OUTPUT"; echo "App checks needed: $1"; exit 0; }

case "$BASE" in ""|0000000000000000000000000000000000000000) answer true ;; esac
[ "$EVENT" = "workflow_dispatch" ] && answer true

# A renamed file counts under its old path too. The compare API lists at most 300 files.
if ! compare=$(gh api "repos/$REPO/compare/$BASE...$HEAD"); then answer true; fi
count=$(jq '.files | length' <<< "$compare")
[ "$count" -eq 0 ] || [ "$count" -ge 300 ] && answer true
files=$(jq -r '.files[] | .filename, (.previous_filename // empty)' <<< "$compare")

echo "$files"
# The two copy-key lists in docs/ are read by the Rust tests (src/i18n.rs).
other=$(grep -Ev '^(website/|deploy/|functions/|video/|\.github/ISSUE_TEMPLATE/)|^wrangler\.jsonc$|^LICENSE$|^\.github/CODEOWNERS$|^[^/]+\.md$|^docs/' <<< "$files" || true)
keys=$(grep -E '^docs/(report|guided)-copy-keys\.md$' <<< "$files" || true)
[ -n "$other" ] || [ -n "$keys" ] && answer true
answer false
