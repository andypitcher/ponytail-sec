#!/usr/bin/env bash
# Write <dir>/triage/index.json from the frontmatter of every valid report.
# Usage: build-index.sh [<dir>]   (default: the latest audit scan)
set -euo pipefail

here=$(dirname "$0")
# Confine an explicit <dir> too (audit-* or standalone triage-*): this is
# the one script that writes.
dir=$("$here/find-scan.sh" ${1:+--confine "$1"})
reports=$("$here/check-triage.sh" --json "$dir")

tmp=$(mktemp "$dir/triage/.index.XXXXXX")
trap 'rm -f "$tmp"' EXIT
jq --arg source "$(basename "$(cd "$dir" && pwd)")" '
  {source: $source,
   findings: sort_by(.id[:1], (.id[1:] | tonumber))}
' <<<"$reports" >"$tmp"
# find-scan.sh already refused any symlink under triage/.
mv "$tmp" "$dir/triage/index.json"
trap - EXIT
echo "Wrote $dir/triage/index.json"
