#!/usr/bin/env bash
# Print the previous audit scan to compare against: the newest
# .ponytail-sec/audit-* whose meta.json commit is HEAD or an ancestor of it.
# Scans that are symlinks, or hold a symlinked meta.json or findings.json or
# any symlink under triage/, are skipped. Names every skipped directory on
# stderr. Prints nothing when there is none. Fails if .ponytail-sec is a
# symlink, so the audit never writes through one.
# Read-only. Usage: previous-scan.sh
set -euo pipefail

die() { echo "Error: $*" >&2; exit 1; }

root=$(git rev-parse --show-toplevel 2>/dev/null) || die "run from inside a git repository"
dir="$root/.ponytail-sec"
[ ! -L "$dir" ] || die "$dir must be a real directory, not a symlink"
[ -d "$dir" ] || exit 0

# NUL-delimited: a directory name containing a newline cannot add candidates.
while IFS= read -r -d '' d; do
  ok=1
  # A newline (even a trailing one) would be lost by $( ) in callers.
  if [[ $d == *$'\n'* ]]; then ok=0; fi
  for f in "" /meta.json /findings.json /triage; do
    [ ! -L "$d$f" ] || ok=0
  done
  [ -f "$d/meta.json" ] || ok=0
  if [ -d "$d/triage" ] && [ -n "$(find "$d/triage" -type l -print -quit)" ]; then ok=0; fi
  c=""
  [ "$ok" = 1 ] && c=$(jq -r '.commit // empty' "$d/meta.json" 2>/dev/null || true)
  if [[ $c =~ ^[0-9a-f]{40}$ ]] && git merge-base --is-ancestor "$c" HEAD 2>/dev/null; then
    printf '%s\n' "$d"
    exit 0
  fi
  printf 'Skipped %q: symlinked state, unreadable meta.json, or commit not HEAD or an ancestor.\n' "$d" >&2
done < <(find "$dir" -mindepth 1 -maxdepth 1 -type d -name 'audit-*' -print0 | LC_ALL=C sort -rz)
