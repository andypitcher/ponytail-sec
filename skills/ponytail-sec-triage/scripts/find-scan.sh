#!/usr/bin/env bash
# Print the audit scan directory to triage: the newest .ponytail-sec/audit-*
# whose commit is HEAD or an ancestor of it, or --scan <dir>. The scan must be
# a real directory directly under the repo's .ponytail-sec/, and its
# meta.json, findings.json and triage/ must not be symlinks. Rejects schema v2
# and warns on a findings_sha256 mismatch.
# Nothing under triage/ may be a symlink.
#   --confine <dir>: only check that <dir> is a real audit-* or triage-*
#   directory under .ponytail-sec/ (for standalone triage) and print it.
#   --list: print every confined audit-* and triage-* directory, newest
#   first, for history lookups; nothing else is checked.
# Read-only. Usage: find-scan.sh [--scan <dir> | --confine <dir> | --list]
set -euo pipefail

die() { echo "Error: $*" >&2; exit 1; }

scan="" mode=scan
case "${1:-}" in
  --scan|--confine) [ -n "${2:-}" ] || die "$1 needs a directory"; scan=$2; mode=${1#--} ;;
  --list) mode=list ;;
  "") ;;
  *) die "usage: find-scan.sh [--scan <dir> | --confine <dir> | --list]" ;;
esac

root=$(git rev-parse --show-toplevel 2>/dev/null) || die "run from inside a git repository"
none="no audit scan of this branch found (scans of commits that are not HEAD or an ancestor are skipped; pass one with --scan <dir>). Paste a finding or run /ponytail-sec-audit."
if [ ! -e "$root/.ponytail-sec" ]; then
  [ "$mode" = list ] && exit 0  # nothing to list yet
  die "$none"
fi
if [ -L "$root/.ponytail-sec" ] || [ ! -d "$root/.ponytail-sec" ]; then
  die "$root/.ponytail-sec must be a real directory, not a symlink"
fi
base=$(cd "$root/.ponytail-sec" && pwd -P)

# True when $1 is a real directory directly under $base, named audit-* (or
# triage-* when $2 is "triage-ok"), with no symlinked state inside it.
confined() {
  local d=$1 name=${1##*/}
  # A newline (even a trailing one) would be lost by $( ) in callers.
  if [[ $d == *$'\n'* ]]; then return 1; fi
  [ "${d%/*}" = "$base" ] && [ -d "$d" ] && [ ! -L "$d" ] || return 1
  case "$name" in
    audit-*) ;;
    triage-*) [ "${2:-}" = triage-ok ] || return 1 ;;
    *) return 1 ;;
  esac
  local f
  for f in meta.json findings.json triage; do
    [ ! -L "$d/$f" ] || return 1
  done
  # Reports, evidence and PoCs are written under triage/: no links anywhere.
  [ ! -d "$d/triage" ] || [ -z "$(find "$d/triage" -type l -print -quit)" ]
}

# True when meta.json names a full commit that is HEAD or an ancestor of it.
on_branch() {
  local c
  c=$(jq -r '.commit // empty' "$1/meta.json" 2>/dev/null) || return 1
  [[ $c =~ ^[0-9a-f]{40}$ ]] && git merge-base --is-ancestor "$c" HEAD 2>/dev/null
}

# One NUL-terminated "<timestamp><TAB><dir>" record per confined scan.
# Kept out of any <( ) block: bash 3.2 (macOS /bin/bash) misparses case
# patterns and quotes in comments inside one.
list_entries() {
  local d name
  while IFS= read -r -d '' d; do
    if [[ $d == *$'\n'* || $d == *$'\t'* ]]; then continue; fi  # not one printable line
    if confined "$d" triage-ok; then
      name=${d##*/}
      printf '%s\t%s\0' "${name#*-}" "$d"
    fi
  done < <(find "$base" -mindepth 1 -maxdepth 1 -type d \( -name 'audit-*' -o -name 'triage-*' \) -print0)
}

if [ "$mode" = list ]; then
  # Newest first by the timestamp after the audit-/triage- prefix.
  while IFS= read -r -d '' entry; do
    printf '%s\n' "${entry#*$'\t'}"
  done < <(list_entries | LC_ALL=C sort -rz)
  exit 0
fi

if [ -z "$scan" ]; then
  # NUL-delimited: a directory name containing a newline cannot add candidates.
  while IFS= read -r -d '' d; do
    if confined "$d" && on_branch "$d"; then scan=$d; break; fi
    printf 'Skipped %q: symlinked state, or its commit is not HEAD or an ancestor.\n' "$d" >&2
  done < <(find "$base" -mindepth 1 -maxdepth 1 -type d -name 'audit-*' -print0 | LC_ALL=C sort -rz)
  [ -n "$scan" ] || die "$none"
else
  if [[ $scan == *$'\n'* ]]; then die "scan path must not contain a newline"; fi
  [ -d "$scan" ] || die "not a directory: $scan"
  [ ! -L "${scan%/}" ] || die "scan directory must not be a symlink: $scan"
  scan=$(cd "$scan" && pwd -P)
  if [ "$mode" = confine ]; then
    confined "$scan" triage-ok ||
      die "must be a real audit-* or triage-* directory under $base, without symlinks inside (got $scan)"
    printf '%s\n' "$scan"
    exit 0
  fi
  confined "$scan" ||
    die "scan must be a real audit-* directory under $base, without symlinks inside (got $scan)"
  on_branch "$scan" ||
    echo "WARNING: this scan's commit is not HEAD or an ancestor; it may describe other code." >&2
fi

for f in findings.json meta.json; do
  [ -f "$scan/$f" ] || die "$scan/$f is missing"
  jq -e 'type == "object"' "$scan/$f" >/dev/null 2>&1 || die "$scan/$f is not a JSON object"
  case "$(jq -r '.schema_version // empty' "$scan/$f")" in
    3) ;;
    2) die "$f is schema v2, which triage does not read. Re-run /ponytail-sec-audit; do not migrate." ;;
    *) die "$f must be schema v3" ;;
  esac
done

if command -v sha256sum >/dev/null; then
  actual=$(sha256sum "$scan/findings.json" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$scan/findings.json" | cut -d' ' -f1)
fi
expected=$(jq -r '.findings_sha256 // empty' "$scan/meta.json")
[ "$actual" = "$expected" ] ||
  echo "WARNING: findings_sha256 mismatch; findings.json changed after the audit." >&2

printf '%s\n' "$scan"
