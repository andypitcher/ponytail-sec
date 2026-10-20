#!/usr/bin/env bash
# Print the audit scan directory to triage: the latest .ponytail-sec/audit-*
# or --scan <dir>. Rejects schema v2 and warns on a findings_sha256 mismatch.
# Read-only. Usage: find-scan.sh [--scan <dir>]
set -euo pipefail

die() { echo "Error: $*" >&2; exit 1; }

scan=""
case "${1:-}" in
  --scan) [ -n "${2:-}" ] || die "--scan needs a directory"; scan=$2 ;;
  "") ;;
  *) die "usage: find-scan.sh [--scan <dir>]" ;;
esac

if [ -z "$scan" ]; then
  none="no audit scan found. Paste a finding or run /ponytail-sec-audit."
  [ -d .ponytail-sec ] || die "$none"
  scan=$(find .ponytail-sec -mindepth 1 -maxdepth 1 -type d -name 'audit-*' | LC_ALL=C sort | tail -n 1)
  [ -n "$scan" ] || die "$none"
fi

[ -d "$scan" ] || die "not a directory: $scan"
scan=$(cd "$scan" && pwd)
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
