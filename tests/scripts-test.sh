#!/usr/bin/env bash
# Regression tests for the triage and audit scripts. Each case builds a
# throwaway git repo with .ponytail-sec/ state, including hostile layouts
# (symlinks, newline names, out-of-tree paths) found in reviews.
# Needs bash (3.2+), git and jq; portable to macOS. Run from anywhere:
#   bash tests/scripts-test.sh
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
T="$ROOT/skills/ponytail-sec-triage/scripts"
A="$ROOT/skills/ponytail-sec-audit/scripts"
pass=0 fail=0
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

ok()   { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '     %s\n' "$2"; }

# expect <name> <0|1> <grep pattern or ""> -- <command...>
# Runs the command; checks the exit status (0 = success, 1 = any failure)
# and that combined output matches the pattern (if given).
expect() {
  local name=$1 want=$2 pat=$3; shift 4
  local out rc
  out=$("$@" 2>&1); rc=$?
  # Rejections exit 1; any other code (a syntax error is 2) is a broken script.
  if { [ "$want" = 0 ] && [ "$rc" -ne 0 ]; } || { [ "$want" = 1 ] && [ "$rc" -ne 1 ]; }; then
    bad "$name" "exit $rc, wanted $( [ "$want" = 0 ] && echo success || echo failure ): ${out:0:300}"
  elif [ -n "$pat" ] && ! grep -Eq -- "$pat" <<<"$out"; then
    bad "$name" "output lacks /$pat/: ${out:0:300}"
  else
    ok "$name"
  fi
}
# refute <name> <pattern> -- <command...>: output must NOT match.
# (Output is captured first: with pipefail, a failing command piped into
# grep would read as "no match" and hide a leak.)
refute() {
  local name=$1 pat=$2 out; shift 3
  out=$("$@" 2>&1)
  if grep -Eq -- "$pat" <<<"$out"; then bad "$name" "output matched /$pat/"; else ok "$name"; fi
}

# New repo with one commit; prints its path. HEAD commit in $repo/.head.
new_repo() {
  local r; r=$(mktemp -d "$WORK/repo.XXXX")
  git -C "$r" init -q
  git -C "$r" -c user.name=t -c user.email=t@t -c core.hooksPath=/dev/null -c commit.gpgsign=false commit -q --allow-empty -m a
  mkdir -p "$r/.ponytail-sec"
  printf '%s\n' "$r"
}
head_of() { git -C "$1" rev-parse HEAD; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

# mkscan <repo> <name> <commit> [schema]: a valid scan with one hardening finding.
mkscan() {
  local d="$1/.ponytail-sec/$2" schema=${4:-3}
  mkdir -p "$d/triage"
  cat >"$d/findings.json" <<EOF
{"schema_version":$schema,"findings":{"code":[],"dependency":[],"security":[
 {"id":"S1","class":"hardening","title":"Debug endpoint always on","location":"cmd/main.go:10"}]}}
EOF
  local sum; sum=$(sha256 "$d/findings.json")
  printf '{"schema_version":%s,"commit":"%s","findings_sha256":"%s"}\n' "$schema" "$3" "$sum" >"$d/meta.json"
}

# mkreport <dir> <ID>: a valid hardening report with one evidence file.
mkreport() {
  local tdir="$1/triage" id=$2
  mkdir -p "$tdir/$id"
  printf '$ grep -n x cmd/main.go\n10: x\nexit=0\n' >"$tdir/$id/grep.txt"
  cat >"$tdir/$id.triage.md" <<EOF
---
id: $id
title: Debug endpoint always on
source: test
class: hardening
stage: 4 · Data
location: cmd/main.go:10
break_risk: Low
efficacy: Low
cwe: CWE-489
fingerprint: repo:cmd/main.go:main:always-on-debug-endpoint
vex_status: affected
evidence: [$id/grep.txt]
context:
  - "repo: cmd/main.go"
---

# $id · Debug endpoint always on
EOF
}

echo "== find-scan.sh"
R=$(new_repo); H=$(head_of "$R"); cd "$R" || exit 1
git -c user.name=t -c user.email=t@t checkout -q -b other
git -c user.name=t -c user.email=t@t -c core.hooksPath=/dev/null -c commit.gpgsign=false commit -q --allow-empty -m o; O=$(head_of "$R")
git checkout -q -
mkscan "$R" audit-20260101-000000-a "$H"
mkscan "$R" audit-20260201-000000-b "$O"
expect "picks newest scan on this branch" 0 "audit-20260101-000000-a" -- "$T/find-scan.sh"
expect "names the off-branch scan it skipped" 0 "Skipped.*audit-20260201-000000-b" -- "$T/find-scan.sh"
expect "--scan off-branch works with a warning" 0 "WARNING: this scan's commit" -- "$T/find-scan.sh" --scan .ponytail-sec/audit-20260201-000000-b
mkdir -p "$WORK/outside/audit-x"; cp .ponytail-sec/audit-20260101-000000-a/*.json "$WORK/outside/audit-x/"
expect "--scan outside .ponytail-sec rejected" 1 "must be a real audit" -- "$T/find-scan.sh" --scan "$WORK/outside/audit-x"
ln -s "$WORK/outside/audit-x" .ponytail-sec/audit-20260301-000000-lnk
expect "symlinked scan skipped in auto mode" 0 "audit-20260101-000000-a" -- "$T/find-scan.sh"
expect "--scan symlinked scan rejected" 1 "must not be a symlink|must be a real audit" -- "$T/find-scan.sh" --scan .ponytail-sec/audit-20260301-000000-lnk
rm .ponytail-sec/audit-20260301-000000-lnk
ln -s "$WORK/outside" .ponytail-sec/audit-20260101-000000-a/triage/S1
expect "symlink under triage/ rejected" 1 "must be a real audit" -- "$T/find-scan.sh" --scan .ponytail-sec/audit-20260101-000000-a
rm .ponytail-sec/audit-20260101-000000-a/triage/S1
mv .ponytail-sec/audit-20260101-000000-a/meta.json "$WORK/meta.json"; ln -s "$WORK/meta.json" .ponytail-sec/audit-20260101-000000-a/meta.json
expect "symlinked meta.json rejected" 1 "must be a real audit" -- "$T/find-scan.sh" --scan .ponytail-sec/audit-20260101-000000-a
rm .ponytail-sec/audit-20260101-000000-a/meta.json; mv "$WORK/meta.json" .ponytail-sec/audit-20260101-000000-a/meta.json
cp .ponytail-sec/audit-20260101-000000-a/*.json .
mkdir ".ponytail-sec/audit-z
."
expect "newline in a name cannot inject the repo root" 0 "audit-20260101-000000-a" -- "$T/find-scan.sh"
rm -rf ".ponytail-sec/audit-z
." meta.json findings.json
mkdir -p .ponytail-sec/triage-20260115-000000/triage
expect "--confine accepts a standalone triage-* dir" 0 "triage-20260115-000000" -- "$T/find-scan.sh" --confine .ponytail-sec/triage-20260115-000000
expect "--confine rejects a dir outside" 1 "must be a real audit" -- "$T/find-scan.sh" --confine "$WORK/outside"
first=$("$T/find-scan.sh" --list | head -n 1)
if [ "${first##*/}" = "audit-20260201-000000-b" ]; then ok "--list is newest first across kinds"
else bad "--list is newest first across kinds" "first was ${first##*/}"; fi
mkscan "$R" audit-20260401-000000-v2 "$H" 2
expect "schema v2 rejected" 1 "schema v2" -- "$T/find-scan.sh" --scan .ponytail-sec/audit-20260401-000000-v2
rm -rf .ponytail-sec/audit-20260401-000000-v2
printf '{"schema_version":3,"commit":"%s","findings_sha256":"0000"}\n' "$H" >.ponytail-sec/audit-20260101-000000-a/meta.json
expect "findings_sha256 mismatch warns" 0 "findings_sha256 mismatch" -- "$T/find-scan.sh" --scan .ponytail-sec/audit-20260101-000000-a
mkscan "$R" audit-20260101-000000-a "$H"
mv .ponytail-sec "$WORK/state"; ln -s "$WORK/state" .ponytail-sec
expect "symlinked .ponytail-sec rejected" 1 "must be a real directory" -- "$T/find-scan.sh"
rm .ponytail-sec; mv "$WORK/state" .ponytail-sec

R=$(new_repo); rmdir "$R/.ponytail-sec"
expect "--list with no .ponytail-sec prints nothing" 0 "" -- bash -c "cd '$R' && '$T/find-scan.sh' --list"
refute "--list with no .ponytail-sec has no error" "." -- bash -c "cd '$R' && '$T/find-scan.sh' --list"

echo "== previous-scan.sh"
R=$(new_repo); H=$(head_of "$R"); cd "$R" || exit 1
expect "no scans: empty output, success" 0 "" -- "$A/previous-scan.sh"
refute "no scans: prints nothing" "." -- "$A/previous-scan.sh"
mkscan "$R" audit-20260101-000000-a "$H"
mkscan "$R" audit-20260201-000000-b 0000000000000000000000000000000000000000
expect "picks the ancestor scan, skips the other" 0 "audit-20260101-000000-a" -- "$A/previous-scan.sh"
expect "names the skipped scan" 0 "Skipped.*audit-20260201-000000-b" -- "$A/previous-scan.sh"
ln -s "$WORK/outside" .ponytail-sec/audit-20260201-000000-b/triage/S9
mkscan "$R" audit-20260301-000000-c "$H"; ln -s "$WORK/outside" .ponytail-sec/audit-20260301-000000-c/triage/x
expect "scan with a symlink under triage/ skipped" 0 "audit-20260101-000000-a" -- "$A/previous-scan.sh"
mv .ponytail-sec "$WORK/state2"; ln -s "$WORK/state2" .ponytail-sec
expect "symlinked .ponytail-sec fails" 1 "must be a real directory" -- "$A/previous-scan.sh"

echo "== check-triage.sh"
R=$(new_repo); H=$(head_of "$R"); cd "$R" || exit 1
mkscan "$R" audit-20260101-000000-a "$H"; S=.ponytail-sec/audit-20260101-000000-a
mkreport "$S" S1
expect "valid report passes (no args)" 0 "OK: 1" -- "$T/check-triage.sh"
expect "valid report passes (scan dir)" 0 "OK: 1" -- "$T/check-triage.sh" "$S"
expect "valid report passes (report path)" 0 "OK: 1" -- "$T/check-triage.sh" "$S/triage/S1.triage.md"
expect "bare name from inside triage/" 0 "OK: 1" -- bash -c "cd '$S/triage' && '$T/check-triage.sh' S1.triage.md"
mkdir -p sub
expect "relative path from a subdirectory" 0 "OK: 1" -- bash -c "cd sub && '$T/check-triage.sh' '../$S/triage/S1.triage.md'"
sed -i.bak '/^stage:/d' "$S/triage/S1.triage.md"
expect "missing stage rejected" 1 "missing required key: stage" -- "$T/check-triage.sh" "$S"
mv "$S/triage/S1.triage.md.bak" "$S/triage/S1.triage.md"
sed -i.bak '/^evidence:/d' "$S/triage/S1.triage.md"
expect "missing evidence key rejected" 1 "missing required key: evidence" -- "$T/check-triage.sh" "$S"
mv "$S/triage/S1.triage.md.bak" "$S/triage/S1.triage.md"
printf 'no header\nexit=0\n' >"$S/triage/S1/grep.txt"
expect "evidence without \$ header rejected" 1 "evidence must begin" -- "$T/check-triage.sh" "$S"
printf '$ grep -n x cmd/main.go\n10: x\nexit=0\n' >"$S/triage/S1/grep.txt"
mkdir -p "$WORK/out2"; printf -- '---\nSECRET_TOKEN=abcd1234\n---\n' >"$WORK/out2/S1.triage.md"
ln -s "$WORK/out2" "$S/evil"
expect "sibling symlink path rejected" 1 "must be a real audit|must be a report" -- "$T/check-triage.sh" "$S/evil/S1.triage.md"
refute "sibling symlink path leaks nothing" "SECRET_TOKEN" -- "$T/check-triage.sh" "$S/evil/S1.triage.md"
expect "triage/../ detour rejected" 1 "must be a real audit|must be a report" -- "$T/check-triage.sh" "$S/triage/../evil/S1.triage.md"
refute "triage/../ detour leaks nothing" "SECRET_TOKEN" -- "$T/check-triage.sh" "$S/triage/../evil/S1.triage.md"
rm "$S/evil"
expect "dir outside .ponytail-sec rejected" 1 "must be a real audit" -- "$T/check-triage.sh" "$WORK/out2"

echo "== build-index.sh, shell-summary.sh, list-findings.sh"
expect "build-index writes index.json for an audit scan" 0 "Wrote .*index.json" -- "$T/build-index.sh" "$S"
if jq -e '.findings[0].id == "S1"' "$S/triage/index.json" >/dev/null; then ok "index.json lists S1"
else bad "index.json lists S1"; fi
P=.ponytail-sec/triage-20260115-000000; mkdir -p "$P"; mkreport "$P" P1
expect "build-index works on a standalone triage-* dir" 0 "Wrote .*index.json" -- "$T/build-index.sh" "$P"
expect "shell-summary prints the finding" 0 "P1 .*affected · evidence: 1" -- "$T/shell-summary.sh" "$P"
expect "build-index refuses a dir outside" 1 "must be a real audit" -- "$T/build-index.sh" "$WORK/out2"
rm -f "$P/triage/index.json"; ln -s "$WORK/out2" "$P/triage/index.json"
expect "build-index refuses a symlinked index.json" 1 "must be a real audit" -- "$T/build-index.sh" "$P"
if [ "$(find "$WORK/out2" -mindepth 1 | wc -l)" -eq 1 ]; then ok "nothing written outside"
else bad "nothing written outside" "$(find "$WORK/out2" -mindepth 1)"; fi
rm "$P/triage/index.json"
expect "list-findings prints id, title and location" 0 "S1 · hardening · Debug endpoint always on · cmd/main.go:10 · triaged yes" -- "$T/list-findings.sh" --scan "$S"

echo
echo "scripts-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
