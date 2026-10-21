#!/usr/bin/env bash
# List security findings as: ID · class · title · triaged yes/no.
# A finding is triaged when triage/<ID>.triage.md exists. Read-only.
# Usage: list-findings.sh [--scan <dir>]
set -euo pipefail

scan=$("$(dirname "$0")/find-scan.sh" "$@")

# Existing report names go to jq as data; finding content never reaches the shell.
reports=()
if [ -d "$scan/triage" ]; then
  while IFS= read -r f; do reports+=("${f##*/}"); done < <(
    find "$scan/triage" -maxdepth 1 -type f -name '*.triage.md')
fi

jq -r '
  (.findings.security // []) as $s
  | if ($s | map(.id) | length) != ($s | map(.id) | unique | length)
    then error("duplicate security finding IDs") else . end
  | $s[]
  | if (.id | type) == "string" and (.id | test("^S[1-9][0-9]*$")) then .
    else error("invalid security finding ID: \(.id | tostring)") end
  | (.id + ".triage.md") as $r
  | "\(.id) · \(.class | tostring | gsub("[\u0000-\u001f\u007f]"; "?")) · \(.title | tostring | gsub("[\u0000-\u001f\u007f]"; "?")) · triaged \(if any($ARGS.positional[]; . == $r) then "yes" else "no" end)"
' "$scan/findings.json" --args ${reports[@]+"${reports[@]}"}
