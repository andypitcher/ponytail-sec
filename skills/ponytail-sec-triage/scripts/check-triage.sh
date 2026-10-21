#!/usr/bin/env bash
# Validate the YAML frontmatter of triage reports. Read-only.
# Usage: check-triage.sh [--json] [<report.triage.md | scan-dir>...]
#   No path: every report under the latest scan's triage/.
#   A directory: every report under <dir>/triage/.
#   --json: when all reports are valid, print their frontmatter as a JSON array.
# Frontmatter is a flat subset of YAML: `key: value`, inline `[a, b]` lists of
# simple tokens, and block lists (`- "item"`) for anything with commas. Quote
# strings with double quotes only.
set -euo pipefail

json=0
[ "${1:-}" = "--json" ] && { json=1; shift; }

files=()
add_dir() {
  [ -d "$1/triage" ] || return 0
  while IFS= read -r f; do files+=("$f"); done < <(
    find "$1/triage" -maxdepth 1 -type f -name '*.triage.md' | LC_ALL=C sort)
}
if [ "$#" -eq 0 ]; then
  scan=$("$(dirname "$0")/find-scan.sh")
  add_dir "$scan"
fi
for p in "$@"; do
  if [ -d "$p" ]; then add_dir "$p"; else files+=("$p"); fi
done
[ "${#files[@]}" -gt 0 ] || { echo "Error: no triage reports found" >&2; exit 1; }

status=0
out=()
for file in "${files[@]}"; do
  [ -f "$file" ] || { echo "$file: not a file" >&2; status=1; continue; }
  tdir=$(dirname "$file")
  # Evidence files that exist, relative to triage/, are passed as data.
  evidence=()
  evidence_files='[]'
  while IFS= read -r -d '' epath; do
    e=${epath#"$tdir"/}
    evidence+=("$e")
    evidence_files=$(jq --arg path "$e" --rawfile content "$epath" \
      '. + [{path: $path, content: $content}]' <<<"$evidence_files")
  done < <(find "$tdir" -mindepth 2 -type f -print0)

  result=$(jq -R -s --arg name "${file##*/}" --argjson evidence_files "$evidence_files" '
    def unq:
      if test("^\".*\"$") then (try fromjson catch error("bad quoted string: \(.)"))
      else . end;
    def trim: gsub("^\\s+|\\s+$"; "");
    def scalar:
      trim
      | if . == "" or . == "null" or . == "~" then null
        elif test("^\\[.*\\]$") then .[1:-1] | trim
          | if . == "" then [] else split(",") | map(trim | unq) end
        elif test("^-?[0-9]+(\\.[0-9]+)?$") then tonumber
        else unq end;

    def parse:
      split("\n") as $l
      | if $l[0] != "---" then error("no YAML frontmatter") else . end
      | (first(range(1; $l | length) as $i | select($l[$i] == "---") | $i)
         // error("frontmatter is not closed")) as $end
      | reduce $l[1:$end][] as $line ({obj: {}, cur: null};
          if ($line | test("^\\s*(#.*)?$")) then .
          elif ($line | test("^[A-Za-z_][A-Za-z0-9_]*:")) then
            ($line | capture("^(?<k>[A-Za-z_][A-Za-z0-9_]*):(?<v>.*)$")) as $m
            | if ($m.k as $k | .obj | has($k)) then error("duplicate key: \($m.k)") else . end
            | .obj[$m.k] = ($m.v | scalar)
            | .cur = (if ($m.v | trim) == "" then $m.k else null end)
          elif .cur != null and ($line | test("^\\s*-\\s")) then
            .cur as $k
            | .obj[$k] = ((.obj[$k] // []) + [$line | sub("^\\s*-\\s"; "") | scalar])
          else error("unsupported frontmatter line: \($line)") end)
      | .obj;

    def band: if . >= 9 then "Critical" elif . >= 7 then "High"
              elif . >= 4 then "Medium" elif . > 0 then "Low" else "None" end;

    def check:
      . as $f
      | ["severity", "cvss", "cvss_score", "cvss_nomenclature"] as $vuln
      | ["efficacy", "cwe"] as $hard
      | [
          ((["id", "title", "source", "class", "stage", "location", "break_risk",
            "fingerprint", "vex_status", "evidence", "context"]
           + (if $f.class == "vulnerability" then $vuln
              elif $f.class == "hardening" then $hard else [] end))[]
          | select(. as $k | $f | has($k) | not) | "missing required key: \(.)"),
          ($f | to_entries[] | select(.value == null)
           | "\(.key) is null; omit keys that do not apply"),
          ($f | to_entries[] | select(.value | type == "array")
           | select(any(.value[]; . == null)) | "\(.key) has a null entry"),
          (select(($f.id | type) != "string" or ($f.id | test("^[SP][1-9][0-9]*$") | not))
           | "id must be S<n> (audit) or P<n> (pasted)"),
          (select(($f.id | type) == "string" and $name != "\($f.id).triage.md")
           | "file name must be \($f.id).triage.md"),
          (select($f.class | IN("vulnerability", "hardening") | not)
           | "class must be vulnerability or hardening"),
          (select($f.break_risk | IN("High", "Medium", "Low") | not)
           | "break_risk must be High, Medium, or Low"),

          # Keys from the other class.
          (select($f.class == "vulnerability")
           | ("efficacy", "efficacy_score", "cwe") | select(. as $k | $f | has($k))
           | "\(.) is not allowed on a vulnerability"),
          (select($f.class == "hardening")
           | ($vuln[], "cve", "cvss_score_audit", "efficacy_score")
           | select(. as $k | $f | has($k))
           | "\(.) is not allowed on hardening"),

          # Vulnerability measurements.
          (select($f.class == "vulnerability" and has("cvss"))
           | select(($f.cvss | type) != "string" or ($f.cvss | startswith("CVSS:4.0/") | not))
           | "cvss must start with CVSS:4.0/"),
          (select($f.class == "vulnerability" and has("cvss_score"))
           | if ($f.cvss_score | type) != "number" then "cvss_score must be a number"
             elif $f.cvss_score < 0 or $f.cvss_score > 10 then
               "cvss_score must be between 0 and 10"
             elif $f.severity != ($f.cvss_score | band) then
               "severity \($f.severity) does not match cvss_score \($f.cvss_score) (expected \($f.cvss_score | band))"
             else empty end),
          (select(has("cvss_score_audit"))
           | if ($f.cvss_score_audit | type) != "number" then
               "cvss_score_audit must be a number"
             elif $f.cvss_score_audit < 0 or $f.cvss_score_audit > 10 then
               "cvss_score_audit must be between 0 and 10"
             else empty end),
          (select(has("cvss_score_audit") and $f.cvss_score_audit == $f.cvss_score)
           | "cvss_score_audit is only set when the score changed"),
          (select(has("cve") and (($f.cve | type) != "string" or ($f.cve | test("^CVE-[0-9]{4}-[0-9]{4,}$") | not)))
           | "cve must be a CVE-YYYY-NNNN ID"),
          (select($f.class == "vulnerability" and ($f.cvss | type) == "string")
           | ($f.cvss | test("/E:[APU](/|$)")) as $t
           | ($f.cvss | test("/(CR|IR|AR|MAV|MAC|MAT|MPR|MUI|MVC|MVI|MVA|MSC|MSI|MSA):[^X/]")) as $e
           | ("CVSS-B" + (if $t then "T" else "" end) + (if $e then "E" else "" end)) as $want
           | select($f.cvss_nomenclature != $want)
           | "cvss_nomenclature must be \($want) for this vector"),

          # Hardening measurements.
          (select($f.class == "hardening" and has("efficacy"))
           | select($f.efficacy | IN("High", "Medium", "Low") | not)
           | "efficacy must be High, Medium, or Low"),
          (select($f.class == "hardening" and has("cwe"))
           | select(($f.cwe | type) != "string" or ($f.cwe | test("^CWE-[0-9]+$") | not))
           | "cwe must be CWE-<n>"),

          # Fingerprint: <repo>:<path>:<symbol>:<weakness-class>, no line numbers.
          (select(($f.fingerprint | type) != "string")
           | "fingerprint must be a string"),
          (select(($f.fingerprint | type) == "string")
           | ($f.fingerprint | split(":")) as $p
           | if ($p | length) != 4 or any($p[]; . == "") then
               "fingerprint must be <repo>:<path>:<symbol>:<weakness-class>"
             elif any($p[]; test("^[0-9]+$")) or ($p[1] | test("#L[0-9]")) then
               "fingerprint must not contain a line number"
             elif ($p[3] | test("^[a-z0-9]+(-[a-z0-9]+)*$") | not) then
               "fingerprint weakness-class must be lowercase and hyphenated"
             else empty end),

          # VEX.
          (select($f.vex_status | IN("affected", "not_affected", "under_investigation", "fixed") | not)
           | "vex_status must be affected, not_affected, or under_investigation"),
          (select($f.vex_status == "fixed") | "vex_status fixed is never set by triage"),
          (select(($f.evidence | type) != "array") | "evidence must be a list"),
          (select(($f.context | type) != "array") | "context must be a list"),
          (select($f.vex_status == "affected" and (($f.evidence | length) == 0))
           | "affected needs at least one evidence file; use under_investigation"),
          (select($f.vex_status == "not_affected")
           | if ($f.vex_justification | IN("component_not_present", "vulnerable_code_not_present",
                   "vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary",
                   "inline_mitigations_already_exist") | not)
             then "not_affected needs an OpenVEX vex_justification"
             elif ($f.context | length) == 0 then "not_affected needs a source in context"
             else empty end),
          (select(has("vex_justification") and $f.vex_status != "not_affected")
           | "vex_justification is only set when not_affected"),
          (select(($f.evidence | type) == "array") | $f.evidence[]
           | select(type != "string" or test("(^|/)\\.\\.(/|$)") or
                    (startswith("\($f.id)/") | not))
           | "evidence entry must be a file under triage/\($f.id)/: \(tostring)"),
          (select(($f.evidence | type) == "array") | $f.evidence[]
           | select(type == "string") | . as $e
           | select(any($ARGS.positional[]; . == $e) | not)
           | "evidence file not found: \(.)"),
          (select(($f.evidence | type) == "array") | $f.evidence[]
           | select(type == "string") as $e
           | select($e | test("(^|/)poc(/|$)"))
           | "evidence must not be a PoC source file: \($e)"),
          (select(($f.evidence | type) == "array") | $f.evidence[]
           | select(type == "string") as $e
           | ($evidence_files[] | select(.path == $e) | .content
              | sub("\\s+$"; "") | split("\n")) as $lines
           | select((($lines[0] | sub("\\r$"; "") | test("^\\$ .+")) | not)
                    or (($lines[-1] | sub("\\r$"; "") | test("^exit=[0-9]+$")) | not))
           | "evidence must begin with a $ <command> header and end with exit=<status>: \($e)"),

          (select(has("reclassified_from"))
           | select(($f.reclassified_from | IN("vulnerability", "hardening") | not)
                    or $f.reclassified_from == $f.class)
           | "reclassified_from must be the other class"),
          (select(has("agent") and $f.agent != "inline") | "agent may only be inline")
        ];

    (try (parse | {fm: ., errors: check}) catch {fm: null, errors: [.]})
    | .fm += (if .fm then {report: $name} else null end)
  ' "$file" --args ${evidence[@]+"${evidence[@]}"})

  # Errors can quote file content; strip control characters before printing.
  errors=$(jq -r '.errors[] | gsub("[\u0000-\u001f\u007f]"; "?")' <<<"$result")
  if [ -n "$errors" ]; then
    while IFS= read -r e; do printf '%s: %s\n' "$file" "$e"; done <<<"$errors" >&2
    status=1
  else
    out+=("$(jq -c '.fm' <<<"$result")")
  fi
done

if [ "$status" -eq 0 ] && [ "$json" -eq 1 ]; then
  printf '%s\n' "${out[@]}" | jq -s .
elif [ "$status" -eq 0 ]; then
  echo "OK: ${#files[@]} triage report(s) valid"
fi
exit "$status"
