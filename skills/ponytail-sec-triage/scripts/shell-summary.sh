#!/usr/bin/env bash
# Print one line per triaged finding, e.g.
#   S1  Vulnerability  Severity: High CVSS-B 8.1 → 7.3 (CVSS-BTE)  affected · evidence: 2  fix: proposed (break-risk Medium)
# Usage: shell-summary.sh [<dir>]   (default: the latest audit scan)
set -euo pipefail

here=$(dirname "$0")
dir=${1:-$("$here/find-scan.sh")}

"$here/check-triage.sh" --json "$dir" | jq -r '
  def pad($n): tostring | . + (" " * ([$n - length, 0] | max));
  sort_by(.id[:1], (.id[1:] | tonumber))[]
  | ((if .class == "vulnerability" then
       "Severity: \(.severity) "
       + (if has("cvss_score_audit") then "CVSS-B \(.cvss_score_audit) → \(.cvss_score) (\(.cvss_nomenclature))"
          else "\(.cvss_nomenclature) \(.cvss_score)" end)
     else "Efficacy: \(.efficacy) \(.cwe)" end)
    + (if has("reclassified_from") then " (was \(.reclassified_from))" else "" end)) as $rating
  | "\(.id | pad(3)) \(.class | ascii_downcase | (.[:1] | ascii_upcase) + .[1:] | pad(14)) \($rating | pad(46)) "
    + "\(.vex_status) · evidence: \(.evidence | length)  fix: \(if .vex_status == "not_affected" then "not needed" else "proposed (break-risk \(.break_risk))" end)"
'
