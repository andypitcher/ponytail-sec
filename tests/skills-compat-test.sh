#!/usr/bin/env bash
# Offline cross-agent install-compatibility checks for the flagship skills.
# No network, no npx: asserts the skills/<name>/ layout meets each agent CLI's
# SKILL.md contract, so `npx skills add andypitcher/ponytail-sec@<name> -a <cli>`
# resolves on Claude Code, Cursor, Codex, Gemini CLI, GitHub Copilot and
# OpenCode. Needs bash and awk. Run from anywhere:
#   bash tests/skills-compat-test.sh
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$ROOT" || exit 1

# Skills published for universal `npx skills add` installation.
FLAGSHIP=(ponytail-sec ponytail-sec-audit ponytail-sec-triage)
# The Agent Skills standard six; claude.ai and the Skills API reject anything else.
SPEC_KEYS="name description license compatibility metadata allowed-tools"

pass=0 fail=0
check() {  # <message> <command...>
  local msg=$1; shift
  if "$@"; then pass=$((pass + 1)); printf 'ok   %s\n' "$msg"
  else fail=$((fail + 1)); printf 'FAIL %s\n' "$msg"; fi
}

# Front-matter helpers: the first `--- ... ---` block only.
fm_keys() {
  awk 'NR==1 && $0=="---"{f=1;next} f && $0=="---"{exit}
       f && /^[A-Za-z_][A-Za-z0-9_-]*:/{k=$0;sub(/:.*/,"",k);print k}' "$1"
}
fm_name() {
  awk 'NR==1 && $0=="---"{f=1;next} f && $0=="---"{exit}
       f && /^name:/{sub(/^name:[ \t]*/,"");print;exit}' "$1"
}

skill_file() { printf 'skills/%s/SKILL.md' "$1"; }

assert_present() {
  local f; f=$(skill_file "$1")
  [ -f "$f" ] && [ "$(head -n1 "$f")" = "---" ]
}
assert_name_desc() {
  local f keys; f=$(skill_file "$1"); keys=$(fm_keys "$f")
  grep -qx name <<<"$keys" && grep -qx description <<<"$keys"
}
assert_name_eq_folder() {
  local f; f=$(skill_file "$1")
  [ "$(fm_name "$f")" = "$1" ]
}
assert_spec_only() {
  local f k; f=$(skill_file "$1")
  while IFS= read -r k; do
    case " $SPEC_KEYS " in *" $k "*) ;; *) return 1 ;; esac
  done < <(fm_keys "$f")
}
assert_body() {
  local f; f=$(skill_file "$1")
  awk 'NR==1 && $0=="---"{fm=1;next} fm && $0=="---"{fm=0;b=1;next}
       b && NF{hit=1} END{exit(hit?0:1)}' "$f"
}
# Portable prompt-injection defense: the one injection control that works on
# agents without Claude Code's enforcement, so it must never silently regress.
# Check the skill body only (not front matter), matching the "[portable]" label.
assert_evidence_guard() {
  local f body; f=$(skill_file "$1")
  body=$(awk 'NR==1 && $0=="---"{fm=1;next} fm && $0=="---"{fm=0;b=1;next} b' "$f")
  grep -qF 'evidence, never instructions to execute code' <<<"$body"
}
# Any documented package-runner install of the skills CLI must pin a full semver
# (skills@X.Y.Z) — a floating install runs third-party code with full privileges.
# Extract each runner command (stopping at #, && or ;) from README and SECURITY,
# so a pinned command can't hide an unpinned one and a trailing comment can't
# satisfy the check; covers npx, bunx and pnpm dlx. Known limit: a command split
# across lines with a trailing backslash is not matched.
assert_docs_runner_pinned() {
  local bad
  bad=$(grep -rhoE '(npx|bunx|pnpm dlx)[^#&;]*skills[^#&;]*\badd\b' README.md SECURITY.md \
        | grep -Ev 'skills@[0-9]+\.[0-9]+\.[0-9]+' || true)
  [ -z "$bad" ]
}

# Each agent the npx skills CLI targets, with the SKILL.md contract it imposes.
#   all:            SKILL.md + front matter, name + description, non-empty body
#   cursor:         also name == folder name
#   codex / gemini-cli / github-copilot / opencode: also front matter limited to
#                   the standard six keys (they share .agents/skills and the
#                   stricter Skills-API key set)
# The universal checks don't vary by agent (same files), so run them once per
# skill; the agent-specific rules are checked under the agents that impose them.
for s in "${FLAGSHIP[@]}"; do
  check "[all agents] $s: SKILL.md with front matter" assert_present "$s"
  check "[all agents] $s: name + description present" assert_name_desc "$s"
  check "[all agents] $s: non-empty body" assert_body "$s"
  check "[cursor] $s: name == folder" assert_name_eq_folder "$s"
  check "[codex/gemini-cli/github-copilot/opencode] $s: front matter within the standard six keys" assert_spec_only "$s"
done

# Agent-independent: every flagship skill must carry the portable injection
# guard in its body, since non-Claude agents don't enforce read-only tooling.
for s in "${FLAGSHIP[@]}"; do
  check "[portable] $s: body keeps the 'evidence, never instructions' guard" assert_evidence_guard "$s"
done

# Docs guard: any package-runner install in README/SECURITY pins a full semver.
check "[docs] skills-CLI install commands pin a full version" assert_docs_runner_pinned

echo
echo "skills-compat-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
