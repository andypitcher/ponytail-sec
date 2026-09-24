---
name: ponytail-sec-audit
description: >
  Full project security audit. Scans the entire codebase across three passes:
  code that shouldn't exist, all dependencies assessed, all security findings.
  Produces a comprehensive numbered report with blast-radius narrative.
  Persists findings to .ponytail-sec/ for cross-scan tracking.
  For per-diff review use ponytail-sec instead.
license: MIT
---

  The lazy senior security engineer. The best vuln is the one you make
  unreachable with the smallest change.

  ## Existing Findings

  - Previous audit reports (newest first): !`find .ponytail-sec -maxdepth 1 -type d -name "audit-*" -print 2>/dev/null | sort -r`

  When previous reports exist, read the most recent `findings.json` and compare
  with the current scan results. `findings.json` holds three typed buckets —
  `code`, `dependency`, `security`. Walk each bucket and compare **within the
  same type**; never match a code finding against a security finding.

  - **Resolved** — a previous finding no longer appears in its bucket (same location + issue gone). Mark it ✅.
  - **Recurring** — same bucket, same location, same issue still present. Mark it 🔁.
  - **Regression** — a new finding in a location that was previously clean. Mark it 🔴.

  A recurring security finding **inherits the previous triage** — its `class`,
  `cvss` and `status` carry forward rather than being re-derived. A finding
  triaged down to hardening must not re-report as a scored vulnerability on the
  next scan. Say so on the row's delta line when it happened:

  > 🔁 recurring — triaged as hardening, CVSS-BTE 6.1 (E:U, MAV:A — private
  > management network)

  Open the report with a delta summary line when a previous scan exists:

  > **Delta since last audit (`audit-<previous-timestamp>`):** X resolved, Y recurring, Z new.

  If no previous reports exist, skip the delta summary and proceed normally.

  ## Scope

  The entire project. All source files, Dockerfiles, manifests, config, and
  dependency declarations. If the project is large, prioritise: auth paths,
  TLS configuration, shell exec, dependency resolvers, and shipped config.

  ## Ranking model

  Fix lower layers first. A network control does not excuse skipping a code fix.

  ```
  Layer 4 · Code       verify=False, InsecureSkipVerify          ← must-fix
  Layer 3 · Auth       OAuth 2.1, JWT audience / issuer / alg    ← must-fix
  Layer 2 · Transport  TLS with verified CA                       ← must-fix
  Layer 1 · Network    NetworkPolicy (default-deny)               ← should-do
  Layer 0 · Mesh       Istio mTLS                                 ← additive only
  ```

  ## Break-risk — applies to all three passes

  **Break-risk** is confidence that the *fix* could break functionality, based on
  what static review can verify. It is orthogonal to severity, and every finding
  in every pass carries one — code, dependency, and security alike.

  - **Low** — additive, or provably-unused removal (nothing references it). Apply freely.
  - **Med** — tightening that may reject real inputs/flows not visible in the read.
  - **High** — removing/narrowing a grant, capability, or class whose consumers can
    live outside the files reviewed (RBAC, shared service accounts, host mounts,
    hooks, reflection). Static review is blind here.

  Med/High findings of **any type** carry the ⚠️ validate-at-runtime line below.

  ## Three passes, in order

  ### Pass 1 — Code review

  Does this code need to exist at all? YAGNI, stdlib first, remove over
  refactor. Fewer lines = smaller attack surface. Dead code and unrequested
  abstractions are security debt.

  ### Pass 2 — Dependency assessment

  Every dependency is supply-chain surface — any language (npm, PyPI, Maven,
  Cargo, Go modules, etc.). For each, web-search the registry page and OpenSSF
  Scorecard before judging — do not assess from name alone. Check: last release
  date, number of contributors, individual vs. company/org maintainer, presence
  of SECURITY.md, and OpenSSF Scorecard maintained score.

  - Does stdlib or the platform already do this? → **remove**.
  - Solo maintainer, low OpenSSF Scorecard, stale commits, no security policy? → **fork or vendor** and flag the risk.
  - Brings more than it costs, healthy upstream? → **keep, pin immutably**:
    exact version + lockfile for package deps, commit hash for VCS deps, digest
    for container images.

  Prefer: remove > stdlib > vendor/fork > immutable pin > keep floating.

  This pass judges supply-chain **health** — who maintains it, is it stale,
  should it exist at all. Enumerating published CVEs in third-party packages is
  out of scope for now; that is scanner work, tracked separately.

  ### Pass 3 — Security findings

  Kill-chain stages in order. A Stage 1 break voids all downstream defences.
  Rank within a stage by attacker leverage removed ÷ lines changed.

  - Stage 1 · Trust: TLS cert bypass, token validation gaps, auth bypass modes.
  - Stage 2 · Authz: RBAC wildcards, server-side claim validation, write/read separation.
  - Stage 3 · Exec: container escape surface, supply chain, shell injection, deserialization.
  - Stage 4 · Data: hardcoded secrets, debug endpoints, missing TLS, verbose logging.

  Tags: `auth` `rbac` `isolate` `dep` `inject` `secret` `expose`

  Every security finding carries a **class**. The triage is practical, not
  forensic — it exists so a reader can sort "there's a way in" from
  "tighten this", and it decides what the `Sev` cell holds:

  - `vulnerability` — behaviour contradicts the product's own documented
    contract: privilege escalation, auth bypass, injection, path traversal,
    unsafe deserialization, hardcoded credential material. Something is broken
    and an attacker acts on it. **Carries a score and a vector.**
  - `hardening` — behaviour matches the documented contract, but the permissive
    option is the default, or a control is missing or too loose (ungated debug
    endpoint, RBAC wildcard, missing TLS). Nothing is broken; you would rather
    it did less. **Carries a CWE and a priority, no score** — CVSS 4.0 base is
    impact-dominated and would misrank the row against real vulnerabilities.

  Two things that look like findings and are not:

  - A **documented trust-model decision** — an agent that must hold
    cluster-admin to function, a controller that by design reads every
    namespace. Name it in the blast-radius paragraph as the perimeter; do not
    emit a row.
  - **Correctness items** — stale comments, missing timeouts, absent test
    coverage. Out of scope per Boundaries; they go to ponytail. Do not score
    them, and do not emit a row.

  **Published CVEs in third-party dependencies are out of scope.** Do not
  enumerate advisories for packages this project consumes. That boundary is
  load-bearing: a stream of pre-scored advisory findings, each fixed by a version
  bump, would outrank and bury the one small change that actually closes an
  attack path.

  The exception: if project code *misuses* a dependency in a way that creates an
  exploitable path, that is a `vulnerability` at the call site — the finding is
  the call, and the fix is the call, not the version.

  ## Output format

  Emit three sections. No cap on findings — this is the full audit.

  Findings are numbered with a type prefix, and the same prefixed IDs are used
  in the tables, in `findings.json`, and in `expand N`:

  - `C1`, `C2` … — code findings
  - `D1`, `D2` … — dependency findings
  - `S1`, `S2` … — security findings

  ---

  ### Pass 1 · Code

  Prose commentary, one paragraph per file with findings. `Clean.` for files
  with nothing to remove. State the security consequence, not just the smell.
  Give each finding an ID and a break-risk.

  Example:
  > `C1` `ProcessManager.scala`: The interactive `bash -i` actor (lines 17–56)
  > exists solely to shell-exec commands replaceable with `ProcessBuilder`. Every
  > string reaching its mailbox executes verbatim — delete the class.
  > **Break-risk: High** — the actor may be addressed by name from config or
  > another subsystem.
  >
  > `ClientSslConfig.scala`: **Clean.**

  ---

  ### Pass 2 · Dependencies

  One sentence if clean. One evidence block per risky dep:

  - **Verdict** — remove / stdlib / vendor or fork / keep with immutable pin.
  - **Upstream** — link to the exact pinned version where one exists, otherwise
    to the latest version. Registry page preferred (pkg.go.dev, npmjs.com,
    pypi.org, crates.io, Maven Central).
  - **Maintainer** — individual, company, foundation, or active org.
  - **Freshness** — last release date and last meaningful commit/activity.
  - **Security posture** — `SECURITY.md`, advisory handling, responsiveness.
  - **OpenSSF Scorecard** — maintained score and any standout risk signals.
  - **Action** — exact replacement, vendoring/forking plan, or immutable pinning.
  - **Break-risk** — an immutable pin is Low; `remove`/`vendor` is Med or High.

  Example:
  > `D1` `build.sbt` HTTP resolvers (spray.io, bintray, sonatype staging,
  > download.java.net, geomajas) → **remove**: all 5 on Maven Central over
  > HTTPS; `withAllowInsecureProtocol(true)` is live MITM surface on the build
  > network. **Break-risk: Med** — an artifact may resolve only from one of them.

  ---

  ### Pass 3 · Security findings

  All findings, numbered (`S1`, `S2` …), stage order.

  The `Sev` cell takes one of two forms, decided by the finding's class:

  - **Vulnerability** — `CVSS-B <score>`, e.g. `CVSS-B 9.3`. Label every score
    with its FIRST nomenclature: `CVSS-B` = base only, `CVSS-BT` = +threat,
    `CVSS-BE` = +environmental, `CVSS-BTE` = all three. The audit emits
    `CVSS-B` (optionally `CVSS-BT`); it has no standing to assert environmental
    metrics. The prefix puts the base-only caveat in the row, where it is read.
  - **Hardening** — `Hardening · CWE-nnnn · <Low|Med|High>`, e.g.
    `Hardening · CWE-1188 · Med`. No score. The CWE maps the finding to a
    CIS / OWASP ASVS / STIG control, which is real work; on a scored
    vulnerability it is ceremony, so it appears on hardening rows only.

  Per FIRST: *"CVSS Base (CVSS-B) scores are designed to measure the severity of
  a vulnerability and should not be used alone to assess risk."* A hardening
  item is not a vulnerability, and a base score on one will be
  impact-dominated — preconditions barely move the macrovector — so it would
  outrank genuine breaks.

  Compute the full CVSS 4.0 vector **now**, at table time, for every
  vulnerability — it must be persisted to `findings.json`, so it cannot be
  deferred to `expand N`. Set the vector to the *reasonable* worst case, which
  FIRST defines as "the worst-case after any unreasonable high-impact
  low-likelihood paths have been discounted" — discount those paths in the
  vector rather than scoring `AC:L` and caveating in prose afterwards.

  | #  | Sev            | Stage     | Location | Finding | Fix | Break-risk |
  |----|----------------|-----------|----------|---------|-----|-----------|
  | S1 | `CVSS-B 9.3` | 1 · Trust | `ClientSslConfig.scala:43` | `auth` `DummyTrustManager` — `checkServerTrusted()` no-op; all manager→controller HTTPS MITMable | Load CA cert into real `TrustManagerFactory` | Low |
  | S2 | `CVSS-B 8.1` | 3 · Exec  | `ProcessManager.scala:34` | `inject` actor message interpolated into `bash -i` — any sender achieves RCE | Replace with `ProcessBuilder`, no shell | Med |
  | S3 | `Hardening · CWE-1188 · Med` | 1 · Trust | `values.yaml:21` | `auth` permissive TLS trust mode is the shipped default; `strict` exists and is documented | Ship `strict` as the default | High |
  | S4 | `Hardening · CWE-269 · High` | 2 · Authz | `rbac.yaml:30` | `rbac` operator SA granted `secrets: ["*"]`; no code path reads Secrets | Drop the grant | High |

  Emit the computed vectors immediately below the table, one per line — not as a
  column, which would make the table unreadable. Vulnerabilities only; a
  hardening row has no vector:

  ```
  Vectors:
    S1  CVSS-B 9.3 · CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
    S2  CVSS-B 8.1 · CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
  ```

  A vulnerability's score = impact if exploited; a hardening priority = how
  soon you would want the default changed. Break-risk is orthogonal to both —
  see the section above.

  `kill-chain: N paths found.`

  Close with two paragraphs:

  **Paragraph 1 — blast radius.** 3–4 sentences: what the top findings enable
  for an attacker, which are pre-existing vs. newly introduced, which are
  already partially mitigated by other controls in the stack. Name any
  documented trust-model decision here as the perimeter — it belongs in this
  paragraph, not in the table.

  **Paragraph 2 — "if I were you".** A frank prioritisation that may differ
  from the CVSS ranking. A higher score does not automatically mean higher
  priority — consider: is it actually reachable given the deployment? Do
  existing controls (network policy, WAF, auth layer) reduce its practical
  urgency? Does fixing one finding make another redundant? Name 2–3 specific
  findings to start with and say why — not because of their score, but because
  of their real-world leverage. Be direct: "I'd start with `S1` because…"

  End with one conversational sentence inviting the user to dig deeper.

  Example closing:
  > `S1` is the critical path — a network-adjacent attacker who MITMs the
  > manager→controller link owns the entire cluster before auth is checked.
  > `S2` becomes exploitable from anywhere that can reach the actor, and lives
  > in a class Pass 1 already recommends deleting outright. `S3` and `S4` are
  > hardening: the permissive trust mode is documented and has a one-setting
  > opt-out, and the operator SA's cluster-admin grant is the trust model this
  > product ships with — that grant is the perimeter, not a finding.
  >
  > If I were you I'd start with `S1` and `S2` — deleting the actor closes `S2`
  > and shrinks the surface `S3` sits on. `S4` is a sprint item not a hotfix;
  > your build isolation is likely compensating.
  >
  > If you'd like to dig into any finding — why it's exploitable, what an
  > attacker does with it, or a concrete fix — just ask by number.

  When the user asks about a finding by number, emit:
  - **Root cause** — 1 sentence. Append the labelled CVSS 4.0 score and vector
    already computed for the table on the same line; do not recompute it. For a
    hardening finding there is no vector — append the CWE instead.
  - **Exploit scenario** — 1 sentence: what the attacker does and what they gain.
  - **Fix** — invoke ponytail on the affected file/snippet for the minimal diff.
    Do not write the fix inline; delegate to ponytail.

  ## Persistence — save findings to disk

  After emitting the report to the user, persist the results so future scans
  can compare. Follow these steps exactly:

  1. Capture the UTC timestamp (use the same value throughout):
     ```
     SCAN_TS=$(date -u +%Y%m%d-%H%M%S)
     ```

  2. Create the output directory:
     ```
     mkdir -p .ponytail-sec
     SCAN_DIR=$(mktemp -d .ponytail-sec/audit-${SCAN_TS}-XXXXXX)
     ```

  3. Write `${SCAN_DIR}/report.md` — the full audit output
     (all three passes, exactly as emitted to the user).

  4. Write `${SCAN_DIR}/findings.json` — every finding from **all three passes**,
     in three typed buckets. Schema:
     ```json
     {
       "schema_version": 2,
       "findings": {
         "code": [
           {
             "id": "C1",
             "type": "code",
             "location": "internal/ssl/client.go:31",
             "finding": "sync.Once caches the CA cert pool at first request; a CA rotation is silent until process restart",
             "consequence": "Rotated CA is not honoured, so revoked intermediates stay trusted for the life of the pod",
             "fix": "Drop the sync.Once and load the pool per-dial",
             "break_risk": "Low",
             "status": "open"
           }
         ],
         "dependency": [
           {
             "id": "D1",
             "type": "dependency",
             "location": "go.mod:24",
             "package": "github.com/tidwall/gjson",
             "ecosystem": "go",
             "current_version": "v1.14.0",
             "upstream_url": "https://pkg.go.dev/github.com/tidwall/gjson@v1.14.0",
             "pinned": true,
             "verdict": "stdlib",
             "finding": "Solo maintainer, used in one call site that encoding/json already covers",
             "maintainer": "individual",
             "last_release": "2023-11-02",
             "scorecard": 4.1,
             "fix": "Replace the single call with encoding/json; drop the require",
             "break_risk": "Low",
             "status": "open"
           }
         ],
         "security": [
           {
             "id": "S1",
             "type": "security",
             "class": "hardening",
             "severity": "Hardening · CWE-1188 · Med",
             "cwe": "CWE-1188",
             "cvss": null,
             "cvss_score": null,
             "stage": "4 · Data",
             "location": "internal/cmd/controller/root.go:147",
             "tags": ["expose"],
             "finding": "net/http/pprof on localhost:6060 started unconditionally in the controller while the agent gates the identical block behind FLEET_AGENT_PPROF_DISABLED",
             "fix": "Apply the same env gate the agent already uses",
             "break_risk": "Low",
             "status": "open"
           },
           {
             "id": "S2",
             "type": "security",
             "class": "vulnerability",
             "severity": "CVSS-B 8.1",
             "cwe": null,
             "cvss": "CVSS-B 8.1 · CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
             "cvss_score": 8.1,
             "stage": "3 · Exec",
             "location": "internal/exec/manager.go:34",
             "tags": ["inject"],
             "finding": "Job name is interpolated into a shell command string passed to sh -c; any caller that controls the name achieves command execution",
             "fix": "Use exec.Command with an argument slice; drop the shell",
             "break_risk": "Med",
             "status": "open"
           }
         ]
       }
     }
     ```
     - `status` is one of `open`, `triaged`, `accepted-risk`, `resolved`. New
       findings are `"open"`. A finding that recurs keeps the `class`, `cvss`
       and `status` carried forward from the previous `findings.json` — a
       triage decision must survive a re-scan, or every future audit re-reports
       a downgraded finding at its original score.
     - IDs carry their type prefix (`C`/`D`/`S`) and match the report tables.
     - `class` is `vulnerability` or `hardening`, and decides the rest:
       a vulnerability carries `cvss`/`cvss_score` and `cwe: null`; a hardening
       finding carries `cwe` and `cvss: null`, `cvss_score: null`.
     - `severity` is the `Sev` cell verbatim — `"CVSS-B 8.1"` or
       `"Hardening · CWE-1188 · Med"`.
     - `cvss` is the labelled score and full vector, `"<nomenclature> <score> ·
       CVSS:4.0/…"`. The audit emits `CVSS-B` (optionally `CVSS-BT`) for
       vulnerabilities and `null` for hardening. Triage may later replace it
       with a `CVSS-BTE` score, and must state in the finding which metrics
       were modified and why — `MAV`, `CR`/`IR`/`AR` assert facts about a
       deployment that a repository scan has no standing to set.
     - `cvss_score` is a JSON **number** (or `null`) and must agree with the
       score in `cvss`.
     - **CVSS fields apply to `security` findings only.** Never invent a
       `cvss`, `cvss_score`, or `cwe` for a code or dependency finding — those
       carry `break_risk` (and, for deps, `verdict`) as their signal. A
       fabricated score is worse than no score.
     - `break_risk` is required on every finding of every type.
     - `upstream_url` points at the exact pinned version, or the latest version
       when the dep is unpinned.
     - Each bucket may be an empty array, but always emit all three keys.
     - Extra keys are allowed where triage needs them (e.g. a note recording
       why a score was modified); the keys above are the required floor.
     - Validate: the file must be valid JSON (no trailing commas, no comments).

  5. Compute the integrity digest of `findings.json`. Do this **after** the file
     is written and final — the digest covers `findings.json` only, never
     `meta.json` itself:
     ```
     command -v sha256sum >/dev/null \
       && FINDINGS_SHA=$(sha256sum "${SCAN_DIR}/findings.json" | cut -d' ' -f1) \
       || FINDINGS_SHA=$(shasum -a 256 "${SCAN_DIR}/findings.json" | cut -d' ' -f1)
     ```
     `sha256sum` is absent on macOS, hence the `shasum` fallback.

  6. Collect scan cost. **Detect only — never install anything.** If a usage CLI
     is already present on PATH, read from it; otherwise emit nulls. Do not run
     `npx`, `bunx`, `pnpm dlx`, or any package-runner invocation: those fetch and
     execute remote code at scan time, which this skill must never do, and an
     unpinned `@latest` fetch is precisely what Pass 2 tells users to avoid.

     ```
     if command -v ccusage >/dev/null 2>&1 &&
          USAGE_JSON=$(ccusage session --json --offline 2>/dev/null); then
         USAGE_SOURCE="ccusage"
       else
         USAGE_JSON='{}'
         USAGE_SOURCE="unavailable"
       fi
     INPUT_TOKENS=$(echo "$USAGE_JSON" | jq '.input_tokens // null')
     OUTPUT_TOKENS=$(echo "$USAGE_JSON" | jq '.output_tokens // (if (.input_tokens != null and .output_tokens != null) then .input_tokens + .output_tokens else null end)')
     TOTAL_TOKENS=$(echo "$USAGE_JSON" | jq '.total_tokens // (if (.input_tokens != null and .output_tokens != null) then .input_tokens + .output_tokens else null end)')
     ESTIMATED_COST=$(echo "$USAGE_JSON" | jq '.total_cost // null')
     MODEL=$(echo "$USAGE_JSON" | jq -r '.model // "unknown"')
     ```

     `--offline` uses cached pricing rather than reaching the network mid-scan.

     **Never estimate, extrapolate, or invent token counts or dollar figures.** A
     fabricated cost is worse than an absent one; `null` is a truthful "not
     measurable in this runtime". Same standard as CVSS on non-security findings.

     If the user wants cost tracking, point them at the upstream project and let
     them install it themselves, pinned:
     `https://github.com/ccusage/ccusage`

  7. Write `${SCAN_DIR}/meta.json`:
     ```json
     {
       "schema_version": 2,
       "timestamp": "2026-08-24T15:30:00Z",
       "commit": "<output of git rev-parse HEAD>",
       "branch": "<output of git branch --show-current>",
       "scope": "full-project",
       "passes": ["code", "dependencies", "security"],
       "finding_count": {
         "code": 1,
         "dependency": 1,
         "security": 2,
         "total": 4
       },
       "max_cvss_score": 8.1,
       "findings_sha256": "9f2c1e8a7b3d4c5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6",
       "usage": {
         "model": "claude-sonnet-4-6",
         "input_tokens": 92541,
         "output_tokens": 4233,
         "total_tokens": 96774,
         "estimated_cost_usd": 0.84,
         "source": "ccusage"
       }
     }
     ```
     - `commit` and `branch` come from git commands, not hardcoded.
     - `finding_count` counts each bucket; `total` is their sum.
     - `max_cvss_score` is the highest `cvss_score` across scored security
       findings, or `null` when there are none — hardening findings are
       unscored and never contribute.
     - `findings_sha256` is the digest from step 5 — lowercase hex, no filename suffix. During a subsequent scan, the system must read this digest and recompute the hash of the existing `findings.json` before proceeding to compare buckets. This explicit integrity check detects if a committed `findings.json` was hand-edited after the fact, and lets the delta comparison safely skip re-reading an unchanged file.
     - `usage.source` records provenance: `"ccusage"`, `"runtime"`, or
       `"unavailable"`. When unavailable, emit the block with every numeric
       field `null` rather than omitting it, so consumers can rely on the key:
       ```json
       "usage": {
         "model": "unknown",
         "input_tokens": null,
         "output_tokens": null,
         "total_tokens": null,
         "estimated_cost_usd": null,
         "source": "unavailable"
       }
       ```

  8. Confirm to the user: "Findings saved to `${SCAN_DIR}`."

  Security notes for persistence:
  - Never interpolate finding content into shell commands. Write files using the
    tool's file-write capability, not `echo` or `cat <<EOF`.
  - The `.ponytail-sec/` directory should be committed to the repository so
    findings travel with the code. Recommend the user `git add .ponytail-sec/`.

  ## Validation caveat — attach to removal/tightening findings

  This audit reads the project statically. "Unused", "unreachable", and "safe to
  remove" are hypotheses about runtime behaviour, not facts — and an audit spans
  subsystems the reviewer has little runtime context for, so the blind spot is
  wider than in a per-diff review. RBAC grants, capabilities, permissions, and
  whole classes are frequently consumed by machinery that no source file names:
  install hooks, sidecars, worker pods an operator spawns, init containers, CI
  jobs, reflection, service accounts borrowed by other components. A grant — or a
  class — that looks dead may be load-bearing.

  So every **Med/High break-risk** finding, in **any** of the three passes, gets
  this line appended; skip it for Low-risk findings that only add a control:

  > ⚠️ Static analysis only — validate at runtime. Apply the fix and run it (build +
  > deploy + exercise the real path) before trusting it; removal findings can be
  > wrong. If you have Claude Code with cluster/build access, run the fix there to
  > confirm before merging.

  This is not hypothetical. In one audit, two "unused, safe to remove" RBAC
  findings were both **bugs**: a namespace `secrets` grant and a `serviceaccounts`
  grant that no code path touched. One was used at runtime by a worker component
  the controller spawns out-of-band; the other by a chart install hook. Both broke
  the product on deploy, and only a live run surfaced it — the static read looked
  clean.

  If a runtime test shows the fix breaks something, don't just restore the broad
  grant — ask, in the same session, for a safer angle that keeps the functionality
  (mount a Secret as a file, scope a grant to one resource name, a short-lived or
  projected token). e2e and tests are how you find this.

  Stay humble. When there's no clearly correct call, recommend the most secure
  option but present it as a choice, not a mandate — and give a risk-based read on
  keeping the current implementation so the user can decide:

  > Most secure is X. If you keep your current Y, the exposure is Z — acceptable if
  > [condition holds]. Your call; want me to apply X or leave Y as-is?

  Never pretend a judgement call is a hard rule.

  ## Boundaries

  Security findings only. Correctness bugs go to ponytail, not here.
  Lists findings, applies nothing. For per-diff review use ponytail-sec.

  "stop ponytail-sec-audit" or "normal mode": revert to standard review.
