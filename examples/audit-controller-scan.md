# Example: full audit with persisted findings

> A fictional Go controller, used to show audit output and the files written to
> `.ponytail-sec/`.

**Trigger:** `/ponytail-sec-audit` on a Kubernetes controller repo. A previous
audit exists at `.ponytail-sec/audit-20260902-091455-a7Kd2p`.

---

**Delta since last audit (`audit-20260902-091455`):** 1 resolved, 3 recurring, 1 new.

### Pass 1 · Code

`C1` `internal/ssl/client.go`: `sync.Once` caches the CA cert pool at first
request, so a CA rotation is silent until the process restarts — revoked
intermediates stay trusted for the life of the pod. Drop the `sync.Once` and
load the pool per-dial; the cost is negligible next to the TLS handshake.
**Break-risk: Low** — nothing else reads the cached pool. 🔁 Recurring.

`internal/api/handlers.go`: **Clean.**

### Pass 2 · Dependencies

`D1` `github.com/tidwall/gjson v1.14.0`

- **Verdict** — **stdlib**.
- **Upstream** — `https://pkg.go.dev/github.com/tidwall/gjson@v1.14.0` (pinned).
- **Maintainer** — individual.
- **Freshness** — last release 2023-11-02.
- **Security posture** — no `SECURITY.md`.
- **OpenSSF Scorecard** — 4.1/10.
- **Action** — one call site in `status.go:44` reads a single field;
  `encoding/json` covers it. Drop the `require`.
- **Break-risk: Low** — single call site, fully visible.

### Pass 3 · Security findings

| #  | Class | Rating | Stage | Location | Finding | Fix | Break-risk |
|----|-------|--------|-------|----------|---------|-----|-----------|
| S1 | Vulnerability | Severity: High (8.1) | 3 · Exec | `internal/exec/manager.go:34` | `[inject]` job name interpolated into a command string passed to `sh -c`; any caller controlling the name gets execution | Use `exec.Command` with an argument slice; drop the shell | Medium |
| S2 | Hardening | Efficacy: High | 2 · Authz | `deploy/rbac.yaml:30` | `[rbac · CWE-269]` controller SA granted `secrets: ["*"]`; no handler reads Secrets | Drop the grant | High |
| S3 | Hardening | Efficacy: Medium | 4 · Data | `internal/cmd/controller/root.go:147` | `[expose · CWE-1188]` `net/http/pprof` on `localhost:6060` starts unconditionally, while the agent gates the identical block behind `FLEET_AGENT_PPROF_DISABLED` | Apply the same env gate the agent already uses | Low |

```
Vectors:
  S1  8.1  CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

`kill-chain: 3 paths found.`

`S1` is the only finding here where something is actually broken — a job name
reaching `sh -c` is execution in the controller's context, and the controller
holds the very grant `S2` describes, so the two compound. `S2` and `S3` are both
pre-existing hardening items, both 🔁 recurring from the last audit and neither
carrying a severity: the RBAC grant and the pprof listener behave as documented,
so a base score on them would be impact-dominated and would outrank `S1`. They
carry an efficacy label instead — how much the fix takes away from an
attacker, as a judgement rather than a number that would read as commensurable
with `S1`'s. `S3` is interesting less for its efficacy than for the
inconsistency: the agent
already gates pprof, so the controller is the odd one out and the fix is a
copy-paste of code you own. The controller's namespace-wide watch is the shipped trust model,
not a finding — that watch is the perimeter. `S1`'s 8.1 is CVSS 4.0 base, so it
assumes the worst case for everything the repo doesn't tell me about your
deployment.

If I were you I'd start with `S1` and `S3` — `S1` because it's the one live
execution path, `S3` because it's four lines you've already written elsewhere
and it's been recurring for two scans. `S2` is the higher-efficacy of the two —
dropping the grant closes Stage 2 outright — but it's the one I'd move slowest
on: High break-risk, and the last audit's RBAC removals
are exactly the kind that broke on deploy. Prove it with an e2e run first.

⚠️ Static analysis only — validate at runtime. A component spawned out-of-band
(job/sidecar/hook) may rely on the `S2` grant; deploy and run one full cycle
before merging. If it breaks, ask for a narrower grant (scope to one secret
name, create-only, or a projected token) rather than restoring `["*"]`.

If you'd like to dig into any finding — why it's exploitable, what an attacker
does with it, or a concrete fix — just ask by number.

---

Findings saved to `.ponytail-sec/audit-20260911-143022-Xk9mQ2`.

## Persisted output

```json name=findings.json
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
        "class": "vulnerability",
        "severity": "High",
        "cvss": "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "cvss_score": 8.1,
        "stage": "3 · Exec",
        "location": "internal/exec/manager.go:34",
        "tags": ["inject"],
        "finding": "Job name is interpolated into a shell command string passed to sh -c; any caller that controls the name achieves command execution",
        "fix": "Use exec.Command with an argument slice; drop the shell",
        "break_risk": "Medium",
        "status": "open"
      },
      {
        "id": "S2",
        "type": "security",
        "class": "hardening",
        "efficacy": "High",
        "cwe": "CWE-269",
        "stage": "2 · Authz",
        "location": "deploy/rbac.yaml:30",
        "tags": ["rbac"],
        "finding": "Controller ServiceAccount granted secrets: [\"*\"]; no handler in the project reads Secrets",
        "fix": "Drop the grant",
        "break_risk": "High",
        "status": "open"
      },
      {
        "id": "S3",
        "type": "security",
        "class": "hardening",
        "efficacy": "Medium",
        "cwe": "CWE-1188",
        "stage": "4 · Data",
        "location": "internal/cmd/controller/root.go:147",
        "tags": ["expose"],
        "finding": "net/http/pprof on localhost:6060 started unconditionally in the controller while the agent gates the identical block behind FLEET_AGENT_PPROF_DISABLED",
        "fix": "Apply the same env gate the agent already uses",
        "break_risk": "Low",
        "status": "open"
      }
    ]
  }
}
```

```json name=meta.json
{
  "schema_version": 2,
  "timestamp": "2026-09-11T14:30:22Z",
  "commit": "d87f7c533703072a304dda39a8f975bc6fab2d39",
  "branch": "main",
  "scope": "full-project",
  "passes": ["code", "dependencies", "security"],
  "finding_count": {
    "code": 1,
    "dependency": 1,
    "security": 3,
    "total": 5
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

When no usage CLI is on PATH, the block is still emitted — with nulls, never an
estimate:

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
