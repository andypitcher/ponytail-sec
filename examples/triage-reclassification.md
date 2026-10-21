# Example: hardening → vulnerability

> A fictional finding on the same controller as the
> [triage walkthrough](triage-controller-scan.md). The score is illustrative.

The audit filed `S4` as hardening:

| #  | Class     | Rating           | Stage     | Location | Finding | Fix | Break-risk |
|----|-----------|------------------|-----------|----------|---------|-----|-----------|
| S4 | Hardening | Efficacy: Medium | 1 · Trust | `internal/webhook/verify.go:22` | `[auth · CWE-1188]` webhook signature check skipped when `webhookSecret` is empty, the chart default | Ship a generated secret by default | Medium |

Triage found a documented contract the code breaks. Step 0 had not covered it,
so the main agent asked:

```
S4: docs/webhooks.md:14 says "the controller rejects webhook deliveries without
a valid X-Signature-256 header". Is that the intended behaviour for every
install, including the chart default? (S4, class)
```

**User:** Yes, every install is supposed to reject unsigned deliveries. Write a PoC to prove it.

The user asked for a PoC, so the main agent wrote it to `triage/S4/poc/` and
ran it with the user's approval.

```
S4: reclassify Hardening → Vulnerability? docs/webhooks.md:14 promises
rejection; triage/S4/go-test.txt shows an unsigned delivery accepted.
New rating: Severity: High (CVSS-B 8.7). Drops efficacy and cwe. [y/N]
```

**User:** `y`

## Frontmatter

`efficacy` and `cwe` are gone; the vulnerability fields are computed from
scratch. There is no `cvss_score_audit`, because the audit had no score.

```yaml
id: S4
title: Unsigned webhook deliveries accepted when no secret is configured
source: audit-20261002-101500-Qp3sV8
class: vulnerability
reclassified_from: hardening
severity: High
cvss: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N
cvss_score: 8.7
cvss_nomenclature: CVSS-B
stage: 1 · Trust
location: internal/webhook/verify.go:22
tags: [auth]
break_risk: Medium
fingerprint: example/controller:internal/webhook/verify.go:VerifySignature:missing-signature-verification
vex_status: affected
evidence: [S4/go-test.txt]
context:
  - "repo: docs/webhooks.md:14"
  - "repo: charts/controller/values.yaml:41"
  - "user: Is rejecting unsigned deliveries intended for every install? → Yes, every install is supposed to reject unsigned deliveries. Write a PoC to prove it."
```

## §3 Description: Reclassification paragraph

> **Reclassification (hardening → vulnerability).** The audit read an empty
> `webhookSecret` as a permissive default. `docs/webhooks.md:14` says the
> controller rejects deliveries without a valid `X-Signature-256` header, with
> no exception for an unset secret, and the user confirmed that is the intended
> contract. `VerifySignature` returns `true` when the secret is empty
> (`internal/webhook/verify.go:22`), and `charts/controller/values.yaml:41`
> ships it empty. The PoC (`triage/S4/poc/verify_poc_test.go`) posts an unsigned
> delivery to the handler and gets `202 Accepted`. Behaviour contradicts the
> documented contract, so this is a vulnerability.

## §4 Rating

| Group | Metric | Audit (CVSS-B) | Triage | Justification | Source |
|---|---|---|---|---|---|
| Base | AV | — (hardening) | N | The webhook endpoint is exposed through the chart's Ingress | `charts/controller/templates/ingress.yaml` |
| Base | AC | — | L | No secret to guess when none is set | PoC |
| Base | AT | — | N | The empty secret is the shipped default, not a rare setup | `charts/controller/values.yaml:41` |
| Base | PR | — | N | No authentication on the endpoint | code read |
| Base | UI | — | N | No user action | code read |
| Base | VC | — | N | The handler returns nothing secret | code read |
| Base | VI | — | H | The payload chooses the Git ref the controller deploys | `internal/webhook/handler.go:57` |
| Base | VA | — | N | No availability effect beyond normal syncs | code read |
| Base | SC | — | N | Deployed workloads are reached through a second step; scored in isolation | §5 |
| Base | SI | — | N | Same as SC | §5 |
| Base | SA | — | N | Same as SC | §5 |
| Threat | E | — | X (not set) | No source | |
| Environmental | CR, IR, AR, MAV … MSA | — | X (not set) | No source | |

`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` → **8.7,
High (CVSS-B)**. Check: <https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N>

§8 proposes the smallest fix (reject when the secret is empty), and points to
`/ponytail` to apply it. The empty-secret path has shipped in released charts,
so it also suggests a GitHub Security Advisory, and warns not to commit
`triage/S4.triage.md` or `triage/S4/` until the advisory is published. No CVE
ID is assigned here.

```
S4  Vulnerability  Severity: High CVSS-B 8.7 (was hardening)      affected · evidence: 1  fix: proposed (break-risk Medium)
```
