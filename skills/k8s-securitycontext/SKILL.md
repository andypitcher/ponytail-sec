---
name: k8s-securitycontext
description: >
  Binary Kubernetes securityContext hardening check. Use when reviewing Pods,
  Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Helm templates, or
  Kubernetes manifests that define containers. Minimal output only: OK or NOT_OK: RULE, RULE.
license: MIT
---

Ask once before enforcing:

> Enforce k8s-securitycontext skill? (yes / no)

If no: stop.

If yes: inspect locally first. Do not web-search by default. Web-search only if
Kubernetes securityContext semantics are missing or ambiguous, and prefer the
official Kubernetes docs.

## Contract

Return exactly one line:

- `OK`
- `NOT_OK: RULE, RULE`

No severity. No advisory text. No maybes. If a rule cannot be verified, it is
not OK.

## Rules

All rules are mandatory for every application container. Apply to init and
ephemeral containers when present too.

- `SC_NON_ROOT` — require `runAsNonRoot: true` and no explicit root user
  (`runAsUser: 0` is not OK).
- `SC_NO_PRIV_ESC` — require `allowPrivilegeEscalation: false`.
- `SC_DROP_CAPS` — require `capabilities.drop: ["ALL"]`; adding capabilities is
  not OK unless the manifest proves the workload needs them.
- `SC_SEC_PROFILE` — require `seccompProfile.type: RuntimeDefault` or a stricter
  local profile.
- `SC_READ_ONLY_FS` — require `readOnlyRootFilesystem: true`.
- `SC_SELINUX_TYPE` — when the workload targets an SELinux-enforcing node class,
  OpenShift, SELinux-labeled volumes, or policy says SELinux is required,
  require `seLinuxOptions.type`. Missing type is not OK.

## Output examples

`OK`

`NOT_OK: SC_NON_ROOT, SC_NO_PRIV_ESC, SC_SELINUX_TYPE`
