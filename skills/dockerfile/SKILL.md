---
name: dockerfile
description: >
  Binary Dockerfile image-build hardening check. Use when reviewing Dockerfiles,
  container image builds, multi-stage builds, runtime users, pinned bases, or
  reproducible dependency installs. Minimal output only: OK or NOT_OK: RULE, RULE.
license: MIT
---

Ask once before enforcing:

> Enforce dockerfile skill? (yes / no)

If no: stop.

If yes: inspect locally. Do not web-search by default. Web-search only if the
user asks or the Dockerfile uses a platform feature whose semantics are unknown.

## Contract

Return exactly one line:

- `OK`
- `NOT_OK: RULE, RULE`

No severity. No advisory text. No maybes. If a rule cannot be verified, it is
not OK.

## Rules

All rules are mandatory.

- `NON_ROOT` — final image must set `USER` to a non-root user or numeric UID
  that is not `0`.
- `MULTI_STAGE` — production Dockerfile must use more than one `FROM` and copy
  only the runtime result into the final stage.
- `LEAN_FINAL` — final stage must not install or retain package managers,
  compilers, build tools, caches, or test tooling.
- `PIN_BASE` — every `FROM` must be pinned to a non-floating tag or digest; no
  `latest`, no untagged images. Digest wins.
- `REPRO_DEPS` — dependency installation must use reproducible inputs: lockfile,
  hash-pinned requirements, vendor directory, or equivalent. Raw manifest-only
  installs are not OK.

## Output examples

`OK`

`NOT_OK: NON_ROOT, PIN_BASE, REPRO_DEPS`
