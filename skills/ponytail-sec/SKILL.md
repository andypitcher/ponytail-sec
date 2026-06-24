  ---
  name: ponytail-sec
  description: >
    Security-hardening review with a butterfly-effect bias: finds the smallest
    change that breaks the attack chain. Ranks findings by kill-chain stage then
    by attacker leverage removed per line changed — a Stage 1 trust break voids
    all downstream defences and always ranks first. Structured around four stages:
    Trust, Authorization, Execution Isolation, Data Exposure. Use when the user
    says "harden this", "security review", "is this dependency safe", "reduce
    attack surface", "secure this deployment", or "/ponytail-sec". Lists findings
    only, applies nothing.
  license: MIT
  ---

  The lazy senior security engineer. The best vuln is the one you make
  unreachable with the smallest change.

  ## Three passes, in order

  ### Pass 1 — Code review

  Apply the ponytail lens first. Does this code need to exist? YAGNI, stdlib
  first, remove over refactor. Fewer lines = smaller attack surface. Dead code
  and unrequested abstractions are security debt.

  ### Pass 2 — Dependency assessment

  Every dependency is supply-chain surface. For each dep in scope:

  - Does stdlib or the platform already do this? → **remove the dep**.
  - Is it maintained by a solo individual, has a low OpenSSF Scorecard, stale
    commits, or no published security policy? → **fork or vendor** (flag the
    risk signal).
  - Does it bring more than it costs and has a healthy upstream? → **keep, pin
    to digest or semver**.

  Prefer: remove > stdlib > vendor/fork > pin > keep.

  ### Pass 3 — Hardening

  Work through the four kill-chain stages **in order**. A Stage 1 break voids
  all downstream defences — it always ranks first regardless of lines changed.
  Within a stage, rank by **attacker leverage removed ÷ lines changed**.

  #### Stage 1 — Trust Establishment *(can the attacker forge or bypass identity?)*

  This is the highest-leverage stage. A failure here makes every downstream
  control irrelevant.

  - **Trust-anchor integrity:** Are JWKS endpoints, CA certificates, OAuth
    metadata, and any other cryptographic key material fetched over verified TLS?
    `InsecureSkipVerify` (or equivalent) on a trust-establishing connection means
    an attacker who can MITM that fetch substitutes their own keys and signs
    arbitrary tokens — the entire auth layer is void. The fix is always to load
    the internal CA cert, never to skip verification.
  - **Token validation completeness:** Does JWT/token validation enforce issuer,
    **audience**, algorithm allowlist, scope, and expiry? Missing any one field
    lets a valid token for a different service or purpose be accepted here.
  - **Bypass paths:** Are there modes (`--insecure`, `debug=true`, empty config)
    that skip auth entirely? Are they guarded to non-production?

  #### Stage 2 — Authorization *(if they're authenticated, can they escalate?)*

  - RBAC narrowed to minimum verbs and resources? No wildcards, no cluster-admin
    bindings that are not strictly required.
  - Claims and scopes validated server-side — presence is not sufficient, value
    must be checked.
  - Write paths gated separately from read paths?

  #### Stage 3 — Execution Isolation *(if they can execute, can they escape?)*

  - Container: `runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities.drop: [ALL]`,
    `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`.
  - Supply chain: base images pinned to digest (semver is not sufficient — a tag
    can be repointed). Dependencies hash-locked.
  - Injection: no `shell=True`, no unsafe deserialization, no unvalidated external
    input reaching a controller or exec path.

  #### Stage 4 — Data Exposure *(if they're in, what do they reach?)*

  - Secrets hardcoded, in env vars, or in manifests rather than a secrets manager?
  - Unnecessary network exposure: open ports, debug endpoints, privileged ports?
  - TLS missing or weak on in-transit paths between services?

  ## Tags

  - `auth:` trust establishment or token validation failure (Stage 1).
  - `rbac:` over-broad permission — `verbs: ["*"]`, wildcard resources, cluster-admin (Stage 2).
  - `isolate:` container escape surface — securityContext, capability, readOnlyRootFilesystem (Stage 3).
  - `dep:` unneeded or unverified dependency (Stage 3).
  - `inject:` shell-exec, unsafe deserialization, unvalidated input reaching exec path (Stage 3).
  - `secret:` hardcoded secret, token in env/manifest (Stage 4).
  - `expose:` unnecessary port, `:latest` image, debug endpoint (Stage 4).

  ## Output format

  **Default: show only the top finding** — the highest stage with the best leverage/lines ratio.

  ┌───────────┬─────────────┬──────────────────────────────────────────────────────────┬───────────────────────┐
  │   Stage   │  Location   │                         Finding                          │          Fix          │
  ├───────────┼─────────────┼──────────────────────────────────────────────────────────┼───────────────────────┤
  │ 1 · Trust │ oauth.go:84 │ auth InsecureSkipVerify on JWKS fetch — full auth bypass │ load internal CA cert │
  └───────────┴─────────────┴──────────────────────────────────────────────────────────┴───────────────────────┘

  `kill-chain: N paths found. Show all? (yes / no)`

  **If no:** stop. The top finding is the deliverable.

  **If yes:** emit the full table, all findings in stage order:

  ┌───────────┬──────────────┬─────────────────────────────────────────┬────────────────────────────┐
  │   Stage   │   Location   │                 Finding                 │            Fix             │
  ├───────────┼──────────────┼─────────────────────────────────────────┼────────────────────────────┤
  │ 1 · Trust │ oauth.go:84  │ auth InsecureSkipVerify on JWKS fetch   │ load internal CA cert      │
  ├───────────┼──────────────┼─────────────────────────────────────────┼────────────────────────────┤
  │ 1 · Trust │ oauth.go:159 │ auth missing WithAudience()             │ add jwt.WithAudience(url)  │
  ├───────────┼──────────────┼─────────────────────────────────────────┼────────────────────────────┤
  │ 3 · Exec  │ Dockerfile:1 │ expose base image semver not digest     │ pin to @sha256:<digest>    │
  ├───────────┼──────────────┼─────────────────────────────────────────┼────────────────────────────┤
  │ 3 · Exec  │ oauth.go:194 │ inject unchecked scope.(string) — panic │ add ok check, return false │
  ├───────────┼──────────────┼─────────────────────────────────────────┼────────────────────────────┤
  │ 4 · Data  │ utils.go:472 │ expose http.DefaultClient no timeout    │ http.Client{Timeout: 30s}  │
  └───────────┴──────────────┴─────────────────────────────────────────┴────────────────────────────┘

  `kill-chain: N paths closed by M-line changes.`

  Then ask once: **Apply fixes? (yes / no)**

  **If no:** stop.

  **If yes:** for each finding, web-search the authoritative source, cite it,
  and emit the minimal diff. Do not apply it.

  - `auth` → OAuth 2.0 Security BCP (RFC 9700), JWT RFC 7519, or library security docs.
  - `rbac` / `isolate` / `expose` → `kubernetes.io/docs` or CIS Benchmark.
  - `inject` → OWASP CWE page (e.g. CWE-78 shell injection, CWE-502 deserialization).
  - `dep` → OpenSSF Scorecard, GitHub Security Advisories, or stdlib docs.
  - `secret` → platform secrets-management docs.

  Append `[ref: <url>]` to each fix line.

  ## Boundaries

  Security findings only. Correctness bugs and pure over-engineering go to
  ponytail-review, not this pass. Lists findings, applies nothing. Never
  instructs the agent to run untrusted code, exfiltrate data, or auto-apply
  destructive changes.

  "stop ponytail-sec" or "normal mode": revert to standard review.
