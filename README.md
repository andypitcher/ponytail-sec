<p align="center">
  <img src="assets/logo.png" width="220" alt="ponytail-sec, the laser-focused security engineer">
</p>

<h1 align="center">ponytail-sec</h1>

<p align="center">
  <em>The smallest change that ruins an attacker's day.</em>
</p>

<p align="center">
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/andypitcher/ponytail-sec">
    <img src="https://api.securityscorecards.dev/projects/github.com/andypitcher/ponytail-sec/badge" alt="OpenSSF Scorecard">
  </a>
</p>

<p align="center">
  <a href="https://ponytail-sec.dev">ponytail-sec.dev</a>
</p>

---

Laser-focused security review. Instead of flooding you with findings, it hunts
the one dropped capability, the one `readOnlyRootFilesystem: true`, the one
narrowed RBAC verb that kills a link in the attack chain. Butterfly effect
for defense: tiny diffs, outsized reduction in attacker leverage.

A plugin for Claude Code and Antigravity CLI — `/ponytail-sec` for your
current diff, `/ponytail-sec-audit` for the whole repo, and
`/ponytail-sec-triage` to review findings with context — and a set of skills
you can install into Cursor, Codex CLI, Gemini CLI, GitHub Copilot and other
agents.

Same dependency lens as [ponytail](https://github.com/DietrichGebert/ponytail):
"Do I actually need this dep?" Fewer dependencies = smaller supply-chain
attack surface. Prefer remove over keep.

## Before / After

```yaml
# before — process runs as root, can write anywhere, keeps default capabilities
containers:
  - name: controller
    image: ghcr.io/example/controller:latest
```

```yaml
# after — pin the image, remove root, confine runtime behavior
containers:
  - name: controller
    image: ghcr.io/example/controller:v1.2.3@sha256:3b7c4e9a1f2d8c6b5a0e9d4c3b2a1908f7e6d5c4b3a2918070605040302010aa
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      seccompProfile:
        type: RuntimeDefault
      seLinuxOptions:
        type: container_t
      capabilities:
        drop: ["ALL"]
```

One diff. One closed kill-chain link.

## Install

Pick the most secure path your agent supports. Native and manual installs run no
third-party installer; `npx` is offered last, as a convenience with a trade-off.

### Claude Code

Latest:
```
/plugin marketplace add andypitcher/ponytail-sec
/plugin install ponytail-sec@ponytail-sec
```

Pinned to a version:
```
/plugin marketplace add andypitcher/ponytail-sec@v0.2.9
/plugin install ponytail-sec@ponytail-sec
```

### Antigravity CLI

Latest:
```bash
agy plugin install https://github.com/andypitcher/ponytail-sec
```

For development/local testing:
```bash
agy plugin install .
```

### Cursor, Codex CLI, Gemini CLI, GitHub Copilot — manual (recommended)

The skills are small, CI-guarded text files. Clone to a scratch directory (not
inside the repo you're auditing), pin to a release, verify its commit, review the
files, then copy them into your **per-user** skills directory — nothing runs on
your machine and the skills never live inside an untrusted repo:

```bash
# clone the release tag into a fresh scratch dir, then check it is the v0.2.9 commit
d=$(mktemp -d)
git clone --depth 1 --branch v0.2.9 https://github.com/andypitcher/ponytail-sec "$d"
[ "$(git -C "$d" rev-parse HEAD)" = 95c968d62791a93f65110f4ab7444b00f74889db ] \
  && echo "commit OK" || echo "COMMIT MISMATCH: do not install"
```

Continue only if it printed `commit OK`. Then replace (never merge into) any
existing copy in your per-user skills directory:

```bash
dest=~/.cursor/skills   # Gemini CLI: ~/.gemini/skills · GitHub Copilot: ~/.copilot/skills
mkdir -p "$dest"
for s in ponytail-sec ponytail-sec-audit ponytail-sec-triage; do
  rm -rf "${dest:?}/$s" && cp -r "$d/skills/$s" "$dest/"
done
```

Codex CLI reads the per-project directory described next.

A per-project `.agents/skills/` directory is read by all these agents too — but
**a hostile repo under audit can ship its own `.agents/skills/ponytail-sec/`**.
If you use the project directory, create it fresh (`rm -rf
.agents/skills/ponytail-sec` first) and never merge into an existing one. For
untrusted code, prefer the per-user path above.

### Quick install with npx (any agent)

> ⚠️ **Trade-off:** `npx` downloads and runs the third-party
> [`skills`](https://skills.sh) CLI **and its dependencies with your full
> privileges, outside any sandbox, before any ponytail-sec check applies.**
> Pinning the CLI version aids reproducibility but is **not** an integrity
> guarantee, and `@ponytail-sec` selects the *skill*, not a version — `npx`
> installs the skill from the repo's default branch (HEAD), so the install is
> **not pinned**; only the manual path above pins a release. On a machine holding
> real credentials, prefer the manual or native path; use `npx` in a
> container/throwaway environment, or only if you trust and have reviewed the
> CLI. Needs Node ≥ 22.20.

```bash
npx skills@1.9.1 add andypitcher/ponytail-sec@ponytail-sec -a cursor
npx skills@1.9.1 add andypitcher/ponytail-sec@ponytail-sec-audit -a codex -a gemini-cli -a github-copilot
```

Available skills: `ponytail-sec`, `ponytail-sec-audit`, `ponytail-sec-triage`.

Slash commands and the read-only triage subagent are Claude Code and Antigravity
features. On other agents, invoke a skill by asking — "security review", "audit
the project", "triage these findings" — and triage runs inline.

## How it works

Three passes, in order:

```
1. Code review    Does this code need to exist at all?
                  Apply the ponytail lens first: YAGNI, stdlib first,
                  remove over refactor. Fewer lines = smaller attack surface.

2. Dependency     Does this dependency need to exist?
                  Every dep is supply-chain surface. For each one, ask:
                    a. Does stdlib or the platform already do this?  → remove the dep
                    b. Is it maintained by a single person, or has a
                       low OpenSSF Scorecard / no recent commits?    → fork or vendor
                    c. Does it bring more than it costs?             → keep, pin immutably
                  Prefer: remove > stdlib > vendor > immutable pin > keep floating.

3. Security       Four stages, top-to-bottom. Stage 1 break voids all below.
   findings       Two classes, same table, ranked together:
                    · vulnerability — behaviour contradicts the documented
                      contract: privesc, auth bypass, injection, path
                      traversal, hardcoded secrets (tagged secret).
                      Rated by severity and a CVSS 4.0 score.
                    · hardening — behaviour matches the contract, but a control
                      is missing or too loose (ungated debug endpoint, RBAC
                      wildcard, missing TLS). Rated by efficacy (High/Medium/
                      Low: how much the fix takes from an attacker) and a CWE.
                  Rank within each stage by attacker leverage removed ÷ lines changed.
                  The smallest change that ruins an attacker's day wins.
                  Default output: up to 3 material findings total; no padding. More only on request.
```

Report only what breaks an attack path. Security theater goes unreported.

## Kill-chain stages

Every security finding lands in one stage, with a class: `vulnerability` or
`hardening`. The split is practical, not forensic — it's there so you can sort
"there's a way in" from "tighten this", not to be a taxonomy.

```
Stage 1 · Trust      Can the attacker forge or bypass identity?
                     · Trust-anchor material (JWKS, CA certs, OAuth) over verified TLS?
                     · Token validation complete — issuer, audience, algorithm, scope, expiry?
                     · Auth bypass modes guarded to non-production?

Stage 2 · Authz      If they're in, can they escalate?
                     · RBAC narrowed to minimum verbs/resources?
                     · Claims validated server-side, not just checked for presence?
                     · Write paths gated from read paths?

Stage 3 · Exec       If they execute, can they escape?
                     · Container: non-root, readOnlyRootFilesystem, capabilities.drop: [ALL]
                     · Supply chain: base images pinned to digest, deps verified
                     · Injection: no shell=True, no unsafe deserialization

Stage 4 · Data       If they're in, what do they reach?
                     · Secrets hardcoded, in env, in manifests?
                     · Unnecessary ports, debug endpoints?
                     · TLS on all in-transit paths?
```

## Safe by design

Lists findings, fixes nothing. The agent reads the skill and reports; it never
applies changes, runs untrusted code, or touches production.

What it reads, writes, runs and fetches, and a copy-paste least-privilege
`.claude/settings.json`, are in [SECURITY.md](SECURITY.md#data-flow).

⚠️ Findings are static reads of the diff. When one isn't fully validated — especially "drop this unused grant" — the agent tells you to prove it at runtime first: build → run → confirm.

ponytail-sec optimises for lean + least-privilege, so a finding can occasionally break something. When it does, don't just restore the broad grant — ask ponytail-sec for a safer angle (mount the Secret as a file, scope the grant to one resource name, use a projected token) that keeps the functionality with far less standing privilege.

## Usage

**`/ponytail-sec`** — The security engineer sitting next to you while you
code. Scopes to your current diff. Three passes, up to 3 material findings,
lean output. Ends with Ship or Ship blocked — nothing in between. Invoke
directly or say "harden this", "security review", "is this dep safe",
"reduce attack surface".

Examples: [new service](https://github.com/andypitcher/ponytail-sec/blob/main/examples/companion-diagnostic-service.md) ·
[dependency](https://github.com/andypitcher/ponytail-sec/blob/main/examples/companion-jexl-dep.md).

**`/ponytail-sec-audit`** — Full project scan. Vulnerabilities get a severity
and a CVSS-B score; hardening gets an efficacy and a CWE. Findings are saved to
`.ponytail-sec/` and tracked across scans. Ends with a frank "if I were you"
and an offer to triage. Invoke directly or say "full security audit", "audit
the project", "security scan".

Example: [full audit with persisted findings](https://github.com/andypitcher/ponytail-sec/blob/main/examples/audit-controller-scan.md).

**`/ponytail-sec-triage`** — The final gate. Proves, disproves, or rescores
findings using your project's context: up to 5 questions, or free text such as
docs or a previous advisory. Writes one `<ID>.triage.md` security report per
finding. Run it from the audit's closing question, as
`/ponytail-sec-triage S1,S2`, or with a pasted finding.

Examples: [triage walkthrough](https://github.com/andypitcher/ponytail-sec/blob/main/examples/triage-controller-scan.md) ·
[reclassification](https://github.com/andypitcher/ponytail-sec/blob/main/examples/triage-reclassification.md).

## Credits

Created and maintained by [Andy Pitcher](https://github.com/andypitcher).
Inspired by the [Ponytail](https://github.com/DietrichGebert/ponytail) plugin. Same voice, security lens.

MIT license.
