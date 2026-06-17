# ponytail-sec

> The smallest change that ruins an attacker's day.

ponytail's security sibling. Instead of flooding you with findings, it hunts
the one dropped capability, the one `readOnlyRootFilesystem: true`, the one
narrowed RBAC verb that kills a link in the attack chain. Butterfly effect
for defense: tiny diffs, outsized reduction in attacker leverage.

Same dependency lens as [ponytail](https://github.com/DietrichGebert/ponytail):
"Do I actually need this dep?" Fewer dependencies = smaller supply-chain
attack surface. Prefer remove over keep.

## Before / After

```yaml
# before — process runs as root, can write anywhere, trivial container escape
containers:
  - name: controller
    image: ghcr.io/example/controller:latest
```

```yaml
# after — 4 lines close the container-escape path
containers:
  - name: controller
    image: ghcr.io/example/controller:v1.2.3
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

One diff. One closed kill-chain link.

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
                    c. Does it bring more than it costs?             → keep, pin to digest
                  Prefer: remove > stdlib > vendor > pin > keep.

3. Hardening      What privilege, filesystem, network, or secret exposure
                  breaks a link in the attack chain?
                  Rank by attacker leverage removed ÷ lines changed.
                  The smallest change that ruins an attacker's day wins.
```

Report only what breaks an attack path. Security theater goes unreported.

## Safe by design

Lists findings, fixes nothing. The agent reads the skill and reports; it never
applies changes, runs untrusted code, or touches production.

## Usage

Invoke with `/ponytail-sec`, or say "harden this", "security review",
"is this dependency safe", "reduce attack surface", "secure this deployment".

## Relation

Part of the [ponytail](https://github.com/DietrichGebert/ponytail) skill
family. Same voice, security lens.

MIT license.