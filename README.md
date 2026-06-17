<!-- logo: TODO — reuse ponytail character with a "sec" hat (assets/logo.png + dark variant) -->

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