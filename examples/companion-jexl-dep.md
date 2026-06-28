# Example: companion blocks ship on a dependency

> `flexpr` is a fictional package used for illustration.

**Trigger:** developer adds `"flexpr": "^2.3.0"` to `package.json` —
a sandboxed expression language evaluator for the Angular frontend.

---

### Pass 1 · Code

`package.json`: One new line. No new application code introduced. **Clean.**

### Pass 2 · Dependencies

`flexpr ^2.3.0` → **vendor or fork**: solo maintainer, last release 2020,
last commit April 2021, no `SECURITY.md`, OpenSSF Maintained score 0/10.
Functionally stable with no known CVEs, but any future vulnerability has
nowhere to go — the author has been silent for 5 years with no co-maintainers.
The active drop-in alternative is `flexpr-extended` (maintained superset with
TypeScript types); switch to that or vendor the current source at the locked
commit so you control patch response.

### Pass 3 · Hardening

`kill-chain: 0 new paths found.` No attack surface introduced by the dep
itself — flexpr evaluates expressions in a sandboxed context with no exec or
network primitives.

**Ship blocked on dep. Resolve `flexpr` before merging.**
