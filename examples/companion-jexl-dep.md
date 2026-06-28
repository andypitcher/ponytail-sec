# Example: companion blocks ship on a dependency

> `flexpr` is a fictional package used for illustration.

**Trigger:** developer adds `"flexpr": "^2.3.0"` to `package.json` —
a sandboxed expression language evaluator for the Angular frontend.

---

### Pass 1 · Code

`package.json`: One new line. No new application code introduced. **Clean.**

### Pass 2 · Dependencies

`flexpr ^2.3.0`

- **Verdict** — **vendor or fork**.
- **Maintainer** — solo individual, no co-maintainers found.
- **Freshness** — last release 2020; last meaningful commit April 2021.
- **Security posture** — no `SECURITY.md`; no known CVEs, but no clear patch-response path.
- **OpenSSF Scorecard** — Maintained score 0/10.
- **Action** — switch to `flexpr-extended` or vendor the locked source so you control patch response.

### Pass 3 · Hardening

`kill-chain: 0 new paths found.` No attack surface introduced by the dep
itself — flexpr evaluates expressions in a sandboxed context with no exec or
network primitives.

**Ship blocked on dep. Resolve `flexpr` before merging.**
