# Example: companion blocks ship on a dependency

> `flexpr` is a fictional package used for illustration.

**Trigger:** developer adds `"flexpr": "^2.3.0"` to `package.json` —
a sandboxed expression language evaluator for the Angular frontend.

---

### Pass 1 · Code

`package.json`: One new line. No new application code introduced. **Clean.**

### Pass 2 · Dependencies

`D1` `flexpr ^2.3.0`

- **Verdict** — **vendor or fork**.
- **Upstream** — `https://www.npmjs.com/package/flexpr` (range `^2.3.0`
  is unpinned; it floats to any 2.x).
- **Maintainer** — solo individual, no co-maintainers found.
- **Freshness** — last release 2020; last meaningful commit April 2021.
- **Security posture** — no `SECURITY.md`; no known advisories, but no clear
  patch-response path either.
- **OpenSSF Scorecard** — Maintained score 0/10.
- **Action** — switch to `flexpr-extended`, or vendor the locked source so you
  control patch response. If it stays, pin to `2.3.0` exactly plus lockfile —
  `^` on an unmaintained solo package means any future publish lands in your
  build unreviewed.
- **Break-risk: Medium** — swapping evaluators may change expression semantics;
  vendoring is behaviour-neutral but shifts maintenance to you.

⚠️ Static analysis only — validate at runtime. Apply the fix and run it (build +
deploy + exercise the real path) before trusting it. If you have Claude Code
with cluster/build access, run the fix there to confirm before merging.

### Pass 3 · Security findings

`kill-chain: 0 new paths found.` No attack surface introduced by the dep
itself — flexpr evaluates expressions in a sandboxed context with no exec or
network primitives.

**Ship blocked on dep. Resolve `flexpr` before merging.**
