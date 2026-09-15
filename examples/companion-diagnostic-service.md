# Example: companion catches 3 issues in a new service

**Trigger:** developer adds `DiagnosticService.scala` — a new health-check
utility with a custom TLS client, a hardcoded token, and a shell ping.

---

### Pass 1 · Code

`C1` **`DiagnosticService.scala`**: `runNetworkDiag()` doesn't need to exist — a
`ping` via string interpolation to a shell is 3 lines that a no-shell
`ProcessBuilder("ping", "-c", "3", target)` replaces cleanly. The companion
`checkControllerReachability()` duplicates what `RestClient` already does with
proper lifecycle management. Both methods are new attack surface for zero added
capability. Delete both; call `RestClient` and `ProcessBuilder` directly from
the call site. **Break-risk: Low** — both methods are new in this diff and have
a single call site.

### Pass 2 · Dependencies

No new dependencies introduced. **Clean.**

### Pass 3 · Security findings

| #  | Kind          | Stage     | Location | Finding | Fix | Break-risk |
|----|---------------|-----------|----------|---------|-----|-----------|
| S1 | vulnerability | 1 · Trust | `DiagnosticService.scala:11` | `auth` inline `X509TrustManager` with no-op `checkServerTrusted()` — sets the JVM-wide SSL socket factory, full MITM | Remove; use the existing `RestClient` | Low |
| S2 | secret        | 4 · Data  | `DiagnosticService.scala:8` | `secret` `internalApiToken` hardcoded as a JWT literal — committed to git history permanently | Inject via env var or k8s Secret | Low |
| S3 | vulnerability | 3 · Exec  | `DiagnosticService.scala:23` | `inject` `s"ping -c 3 $target".!!` — `target` is interpolated into a shell string; `;` or `&&` executes arbitrary commands | Replace with `Seq("ping", "-c", "3", target)` | Low |

`kill-chain: 3 paths found.`

`S1` is the most urgent — it overwrites the JVM-wide SSL factory and undoes
whatever the real TLS config would have fixed. `S2` is permanent the moment
it's committed; a token in git history survives secret rotation. `S3` is the
classic shell injection shape — `target` is one HTTP request away from an
attacker. All three live in code `C1` recommends deleting outright, so the
smallest change here closes every path at once.

**Ship blocked on security. Fix before merging.**

Type 'expand N' for root cause, exploit scenario, and fix.
