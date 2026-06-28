# Example: companion catches 3 issues in a new service

**Trigger:** developer adds `DiagnosticService.scala` — a new health-check
utility with a custom TLS client, a hardcoded token, and a shell ping.

---

### Pass 1 · Code

**`DiagnosticService.scala`**: `runNetworkDiag()` doesn't need to exist — a
`ping` via string interpolation to a shell is 3 lines that a no-shell
`ProcessBuilder("ping", "-c", "3", target)` replaces cleanly. The companion
`checkControllerReachability()` duplicates what `RestClient` already does with
proper lifecycle management. Both methods are new attack surface for zero added
capability. Delete both; call `RestClient` and `ProcessBuilder` directly from
the call site.

### Pass 2 · Dependencies

No new dependencies introduced. **Clean.**

### Pass 3 · Hardening

| #  | Stage    | Location | Finding | Fix |
|----|----------|----------|---------|-----|
| #1 | 1 · Trust | `DiagnosticService.scala:11` | `auth` Inline `X509TrustManager` with no-op `checkServerTrusted()` — sets JVM-wide SSL socket factory, full MITM | Remove; use existing `RestClient` which loads the real CA |
| #2 | 4 · Data | `DiagnosticService.scala:8` | `secret` `internalApiToken` hardcoded as a JWT literal — committed to git history permanently | Inject via env var or k8s secret |
| #3 | 3 · Exec | `DiagnosticService.scala:23` | `inject` `s"ping -c 3 $target".!!` — `target` interpolated into a shell string; `;` or `&&` executes arbitrary commands | Replace with `Seq("ping", "-c", "3", target).!!` |

`kill-chain: 3 paths found.`

`#1` is the most urgent — it overwrites the JVM-wide SSL factory and undoes
whatever the real TLS config would have fixed. `#2` is permanent the moment
it's committed; a token in git history survives secret rotation. `#3` is the
classic shell injection shape — `target` is one HTTP request away from an
attacker.

**Ship blocked on hardening. Fix before merging.**
