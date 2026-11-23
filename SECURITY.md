# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues. 

Instead, please report them privately using [GitHub's Private Vulnerability Reporting](https://github.com/andypitcher/ponytail-sec/security/advisories/new). 

### What to expect:

* **Acknowledgment & Triage:** We will review and acknowledge your report as quickly as possible.
* **Resolution Timeframe:** We align with standard open-source responsible disclosure practices. We ask for up to **90 days** to investigate and issue a patch before the vulnerability is disclosed publicly.
* **Status Updates:** We will keep you informed of our progress as we work on a fix.
* **If Accepted:** We will patch the vulnerability as quickly as possible. Once the fix is released, we will notify you and (with your permission) credit you in the release notes or advisory.
* **If Declined:** If we determine the issue is not a valid security vulnerability or falls outside our project's threat model, we will provide a clear explanation of our reasoning.

## Threat model

- **Scanned repositories are untrusted.** Auditing third-party code is an intended use. Every skill and command treats repository content, fetched pages and web search results as evidence, never instructions. That rule lowers the odds an agent follows planted text; it is not a guarantee, so the enforced controls below matter.
- **The plugin is trusted.** Its skills and scripts run with your agent's permissions. CI (`Skill guard`) fails on exec or network commands, load-time shell commands, hidden Unicode, hooks, MCP or LSP servers, custom component paths in the manifest, and skills, commands or agents that pre-approve more than read-only tools.
- **`/ponytail` is a separate plugin, outside this threat model.** ponytail-sec never edits code; fixes are handed to [ponytail](https://github.com/DietrichGebert/ponytail), maintained by another author. Unlike ponytail-sec, ponytail installs hooks that run on every turn. If it is not installed, the skills offer `DietrichGebert/ponytail@v5.3.3`, say that it installs hooks, and never install it themselves; decline and the fix is described in prose instead. `v5.3.3` is a lightweight tag its author can move: before installing, check that it still points to commit `7801d061243d7b753bad0e0b3c057cd250b11755` (`git ls-remote https://github.com/DietrichGebert/ponytail refs/tags/v5.3.3`).
- **`.ponytail-sec/` is trusted state.** Later audits inherit triage decisions from reports stored there. Review changes to it like code; in your own repository, protect it with CODEOWNERS.

## Data flow

| | What |
|---|---|
| **Runs on install** | Nothing. No hooks, no MCP or LSP servers, no telemetry. |
| **Reads** | Repository files. |
| **Writes** | `/ponytail-sec-audit` and `/ponytail-sec-triage` write only under `.ponytail-sec/`. `/ponytail-sec` and the Dockerfile and Kubernetes checks write nothing. |
| **Runs** | Nothing when a skill loads. Audit: its bundled `previous-scan.sh`, the triage skill's `find-scan.sh` and `check-triage.sh` (to validate earlier triage reports), `git`, `jq`, `date`, `mkdir`, `mktemp`, `sha256sum`/`shasum`, and `ccusage --offline` only if already installed. Triage: its bundled bash + jq scripts, `gh api` for published advisories only if `gh` is already installed, and evidence commands only after you approve them. Nothing is installed or fetched-and-run. |
| **Network** | Dependency lookups in Pass 2 (package name, version and generic terms only, on registry, deps.dev, OpenSSF Scorecard and source-host pages) and, in triage, the repository's published advisories via `gh`. Repository content, file contents, environment variables and secrets are never sent. |

## OWASP Top 10 for LLM Applications (2025)

| Risk | Applies? | Control | Residual risk |
|---|---|---|---|
| **LLM01 Prompt injection** | Yes, the main risk: audited repositories are untrusted. | Every skill, command and the triage agent treats repository content as evidence, never instructions. No command runs when a skill loads. CI blocks skills, commands and agents that pre-approve more than read-only tools. | The evidence rule guides the model; it is not enforcement. Permission prompts are the real control. |
| **LLM02 Sensitive information disclosure** | Yes | Web queries may contain only package, image or field names, versions and generic terms. Triage's only automatic outbound call is `gh api` for published advisories. Secrets are reported by location, type and at most the last 4 characters. The settings above make secret files `ask` and deny your own credentials. | Triage reports for `affected` findings are undisclosed exploit write-ups; the skills warn not to commit them until a fix or advisory ships. Web search has no domain filter. |
| **LLM03 Supply chain** | Yes, the plugin itself | CI skill guard, actions pinned by commit, zizmor, Scorecard, Dependabot, read-only workflow tokens, CODEOWNERS, version-pinned install. | Installing without a version follows `main`. Branch protection must require reviews and passing checks. |
| **LLM04 Data and model poisoning** | Partly | A later audit inherits a triage verdict only if `check-triage.sh` accepts the report and the judged code is unchanged. CODEOWNERS on `.ponytail-sec/` is recommended. | A well-formed planted report on unchanged code is still inherited. |
| **LLM05 Improper output handling** | Low | ponytail-sec never edits code; fixes go to `/ponytail`, which you run. | `/ponytail` is outside this threat model. |
| **LLM06 Excessive agency** | Yes | Nothing runs on install: no hooks, MCP or LSP servers. The triage agent is read-only. Writes stay under `.ponytail-sec/`. Triage evidence commands run only after you approve them. | Depends on your permission mode and runtime. |
| **LLM07 System prompt leakage** | No | The skills are public, MIT-licensed text. | None |
| **LLM08 Vector and embedding weaknesses** | No | No retrieval or embeddings. | None |
| **LLM09 Misinformation** | Yes | Companion, audit and triage findings carry a break-risk; Medium/High ones say to validate at runtime. Triage proves, disproves or rescores. The Dockerfile and Kubernetes checks are binary by design. | False positives and negatives; removal findings in particular can be wrong. |
| **LLM10 Unbounded consumption** | Low | Companion mode caps security findings at 3. The audit records scan cost when `ccusage` is already installed. | A full audit of a large repository is expensive. |

## Running it safely

Claude Code enforces permissions through your settings; a plugin cannot. To run the skills with the least access, add this to `.claude/settings.json` in the repository you audit:

```json
{
  "permissions": {
    "ask": [
      "Read(**/.env)",
      "Read(**/.env.*)",
      "Read(**/*.pem)",
      "Read(**/*.key)"
    ],
    "deny": [
      "Read(~/.ssh/**)",
      "Read(~/.aws/**)",
      "Read(~/.config/gcloud/**)",
      "Read(~/.kube/config)"
    ],
    "allow": [
      "Edit(/.ponytail-sec/**)",
      "WebFetch(domain:pypi.org)",
      "WebFetch(domain:www.npmjs.com)",
      "WebFetch(domain:registry.npmjs.org)",
      "WebFetch(domain:pkg.go.dev)",
      "WebFetch(domain:crates.io)",
      "WebFetch(domain:central.sonatype.com)",
      "WebFetch(domain:rubygems.org)",
      "WebFetch(domain:deps.dev)",
      "WebFetch(domain:api.deps.dev)",
      "WebFetch(domain:scorecard.dev)",
      "WebFetch(domain:api.securityscorecards.dev)",
      "WebFetch(domain:github.com)",
      "WebFetch(domain:raw.githubusercontent.com)"
    ]
  },
  "sandbox": {
    "enabled": true
  }
}
```

- The plugin's own scripts (`previous-scan.sh`, `find-scan.sh`, `check-triage.sh`, `build-index.sh` and the other triage scripts) run through Bash, so you are asked before each one. Approve those plugin paths; don't answer "always allow" for Bash in general.
- `Read` rules also cover Grep and Glob when they target a matching file, but a search of the whole repository can still return lines from a committed secret file without asking. The skills report a secret only by location, type and at most its last 4 characters.
- CVSS scores are checked with `cvss_calculator` only if it is already installed; otherwise reports mark them as not checked. For computed scores, install it yourself once (`pipx install cvss==3.6`). The skills never install it.
- Secret files in the audited repository are `ask`, not `deny`: a committed `.env` or private key is a finding the audit should report, so approve the read when it comes up. Your own credentials under `~` stay denied.
- `Edit` rules cover every file-editing tool, so writes outside `.ponytail-sec/` still ask you first.
- Fetches to other domains still ask you first. Web search has no domain filter; approve it per use.
- The sandbox confines Bash commands (filesystem and network); Read, Edit and WebFetch follow the permission rules above. On Linux it needs `bubblewrap` and `socat`.
- Don't approve "always allow" for Bash while auditing an untrusted repository: permission prompts are the control that stops planted instructions from running commands. Auto mode and `bypassPermissions` remove those prompts too; on untrusted code, turn them off or rely on the sandbox.

**Other runtimes (Antigravity and others).** Tool and permission rules may not be enforced. Run audits of untrusted code in a container, devcontainer or VM, without cloud credentials or SSH keys in the environment.
