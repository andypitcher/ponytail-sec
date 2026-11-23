#!/usr/bin/env python3
"""Fail CI when the plugin's prompt surface gains exec, network, hidden-text,
or auto-run capabilities. Stdlib only; run from the repo root:

    python3 -I .github/scripts/skill-guard.py

Checks (tracked files only):
  1. exec/network patterns and load-time shell injection (!`cmd` in skills,
     !{cmd} in command TOML) in skills/, agents/, commands/ -- allowlist below
  2. invisible, bidi or variation-selector Unicode in any tracked text file
     (prompt-injection carriers)
  3. hooks, MCP servers or LSP servers anywhere in the plugin
  4. SKILL.md and command .md front matter must parse, use allowlisted keys
     only (no hooks), and pre-approve read-only tools only (allowed-tools
     skips prompts); commands/ holds .toml and .md files only
  5. agents: front matter must parse, allowlisted keys only, read-only tools
  6. manifests: no custom component paths, so checks 1, 4 and 5 see every
     skill, command and agent the plugin loads
  7. no tracked symlinks or submodules: they load files the checks never see
  8. marketplace plugins load from the repo root only (source "./")
  9. lines end in \n (or \r\n) only: a lone \r, NEL or other separator
     would make the checks here and the runtime split lines differently
Command TOML is also checked after decoding, so a \u0021 escape cannot hide
`!{cmd}`; tool lists may not use escapes either.
Path checks ignore case (macOS and Windows load `Hooks/` as `hooks/`), and a
text file that is not valid UTF-8 fails instead of being skipped as binary.
"""
import json
import re
import subprocess
import sys
import tomllib
import unicodedata
from pathlib import Path

ALLOWLIST = Path(".github/scripts/skill-guard-allow.txt")

EXEC_PATTERNS = re.compile(
    r"\bcurl\b|\bwget\b|\bnc\s|\bncat\b|/dev/(?:tcp|udp)\b|\bnpx\b|\bbunx\b"
    r"|\bpnpm\s+dlx\b|\bpip3?\s+install\b|base64\s+(?:-d|--decode)"
    r"|\|\s*(?:ba|z)?sh\b"
    r"|!`|!\{"
    r"|^\s*(?:`{3,}|~{3,})\s*!"  # fenced load-time block: a ```! fence runs on load
)
# Format (Cf: bidi controls and marks, zero-width, soft hyphen, tags...) and
# line/paragraph separators, plus invisible letters and marks outside Cf.
INVISIBLE_EXTRA = set("\u034f\u115f\u1160\u17b4\u17b5\u3164\uffa0") | {
    chr(c) for c in range(0xE0100, 0xE01F0)}


def hidden_chars(line):
    return [c for c in line
            if unicodedata.category(c) in ("Cf", "Zl", "Zp") or c in INVISIBLE_EXTRA]


# One selector after an emoji (e.g. the U+FE0F in a warning sign) is normal;
# a run of them can encode hidden text.
SELECTOR_RUN = re.compile("[\ufe00-\ufe0f]{2,}")
SKILL_KEYS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
READ_ONLY_TOOLS = {"Read", "Grep", "Glob"}
COMMAND_KEYS = {"description", "allowed-tools", "argument-hint", "model", "disable-model-invocation"}
AGENT_KEYS = {"name", "description", "tools", "model", "color"}
MANIFESTS = {"plugin.json", ".claude-plugin/plugin.json", ".claude-plugin/marketplace.json"}
AUTORUN_KEYS = {"hooks", "mcpServers", "lspServers"}
AUTORUN_FILES = {".mcp.json", ".lsp.json"}
# Lone \r, VT, FF, file/group/record separators, NEL: str.splitlines() and
# split("\n") disagree on these, so lines would be cut differently.
ODD_BREAK = re.compile("\r(?!$)|[\x0b\x0c\x1c-\x1e\x85]")
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp"}
# Custom paths would load components from outside the folders checked here.
COMPONENT_PATH_KEYS = {"skills", "commands", "agents", "outputStyles"}


def tracked_files():
    """{path: git mode} for every tracked file; mode 120000 is a symlink."""
    out = subprocess.run(["git", "ls-files", "-s", "-z"], capture_output=True, check=True).stdout
    files = {}
    for entry in out.decode().split("\0"):
        if entry:
            meta, _, path = entry.partition("\t")
            files[path] = meta.split()[0]
    return files


def load_allowlist():
    """Lines of `path<TAB>exact line text`; blank lines and # comments ignored."""
    allowed = set()
    for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        if raw.strip() and not raw.startswith("#"):
            path, _, text = raw.partition("\t")
            allowed.add((path, text.strip()))
    return allowed


def front_matter(text):
    """Return ({key: raw value lines}, [unparseable lines]) for a leading ---
    block, or None. Only plain `key:` lines start a key; indented lines and
    `- item` lines continue it. Anything else (a quoted key, flow mapping)
    is reported rather than silently attached to the previous key."""
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return None
    keys, bad, current = {}, [], None
    for line in lines[1:]:
        if line == "---":
            return keys, bad
        match = re.match(r"([A-Za-z_][\w-]*):(.*)$", line)
        if match:
            current = match.group(1)
            if current in keys:  # YAML loaders disagree on which duplicate wins
                bad.append(f"duplicate key '{current}'")
            keys[current] = [match.group(2)]
        elif current and (line[:1].isspace() or line.startswith("- ") or not line.strip()):
            keys[current].append(line)
        elif line.strip() and not line.startswith("#"):
            bad.append(line.strip())
    return None


def strings(node, key=""):
    """(key, value) for every string in a parsed TOML/JSON tree."""
    if isinstance(node, str):
        yield key, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from strings(v, k)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v, key)


def tool_names(value_lines):
    """Tool names from a space/comma string or a YAML list, minus any (...) scope."""
    raw = " ".join(v.strip().lstrip("-").strip() for v in value_lines)
    if "\\" in raw:
        return {"<escape sequence: " + raw[:40] + ">"}  # YAML "\u0042ash" is Bash
    raw = re.sub(r"\(.*?\)", "()", raw)
    return {t for t in re.split(r"[\s,\[\]]+", raw) if t}


def main():
    errors = []
    files = tracked_files()
    allowed = load_allowlist()

    for path, mode in files.items():
        p = Path(path)
        lp, lname = path.lower(), p.name.lower()
        if mode in ("120000", "160000"):
            errors.append(f"{path}: symlinks and submodules are not allowed in this plugin")
            continue
        if lp.split("/")[0] == "hooks" or lp.startswith(".claude-plugin/hooks") or lname in AUTORUN_FILES:
            errors.append(f"{path}: hooks, MCP or LSP config is not allowed in this plugin")
        if not p.is_file():
            continue
        try:
            text = p.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            if p.suffix.lower() not in BINARY_SUFFIXES:
                errors.append(f"{path}: not valid UTF-8; a skipped file would skip every check")
            continue

        def check_line(where, line, first=False):
            if ODD_BREAK.search(line):
                errors.append(f"{where}: line break other than \\n or \\r\\n")
            hidden = hidden_chars(line)
            if hidden and not (first and line.startswith("\ufeff") and len(hidden) == 1):
                codes = ", ".join(f"U+{ord(c):04X}" for c in hidden)
                errors.append(f"{where}: invisible/bidi Unicode ({codes})")
            if SELECTOR_RUN.search(line):
                errors.append(f"{where}: run of Unicode variation selectors")
            if lp.startswith(("skills/", "agents/", "commands/")) and EXEC_PATTERNS.search(line):
                if (path, line.strip()) not in allowed:
                    errors.append(f"{where}: exec/network pattern: {line.strip()[:100]}")

        # split on \n only: splitlines() would eat U+2028/U+2029 before the check
        for n, line in enumerate(text.split("\n"), 1):
            check_line(f"{path}:{n}", line, first=(n == 1))

        if lp.startswith("commands/") and p.suffix.lower() == ".toml":
            # The agent sees decoded strings: check those too.
            try:
                values = list(strings(tomllib.loads(text)))
            except tomllib.TOMLDecodeError as e:
                errors.append(f"{path}: invalid TOML: {e}")
                values = []
            for key, value in values:
                for line in value.split("\n"):
                    check_line(f"{path} [{key}, decoded]", line)

        if lp in MANIFESTS:
            def walk(node):
                if isinstance(node, dict):
                    for key, value in node.items():
                        if key in AUTORUN_KEYS:
                            errors.append(f"{path}: '{key}' is not allowed in a manifest")
                        elif key in COMPONENT_PATH_KEYS:
                            errors.append(f"{path}: '{key}' custom path is not allowed; use the default {key} folder")
                        walk(value)
                elif isinstance(node, list):
                    for item in node:
                        walk(item)
            walk(json.loads(text))
            if lname == "marketplace.json":
                for plugin in json.loads(text).get("plugins", []):
                    if plugin.get("source") != "./":
                        errors.append(f"{path}: plugin source must be \"./\" so the guard sees every component")

        if lp.startswith("skills/") and lname == "skill.md":
            parsed = front_matter(text)
            if parsed is None:
                errors.append(f"{path}: missing or unterminated front matter")
                continue
            fm, bad = parsed
            errors.extend(f"{path}: unsupported front matter line: {b[:80]}" for b in bad)
            for key in sorted(set(fm) - SKILL_KEYS):
                errors.append(f"{path}: front matter key '{key}' is outside the Agent Skills spec")
            if "allowed-tools" in fm:
                extra = tool_names(fm["allowed-tools"]) - READ_ONLY_TOOLS
                if extra:
                    errors.append(f"{path}: allowed-tools pre-approves non-read-only tools: {sorted(extra)}")

        if lp.startswith("commands/"):
            suffix = p.suffix.lower()
            if suffix not in {".toml", ".md"}:
                errors.append(f"{path}: only .toml and .md files are allowed in commands/")
            elif suffix == ".md" and (parsed := front_matter(text)) is None:
                errors.append(f"{path}: missing or unterminated front matter")
            elif suffix == ".md":
                fm, bad = parsed
                errors.extend(f"{path}: unsupported front matter line: {b[:80]}" for b in bad)
                for key in sorted(set(fm) - COMMAND_KEYS):
                    errors.append(f"{path}: command front matter key '{key}' is not allowed")
                extra = tool_names(fm.get("allowed-tools", [])) - READ_ONLY_TOOLS
                if extra:
                    errors.append(f"{path}: allowed-tools pre-approves non-read-only tools: {sorted(extra)}")

        if lp.startswith("agents/") and p.suffix.lower() == ".md":
            parsed = front_matter(text)
            if parsed is None:
                errors.append(f"{path}: missing or unterminated front matter")
                continue
            fm, bad = parsed
            errors.extend(f"{path}: unsupported front matter line: {b[:80]}" for b in bad)
            for key in sorted(set(fm) - AGENT_KEYS):
                errors.append(f"{path}: agent front matter key '{key}' is not allowed")
            tools = tool_names(fm.get("tools", []))
            if not tools:
                errors.append(f"{path}: agent must declare a read-only tools list")
            elif tools - READ_ONLY_TOOLS:
                errors.append(f"{path}: agent tools beyond read-only: {sorted(tools - READ_ONLY_TOOLS)}")

    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        print(f"skill-guard: {len(errors)} problem(s). Legitimate prose mentions go in {ALLOWLIST}.")
        return 1
    print(f"skill-guard: OK ({len(files)} tracked files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
