"""Read audit v3 findings and report per-finding triage-file status."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def read_scan(scan=None):
    if scan is None:
        scans = sorted(
            path for path in Path(".ponytail-sec").glob("audit-*") if path.is_dir()
        )
        if not scans:
            raise ValueError("No audit scan found. Paste a finding or run /ponytail-sec-audit.")
        scan = scans[-1]
    scan = Path(scan).resolve()
    raw = (scan / "findings.json").read_bytes()
    findings = json.loads(raw)
    meta = json.loads((scan / "meta.json").read_bytes())
    if not isinstance(findings, dict) or not isinstance(meta, dict):
        raise ValueError("findings.json and meta.json must be JSON objects.")
    if findings.get("schema_version") == 2 or meta.get("schema_version") == 2:
        raise ValueError("Schema v2 is unsupported. Re-run /ponytail-sec-audit; do not migrate.")
    if findings.get("schema_version") != 3 or meta.get("schema_version") != 3:
        raise ValueError("Expected schema v3 findings.json and meta.json.")
    if hashlib.sha256(raw).hexdigest() != meta.get("findings_sha256"):
        print("WARNING: findings_sha256 mismatch; findings may have changed.", file=sys.stderr)

    buckets = findings.get("findings")
    if not isinstance(buckets, dict):
        raise ValueError("Expected code, dependency, and security finding buckets.")
    entries = []
    seen = set()
    for bucket, prefix in (("code", "C"), ("dependency", "D"), ("security", "S")):
        if not isinstance(buckets.get(bucket), list):
            raise ValueError(f"Expected a {bucket} findings array.")
        for finding in buckets[bucket]:
            identifier = finding.get("id") if isinstance(finding, dict) else None
            if not isinstance(identifier, str) or not re.fullmatch(prefix + r"[1-9][0-9]*", identifier):
                raise ValueError(f"Invalid {bucket} finding ID: {identifier!r}")
            if identifier in seen:
                raise ValueError(f"Duplicate finding ID: {identifier}")
            seen.add(identifier)
            entries.append({
                "finding": finding,
                "triaged": (scan / "triage" / f"{identifier}.triage.md").is_file(),
            })
    return {"scan": str(scan), "findings": entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan", type=Path, help="Audit directory (default: latest audit-*).")
    args = parser.parse_args()
    try:
        result = read_scan(args.scan)
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
