#!/usr/bin/env python3
"""Fail-closed static policy for GitHub Actions workflow files (stdlib only)."""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SHA_ACTION = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
PERMISSION = re.compile(r"(?m)^permissions:\s*(?:\{\s*\}|\n(?:[ \t]+[^\n]+\n)+)")
TRIGGER = re.compile(r"(?m)^\s{0,2}(pull_request_target|workflow_run):")
UNSAFE = (
    (re.compile(r"toJSON\s*\(\s*secrets\s*\)", re.I), "secret serialization"),
    (re.compile(r"(?m)^\s*(?:curl|wget)\b[^\n]*\|\s*(?:ba)?sh\b"), "remote shell execution"),
)
WRITE_SCOPE = re.compile(r"(?m)^\s*(?:contents|actions|packages|security-events|attestations|id-token):\s*write\b")
JOB = re.compile(r"(?m)^  ([a-zA-Z][\w-]*):\s*$")


def audit(text: str, name: str) -> list[str]:
    """Return policy failures; no shell execution and no YAML parser dependency."""
    problems: list[str] = []
    if not PERMISSION.search(text):
        problems.append("missing explicit top-level permissions")
    for action in SHA_ACTION.findall(text):
        if action.startswith("./"):
            continue
        if action.startswith("docker://"):
            if "@sha256:" not in action:
                problems.append(f"unpinned container action: {action}")
            continue
        if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action):
            problems.append(f"unpinned action: {action}")
    for match in TRIGGER.finditer(text):
        problems.append(f"privileged trigger requires separate review: {match.group(1)}")
    for pattern, description in UNSAFE:
        if pattern.search(text):
            problems.append(description)
    if "pull_request:" in text and "secrets." in text:
        problems.append("PR-triggered workflow references repository secrets; review isolation")
    if "pull_request:" in text and WRITE_SCOPE.search(text):
        # Job-level write can be legitimate when guarded; report for explicit review.
        problems.append("PR-triggered workflow contains write permission; review job guards")
    return [f"{name}: {problem}" for problem in problems]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=pathlib.Path, default=WORKFLOWS)
    args = parser.parse_args()
    paths = sorted(args.path.glob("*.yml")) + sorted(args.path.glob("*.yaml"))
    if not paths:
        print("No workflow files found", file=sys.stderr)
        return 2
    failures = []
    for path in paths:
        failures.extend(audit(path.read_text(encoding="utf-8"), path.name))
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"Audited {len(paths)} workflow files; {len(failures)} findings")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
