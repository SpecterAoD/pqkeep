#!/usr/bin/env python3
"""DE: Eigene, strenge Regeln für die Workflow-Dateien (#181), nur Standardbibliothek, kein
YAML-Parser: explizite `permissions` oben, Actions per vollständigem Commit-SHA, keine
`pull_request_target`/`workflow_run`-Trigger, keine serialisierten Secrets, kein `curl | sh`,
keine Secrets und keine Schreibrechte in PR-Workflows (Ausnahme: CodeQL-Upload). Ergänzt
actionlint und zizmor, ersetzt sie nicht. Aufruf: `python3 scripts/check_actions_policy.py`
(Exit 1 bei Funden).

EN: Own strict rules for the workflow files (#181), standard library only, no YAML parser:
explicit top-level `permissions`, actions pinned to full commit SHAs, no
`pull_request_target`/`workflow_run` triggers, no serialized secrets, no `curl | sh`, no secrets
and no write permissions in PR workflows (exception: CodeQL upload). Complements actionlint and
zizmor, does not replace them. Usage: `python3 scripts/check_actions_policy.py` (exit 1 on
findings).
"""
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
    (re.compile(r"(?m)^\s*(?:-\s*run:\s*)?(?:curl|wget)\b[^\n]*\|\s*(?:ba)?sh\b"), "remote shell execution"),
)
SECRET_EXPR = re.compile(r"\$\{\{[^}]*\bsecrets\s*[.\[]")
WRITE_SCOPE = re.compile(r"(?m)^\s*(?:contents|actions|packages|security-events|attestations|id-token):\s*write\b")


def audit(text: str, name: str) -> list[str]:
    """DE: Funde einer Workflow-Datei (leer = in Ordnung). EN: Findings of one workflow file."""
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
    # DE: Nur echte Ausdrücke, nicht das Wort in Kommentaren. EN: Real expressions only.
    if "pull_request:" in text and SECRET_EXPR.search(text):
        problems.append("PR-triggered workflow references repository secrets; review isolation")
    if ("pull_request:" in text and WRITE_SCOPE.search(text)
            and "if: github.event_name != 'pull_request'" not in text
            and not (name == "codeql.yml"
                     and "security-events: write" in text
                     and "contents: write" not in text
                     and "actions: write" not in text)):
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
