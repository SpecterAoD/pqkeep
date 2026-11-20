#!/usr/bin/env python3
"""DE: Eigene, strenge Regeln für die Workflow-Dateien (#181), nur Standardbibliothek, kein
YAML-Parser: explizite `permissions` oben, Actions per vollständigem Commit-SHA, keine
`pull_request_target`/`workflow_run`-Trigger, keine serialisierten Secrets, kein `curl | sh`,
keine Downloads ohne Prüfsumme,
keine Secrets und keine Schreibrechte in PR-Workflows (Ausnahme: CodeQL-Upload), wiederverwendbare
Workflows (`workflow_call`) ohne Schreibrechte, Vorschau-Workflow (`preview.yml`) ohne Signierung und
ohne Environment `release` (#269). Ergänzt
actionlint und zizmor, ersetzt sie nicht. Aufruf: `python3 scripts/check_actions_policy.py`
(Exit 1 bei Funden).

EN: Own strict rules for the workflow files (#181), standard library only, no YAML parser:
explicit top-level `permissions`, actions pinned to full commit SHAs, no
`pull_request_target`/`workflow_run` triggers, no serialized secrets, no `curl | sh`, no downloads
without a checksum, no secrets
and no write permissions in PR workflows (exception: CodeQL upload), reusable workflows
(`workflow_call`) without write permissions, the preview workflow (`preview.yml`) without signing and
without the `release` environment (#269). Complements actionlint and
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
ON_BLOCK = re.compile(r"(?m)^(?:on|'on'|\"on\"):[^\n]*\n(?:(?:[ \t]+[^\n]*|[ \t]*)\n)*")
EVENT = re.compile(r"[A-Za-z_]+")
PRIVILEGED = ("pull_request_target", "workflow_run")
JOB = re.compile(r"(?m)^  (?![ #-])[^\n]*:[ \t]*(?:#[^\n]*)?\n(?:(?:   [^\n]*|[ \t]*)\n)*")
GUARD = re.compile(r"(?m)^    if:\s*github\.event_name != 'pull_request'\s*$")
UNSAFE = (
    (re.compile(r"toJSON\s*\(\s*secrets\s*\)", re.I), "secret serialization"),
    (re.compile(r"(?m)^\s*(?:-\s*run:\s*)?(?:curl|wget)\b[^\n]*\|\s*(?:ba)?sh\b"), "remote shell execution"),
)
SECRET_EXPR = re.compile(r"\$\{\{[^}]*\bsecrets\s*[.\[]")
# DE: Heruntergeladene Dateien brauchen eine Prüfsumme im selben `run`-Schritt (#185): Ausgabe per
#     Option, Umleitung oder Pipe zählt als Download; Kommentare zählen nicht als Prüfung.
# EN: Downloads need a checksum in the same `run` step (#185): output via option, redirection or
#     pipe counts as a download; comments do not count as a check.
RUN_KEY = re.compile(r"^(\s*)(?:-\s+)?run:\s*(.*)$")
DOWNLOAD = re.compile(r"\b(?:curl|wget)\b[^\n]*(?:\s-[a-zA-Z]*[oO]\b|--output\b|--remote-name\b|>|\|)")
CHECKSUM = re.compile(r"sha256sum\s+(?:-c|--check)\b|--require-hashes\b|shasum\s+-a\s*256\s+-c\b")
WRITE_SCOPE = re.compile(r"(?m)^\s*(?:permissions:\s*write-all\b|[a-z-]+:\s*write\b)")
CODEQL_SCOPE = re.compile(r"(?m)^\s*security-events:\s*write\b")
RELEASE_ENV = re.compile(r"(?m)^\s*environment:\s*['\"]?release\b")
SIGNING = re.compile(r"\b(?:cosign|signpath|sigstore)\b", re.I)


def events(text: str) -> set[str]:
    """DE: Auslöser aus dem `on`-Abschnitt (Block, Liste oder Einzeiler). EN: Triggers from `on`."""
    block = ON_BLOCK.search(text + "\n")
    lines = block.group(0).split("\n") if block else []
    return {word for line in lines for word in EVENT.findall(line.split("#", 1)[0])}


def unguarded_writes(text: str, name: str) -> list[str]:
    """DE: Teile mit Schreibrecht ohne eigenen PR-Ausschluss; jeder Job zählt für sich, der
    Ausschluss eines anderen Jobs gilt nicht mit. Ausnahme: nur CodeQL-Upload in codeql.yml.
    EN: Parts with write permission lacking their own PR guard; every job counts on its own,
    another job's guard does not carry over. Exception: CodeQL upload only in codeql.yml."""
    head, _, jobs = (text + "\n").partition("\njobs:")
    parts = [("top level", head)] + [(m.group(0).split(":", 1)[0].strip(), m.group(0))
                                     for m in JOB.finditer(jobs)]
    found = []
    for label, part in parts:
        writes = WRITE_SCOPE.findall(part)
        if not writes or (label != "top level" and GUARD.search(part)):
            continue
        if name == "codeql.yml" and all(CODEQL_SCOPE.fullmatch(w) for w in writes):
            continue
        found.append(label)
    return found


def run_steps(text: str) -> list[str]:
    """DE: Befehle je `run`-Schritt, ohne Kommentarzeilen, Fortsetzungszeilen (`\\`) verbunden.
    EN: Commands per `run` step, without comment lines, continuation lines (`\\`) joined."""
    lines, steps, i = text.split("\n"), [], 0
    while i < len(lines):
        match = RUN_KEY.match(lines[i])
        i += 1
        if not match:
            continue
        indent, rest = len(match.group(1)), match.group(2).strip()
        body = []
        if rest in ("", "|", "|-", "|+", ">", ">-", ">+"):
            while i < len(lines) and (not lines[i].strip()
                                      or len(lines[i]) - len(lines[i].lstrip()) > indent):
                body.append(lines[i])
                i += 1
        else:
            body.append(rest.strip("'\""))
        code = "\n".join(line for line in body if not line.strip().startswith("#"))
        steps.append(re.sub(r"\\\n\s*", " ", code))
    return steps


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
    triggers = events(text)
    for trigger in PRIVILEGED:
        if trigger in triggers:
            problems.append(f"privileged trigger requires separate review: {trigger}")
    for pattern, description in UNSAFE:
        if pattern.search(text):
            problems.append(description)
    for step in run_steps(text):
        if DOWNLOAD.search(step) and not CHECKSUM.search(step):
            problems.append("download without checksum verification")
    code = "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("#"))
    if "workflow_call" in triggers and WRITE_SCOPE.search(code):
        problems.append("reusable workflow requests write permission")
    if name == "preview.yml":
        # DE: Vorschauen werden nicht signiert und brauchen die Freigabe `release` nie.
        # EN: Previews are never signed and never need the `release` approval.
        if RELEASE_ENV.search(code):
            problems.append("preview workflow must not use the release environment")
        if SIGNING.search(code):
            problems.append("preview workflow must not sign")
    if "pull_request" in triggers:
        # DE: Nur echte Ausdrücke, nicht das Wort in Kommentaren. EN: Real expressions only.
        if SECRET_EXPR.search(text):
            problems.append("PR-triggered workflow references repository secrets; review isolation")
        for label in unguarded_writes(text, name):
            problems.append(f"PR-triggered workflow contains write permission without PR guard: {label}")
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
