#!/usr/bin/env python3
"""Validate a single GitHub issue_comment event; no API or model access."""
import json
import re
import sys

OWNER_ID = 77644070
COMMAND = re.compile(r"^/oc (plan|review|explain|implement) ([^\r\n]+)", re.ASCII)


def validate(event: dict, repository: str) -> tuple[str, str] | None:
    comment = event.get("comment") or {}
    issue = event.get("issue") or {}
    sender = event.get("sender") or {}
    repo = event.get("repository") or {}
    if event.get("action") != "created":
        return None
    if repo.get("full_name") != repository or repository != "SpecterAoD/pqkeep":
        return None
    if "pull_request" in issue or not isinstance(issue.get("number"), int):
        return None
    if comment.get("user", {}).get("id") != OWNER_ID:
        return None
    if sender.get("id") != OWNER_ID:
        return None
    body = comment.get("body")
    if not isinstance(body, str) or len(body) > 4000:
        return None
    match = COMMAND.fullmatch(body.strip("\r\n"))
    if not match:
        return None
    return match.group(1), match.group(2)


def main() -> int:
    if len(sys.argv) != 3:
        return 2
    with open(sys.argv[1], encoding="utf-8") as source:
        event = json.load(source)
    result = validate(event, sys.argv[2])
    if result is None:
        print("DENIED")
        return 1
    command, _ = result
    print(f"AUTHORIZED command={command} issue={event['issue']['number']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
