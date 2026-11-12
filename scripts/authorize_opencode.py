#!/usr/bin/env python3
"""Fail-closed authorization for OpenCode issue_comment events.

Reads GitHub's event JSON; prints no untrusted content.
"""
import json
import os
import sys
from pathlib import Path

REPOSITORY = "SpecterAoD/pqkeep"
MAINTAINER_ID = 77644070


def authorized(event: dict, repository: str) -> bool:
    """Allow only an exact /oc command on an owner's normal issue."""
    if repository != REPOSITORY:
        return False
    if event.get("action") != "created":
        return False
    sender = event.get("sender") or {}
    comment = event.get("comment") or {}
    issue = event.get("issue") or {}
    repo = event.get("repository") or {}
    if repo.get("full_name") != REPOSITORY:
        return False
    if sender.get("id") != MAINTAINER_ID or sender.get("type") != "User":
        return False
    if (comment.get("user") or {}).get("id") != MAINTAINER_ID:
        return False
    if (issue.get("user") or {}).get("id") != MAINTAINER_ID:
        return False
    if "pull_request" in issue:
        return False
    if not isinstance(issue.get("number"), int) or issue["number"] <= 0:
        return False
    if comment.get("body") != "/oc":
        return False
    return True


def main() -> int:
    """Validate event and exit nonzero for every denied request."""
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not event_path:
        print("DENIED: event path missing", file=sys.stderr)
        return 1
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"DENIED: invalid event ({type(exc).__name__})", file=sys.stderr)
        return 1
    if not isinstance(event, dict) or not authorized(event, repository):
        print("DENIED: unauthorized issue comment", file=sys.stderr)
        return 1
    print(f"AUTHORIZED: issue #{event['issue']['number']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
