#!/usr/bin/env python3
"""Validate an issue snapshot against a fresh GitHub API response.

Both objects are untrusted inputs. No tokens or issue bodies are logged.
"""
import hashlib
import json
import sys
from pathlib import Path

OWNER_ID = 77644070
REPO_IDENTITY = "SpecterAoD/pqkeep"


def digest(text: str) -> str:
    """Return stable SHA-256 for an issue text field."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def snapshot(issue: dict, repository: str) -> dict:
    """Create a minimal, immutable issue identity snapshot."""
    user = issue.get("user") or {}
    if (
        repository != REPO_IDENTITY
        or user.get("id") != OWNER_ID
        or not isinstance(issue.get("number"), int)
        or isinstance(issue.get("number"), bool)
        or issue["number"] <= 0
        or issue.get("pull_request") is not None
        or not isinstance(issue.get("title"), str)
        or not isinstance(issue.get("body"), (str, type(None)))
        or not isinstance(issue.get("updated_at"), str)
        or not issue["updated_at"]
    ):
        raise ValueError("invalid issue identity or metadata")
    return {
        "repository": repository,
        "number": issue["number"],
        "author_id": OWNER_ID,
        "updated_at": issue["updated_at"],
        "title_sha256": digest(issue["title"]),
        "body_sha256": digest(issue["body"] or ""),
    }


def unchanged(saved: dict, current: dict, repository: str) -> bool:
    """Fail closed if issue identity, timestamp, or content changed."""
    try:
        return saved == snapshot(current, repository)
    except (AttributeError, TypeError, ValueError):
        return False


def main() -> int:
    """Compare saved snapshot with fresh API issue JSON, exit 1 on mismatch."""
    if len(sys.argv) != 3:
        print("DENIED: expected snapshot and current issue paths", file=sys.stderr)
        return 1
    try:
        saved = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        current = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
        if not isinstance(saved, dict) or not isinstance(current, dict):
            raise ValueError("invalid objects")
        if not unchanged(saved, current, REPO_IDENTITY):
            raise ValueError("issue changed")
    except (OSError, UnicodeError, ValueError, TypeError):
        print("DENIED: issue snapshot mismatch", file=sys.stderr)
        return 1
    print("ALLOWED: issue snapshot unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
