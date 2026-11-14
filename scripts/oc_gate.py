#!/usr/bin/env python3
"""Validate a single GitHub issue_comment event; no API or model access."""
import json
import os
import re
import sys
import urllib.error
import urllib.request

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
    if ("pull_request" in issue or type(issue.get("number")) is not int
            or issue["number"] <= 0):
        return None
    if comment.get("user", {}).get("id") != OWNER_ID:
        return None
    if sender.get("id") != OWNER_ID:
        return None
    body = comment.get("body")
    if (not isinstance(body, str) or len(body) > 4000
            or any(ord(char) < 32 and char not in "\r\n" for char in body)
            or any(char in body for char in ("\u200b", "\u200c", "\u200d", "\ufeff"))):
        return None
    match = COMMAND.fullmatch(body)
    if not match:
        return None
    if match.group(1) == "implement":
        return None  # Not implemented: fail closed until separate approval workflow exists.
    return match.group(1), match.group(2)


def unchanged_comment(event: dict, current: dict) -> bool:
    """A deleted, edited, or replaced comment must not authorize a run."""
    original = event.get("comment") or {}
    return (
        isinstance(original.get("id"), int)
        and current.get("id") == original["id"]
        and current.get("user", {}).get("id") == OWNER_ID
        and current.get("body") == original.get("body")
        and current.get("created_at") == original.get("created_at")
        and current.get("updated_at") == original.get("updated_at")
    )


def fetch_comment(event: dict, repository: str, token: str) -> dict:
    """Fetch by immutable comment ID; no issue-history scanning."""
    comment_id = event["comment"]["id"]
    if not isinstance(comment_id, int) or comment_id <= 0:
        raise ValueError("Missing comment ID")
    url = f"https://api.github.com/repos/{repository}/issues/comments/{comment_id}"
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def main() -> int:
    if len(sys.argv) != 3:
        return 2
    with open(sys.argv[1], encoding="utf-8") as source:
        event = json.load(source)
    result = validate(event, sys.argv[2])
    if result is None:
        print("DENIED")
        return 1
    if os.environ.get("OC_VERIFY_LIVE") == "1":
        token = os.environ.get("GH_TOKEN")
        if not token:
            print("DENIED: missing read token", file=sys.stderr)
            return 1
        try:
            current = fetch_comment(event, sys.argv[2], token)
            if not unchanged_comment(event, current):
                print("DENIED: comment changed", file=sys.stderr)
                return 1
        except (ValueError, KeyError, OSError, urllib.error.URLError):
            print("DENIED: cannot verify comment", file=sys.stderr)
            return 1
    command, _ = result
    print(f"AUTHORIZED command={command} issue={event['issue']['number']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
