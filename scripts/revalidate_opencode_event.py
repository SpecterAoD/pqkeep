#!/usr/bin/env python3
"""Revalidate a GitHub issue_comment event against the GitHub REST API.

This is a read-only preflight gate, not an agent runner.
"""
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from authorize_opencode import REPOSITORY, MAINTAINER_ID, authorized
from verify_opencode_issue import snapshot

API_ROOT = "https://api.github.com/repos/SpecterAoD/pqkeep"


def verified_metadata(event: dict, comment: dict, issue: dict) -> dict:
    """Fail closed if GitHub's current records disagree with the event."""
    if not authorized(event, REPOSITORY):
        raise ValueError("event unauthorized")
    original = event["comment"]
    if comment.get("id") != original["id"]:
        raise ValueError("comment ID changed")
    if (comment.get("user") or {}).get("id") != MAINTAINER_ID:
        raise ValueError("comment author changed")
    if comment.get("body") != "/oc":
        raise ValueError("comment edited")
    if not comment.get("created_at") or (
        comment.get("created_at") != comment.get("updated_at")
    ):
        raise ValueError("comment edited after creation")
    if comment.get("created_at") != original.get("created_at"):
        raise ValueError("comment creation timestamp mismatch")
    if issue.get("number") != event["issue"]["number"]:
        raise ValueError("issue identity changed")
    if issue.get("updated_at") != event["issue"].get("updated_at"):
        raise ValueError("issue edited after event")
    current = snapshot(issue, REPOSITORY)
    original_snapshot = snapshot(event["issue"], REPOSITORY)
    if current != original_snapshot:
        raise ValueError("issue content changed")
    return current


def fetch_json(url: str, token: str) -> dict:
    """Fetch one exact trusted API endpoint; no redirects or untrusted URLs."""
    if not url.startswith(API_ROOT + "/"):
        raise ValueError("API endpoint outside repository")
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=15) as response:
        if response.status != 200:
            raise ValueError("GitHub API unexpected status")
        if int(response.headers.get("Content-Length", "0")) > 200_000:
            raise ValueError("GitHub API response too large")
        data = response.read(200_001)
        if len(data) > 200_000:
            raise ValueError("GitHub API response too large")
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError("GitHub API response invalid")
        return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevent authorization headers being sent to redirected hosts."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Reject all redirects."""
        raise ValueError("GitHub API redirect refused")


def main() -> int:
    """Verify event, then write a snapshot without disclosing issue text."""
    try:
        token = os.environ["GH_READ_TOKEN"]
        if not token:
            raise ValueError("missing read token")
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        if not isinstance(event, dict) or not authorized(
            event, os.environ.get("GITHUB_REPOSITORY", "")
        ):
            raise ValueError("unauthorized event")
        number = event["issue"]["number"]
        comment_id = event["comment"]["id"]
        comment = fetch_json(f"{API_ROOT}/issues/comments/{comment_id}", token)
        issue = fetch_json(f"{API_ROOT}/issues/{number}", token)
        verified = verified_metadata(event, comment, issue)
        output = Path(os.environ["OPENCODE_SNAPSHOT_PATH"])
        output.write_text(json.dumps(verified, sort_keys=True) + "\n")
    except (
        KeyError, OSError, ValueError, TypeError, UnicodeError,
        urllib.error.URLError,
    ):
        print("DENIED: GitHub issue/comment revalidation failed", file=sys.stderr)
        return 1
    print("ALLOWED: GitHub issue/comment revalidated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
