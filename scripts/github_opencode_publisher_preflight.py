#!/usr/bin/env python3
"""Read-only GitHub preflight for a future draft PR publisher.

No write API, no git push, no credential forwarding to untrusted code.
"""
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from policy_opencode_publisher import authorized_publication

API = "https://api.github.com/repos/SpecterAoD/pqkeep"
SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_RESPONSE = 100_000


def github_get(path: str, token: str) -> tuple[int, dict]:
    """Read a fixed GitHub API path, never follow redirects."""
    if not path.startswith("/"):
        raise ValueError("invalid API path")
    request = Request(
        API + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "pqkeep-opencode-publisher-preflight",
        },
        method="GET",
    )
    # urllib follows redirects by default. Reject them explicitly.
    from urllib.request import build_opener, HTTPRedirectHandler

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = build_opener(NoRedirect)
    try:
        response = opener.open(request, timeout=10)
    except HTTPError as exc:
        if exc.code == 404:
            return 404, {}
        raise
    with response:
        if response.status != 200:
            raise ValueError("unexpected GitHub API response")
        data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise ValueError("oversized GitHub response")
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError("invalid GitHub response")
        return 200, result


def preflight(proposal: dict, expected_issue: int, expected_run: int,
              expected_base_sha: str, token: str,
              get=github_get) -> bool:
    """Require exact branch policy and GitHub state before any future push."""
    if not isinstance(token, str) or not token:
        return False
    if not authorized_publication(
        proposal, expected_issue, expected_run, expected_base_sha, False
    ):
        return False
    try:
        status, branch = get("/branches/main", token)
        if status != 200:
            return False
        current_sha = branch.get("commit", {}).get("sha")
        if current_sha != expected_base_sha:
            return False
        head = proposal["head"]
        status, _ = get("/git/ref/heads/" + quote(head, safe="/"), token)
        if status != 404:
            return False
    except (HTTPError, URLError, OSError, ValueError, TypeError, KeyError):
        return False
    return True


def main() -> int:
    """Read JSON proposal and independently trusted identity; never publish."""
    if len(sys.argv) != 2:
        return 1
    try:
        with open(sys.argv[1], encoding="utf-8") as file:
            proposal = json.load(file)
        issue = int(os.environ["OPENCODE_EXPECTED_ISSUE"])
        run = int(os.environ["OPENCODE_EXPECTED_RUN_ID"])
        base = os.environ["OPENCODE_EXPECTED_BASE_SHA"]
        token = os.environ["GH_READ_TOKEN"]
        if not preflight(proposal, issue, run, base, token):
            raise ValueError("publication preflight denied")
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        print("DENIED: GitHub publisher preflight failed", file=sys.stderr)
        return 1
    print("PASS: GitHub state matches draft policy; publication still disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
