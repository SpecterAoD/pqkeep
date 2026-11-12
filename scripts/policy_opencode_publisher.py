#!/usr/bin/env python3
"""Fail-closed policy for a future OpenCode draft PR publisher.

Pure validation only: no network calls, no git push, no PR creation.
The caller MUST independently verify branch nonexistence via GitHub API.
"""
import re
import sys

REPO = "SpecterAoD/pqkeep"
BASE = "main"
BRANCH = re.compile(r"opencode/issue-([1-9][0-9]*)-run-([1-9][0-9]*)\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
ALLOWED_METHODS = frozenset({"POST"})
ALLOWED_ENDPOINT = "/repos/SpecterAoD/pqkeep/pulls"


def authorized_publication(
    proposal: dict, expected_issue: int, expected_run: int,
    expected_base_sha: str, branch_exists: bool,
) -> bool:
    """Allow only one brand-new draft PR against a fixed base."""
    if not isinstance(proposal, dict):
        return False
    if set(proposal) != {
        "repository", "base", "base_sha", "head",
        "draft", "maintainer_can_modify", "issue_number",
        "run_id", "method", "endpoint",
    }:
        return False
    for value in (expected_issue, expected_run):
        if type(value) is not int or value <= 0:
            return False
    if type(branch_exists) is not bool or branch_exists:
        return False
    if not isinstance(expected_base_sha, str) or not SHA.fullmatch(
        expected_base_sha
    ):
        return False
    if (
        proposal["repository"] != REPO
        or proposal["base"] != BASE
        or proposal["base_sha"] != expected_base_sha
        or proposal["draft"] is not True
        or proposal["maintainer_can_modify"] is not False
        or proposal["method"] not in ALLOWED_METHODS
        or proposal["endpoint"] != ALLOWED_ENDPOINT
        or type(proposal["issue_number"]) is not int
        or type(proposal["run_id"]) is not int
        or proposal["issue_number"] != expected_issue
        or proposal["run_id"] != expected_run
    ):
        return False
    head = proposal["head"]
    if not isinstance(head, str):
        return False
    match = BRANCH.fullmatch(head)
    return bool(
        match
        and int(match.group(1)) == expected_issue
        and int(match.group(2)) == expected_run
    )


def main() -> int:
    """Not an API client. No publishing entrypoint is available yet."""
    print("DENIED: publishing disabled; policy is validation-only", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
