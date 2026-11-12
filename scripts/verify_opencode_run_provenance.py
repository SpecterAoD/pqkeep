#!/usr/bin/env python3
"""Independently verify GitHub Actions run provenance before publication.

This is a read-only trust gate. A manifest-provided run ID is never trusted
without comparison to the independently expected ID and GitHub API response.
"""
import re
from urllib.error import HTTPError, URLError

from github_opencode_publisher_preflight import github_get

REPOSITORY = "SpecterAoD/pqkeep"
OWNER_ID = 77644070
SHA = re.compile(r"[0-9a-f]{40}\Z")
ALLOWED_WORKFLOW = ".github/workflows/opencode.yml"


def verify_run(
    expected_run: int, expected_base_sha: str, read_token: str,
    get=github_get,
) -> bool:
    """Reject runs not owned by the designated actor and trusted workflow."""
    if type(expected_run) is not int or expected_run <= 0:
        return False
    if not isinstance(expected_base_sha, str) or not SHA.fullmatch(
        expected_base_sha
    ):
        return False
    if not isinstance(read_token, str) or not read_token:
        return False
    try:
        status, run = get(f"/actions/runs/{expected_run}", read_token)
        if status != 200 or not isinstance(run, dict):
            return False
        actor = run.get("actor")
        trigger = run.get("triggering_actor")
        repo = run.get("repository")
        head_repo = run.get("head_repository")
        if not all(isinstance(item, dict) for item in (
            actor, trigger, repo, head_repo
        )):
            return False
        return (
            run.get("id") == expected_run
            and type(run.get("id")) is int
            and run.get("event") == "issue_comment"
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and run.get("path") == ALLOWED_WORKFLOW
            and run.get("head_sha") == expected_base_sha
            and actor.get("id") == OWNER_ID
            and type(actor.get("id")) is int
            and trigger.get("id") == OWNER_ID
            and type(trigger.get("id")) is int
            and repo.get("full_name") == REPOSITORY
            and head_repo.get("full_name") == REPOSITORY
        )
    except (HTTPError, URLError, OSError, ValueError, TypeError, KeyError):
        return False
