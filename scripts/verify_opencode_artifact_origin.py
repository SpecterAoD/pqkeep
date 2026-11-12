#!/usr/bin/env python3
"""Verify a proposal ZIP belongs to the independently verified Actions run.

This gate only reads GitHub metadata. Artifact name is deterministic and must
match the independently expected issue/run. No artifact URL is trusted here.
"""
import re
from urllib.error import HTTPError, URLError

from github_opencode_publisher_preflight import github_get

REPOSITORY = "SpecterAoD/pqkeep"
MAX_ARTIFACT_SIZE = 120_000
SHA = re.compile(r"[0-9a-f]{40}\Z")


def verify_artifact_listing(
    issue: int, run: int, base_sha: str, artifact_id: int,
    token: str, get=github_get,
) -> bool:
    """Bind a uniquely named artifact to one verified run and issue."""
    if any(type(value) is not int or value <= 0 for value in (
        issue, run, artifact_id
    )):
        return False
    if not isinstance(base_sha, str) or not SHA.fullmatch(base_sha):
        return False
    if not isinstance(token, str) or not token:
        return False
    expected_name = f"opencode-issue-{issue}-run-{run}"
    try:
        status, payload = get(
            f"/actions/runs/{run}/artifacts?per_page=100&page=1", token
        )
        if status != 200 or not isinstance(payload, dict):
            return False
        items = payload.get("artifacts")
        if not isinstance(items, list) or len(items) != 1:
            return False
        artifact = items[0]
        if not isinstance(artifact, dict):
            return False
        workflow = artifact.get("workflow_run")
        if not isinstance(workflow, dict):
            return False
        return (
            payload.get("total_count") == 1
            and type(payload.get("total_count")) is int
            and artifact.get("id") == artifact_id
            and type(artifact.get("id")) is int
            and artifact.get("name") == expected_name
            and artifact.get("expired") is False
            and type(artifact.get("size_in_bytes")) is int
            and 0 < artifact["size_in_bytes"] <= MAX_ARTIFACT_SIZE
            and workflow.get("id") == run
            and type(workflow.get("id")) is int
            and workflow.get("head_sha") == base_sha
            and type(workflow.get("repository_id")) is int
            and workflow["repository_id"] > 0
        )
    except (HTTPError, URLError, OSError, ValueError, TypeError, KeyError):
        return False
