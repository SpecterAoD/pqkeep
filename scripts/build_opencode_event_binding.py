#!/usr/bin/env python3
"""Build an event identity only after independent GitHub API revalidation.

Pure helper for a future trusted preflight. Does not sign, upload or publish.
Never invoke it with an AI-generated event or unverified GitHub API response.
"""
import re

from attest_opencode_event import ACTOR_ID, REPOSITORY, WORKFLOW, canonical
from revalidate_opencode_event import verified_metadata

SHA = re.compile(r"[0-9a-f]{40}\Z")


def build_binding(event: dict, live_comment: dict, live_issue: dict,
                  run_id: int, base_sha: str) -> dict:
    """Bind the validated issue/comment to an independent run and SHA."""
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("invalid independent run ID")
    if not isinstance(base_sha, str) or not SHA.fullmatch(base_sha):
        raise ValueError("invalid independent base SHA")
    verified_metadata(event, live_comment, live_issue)
    record = {
        "repository": REPOSITORY,
        "workflow": WORKFLOW,
        "run_id": run_id,
        "issue_number": live_issue["number"],
        "comment_id": live_comment["id"],
        "base_sha": base_sha,
        "event": "issue_comment",
        "actor_id": ACTOR_ID,
    }
    canonical(record)
    return record
