#!/usr/bin/env python3
"""Trusted publisher entry gate: require signed event identity before preflight.

This is a read-only wrapper. The expected identity and signing key MUST be
supplied independently by trusted infrastructure, never from agent artifacts.
No GitHub write permissions or publisher side effects are implemented.
"""
from pathlib import Path

from check_opencode_publisher_ready import check
from verify_opencode_event_binding import verify_files


def check_bound(repository: Path, manifest: Path, archive: Path,
                issue_snapshot: Path, proposal: dict, issue_number: int,
                run_id: int, base_sha: str, read_token: str, artifact_id: int,
                comment_id: int, envelope_path: Path, expected_path: Path,
                key_path: Path, **trusted_overrides) -> list[str]:
    """Deny before any GitHub API call if trusted HMAC binding fails."""
    if not verify_files(envelope_path, expected_path, key_path):
        raise ValueError("event binding verification denied")
    # Verify the expected identity is the one actually used by this request.
    from verify_opencode_event_binding import load_json
    expected = load_json(expected_path)
    if (type(issue_number) is not int or type(run_id) is not int
            or type(comment_id) is not int
            or expected["issue_number"] != issue_number
            or expected["run_id"] != run_id
            or expected["comment_id"] != comment_id
            or expected["base_sha"] != base_sha):
        raise ValueError("trusted identity differs from publication request")
    return check(
        repository, manifest, archive, issue_snapshot, proposal, issue_number,
        run_id, base_sha, read_token, artifact_id,
        expected_comment_id=comment_id, **trusted_overrides,
    )
