#!/usr/bin/env python3
"""Verify an untrusted AI artifact against a trusted run manifest.

This only checks artifact identity. It does not authorize publication.
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
MAX_ARTIFACT = 100_000
MAX_MANIFEST = 4_096


def verify(
    manifest: dict, artifact: bytes, issue: dict,
    expected_run_id: int, expected_base_sha: str,
) -> bool:
    """Fail closed on wrong identity, size, hash, or run metadata."""
    if not isinstance(manifest, dict) or not isinstance(issue, dict):
        return False
    if set(manifest) != {
        "repository", "run_id", "issue_number", "base_sha",
        "artifact_sha256", "artifact_size",
    }:
        return False
    if (
        not isinstance(expected_run_id, int)
        or isinstance(expected_run_id, bool)
        or expected_run_id <= 0
        or not isinstance(expected_base_sha, str)
        or not COMMIT.fullmatch(expected_base_sha)
    ):
        return False
    if manifest["repository"] != "SpecterAoD/pqkeep":
        return False
    if not isinstance(manifest["run_id"], int) or isinstance(
        manifest["run_id"], bool
    ) or manifest["run_id"] <= 0:
        return False
    if not isinstance(manifest["issue_number"], int) or isinstance(
        manifest["issue_number"], bool
    ) or manifest["issue_number"] <= 0:
        return False
    if manifest["run_id"] != expected_run_id:
        return False
    if manifest["issue_number"] != issue.get("number"):
        return False
    if not isinstance(manifest["base_sha"], str) or not COMMIT.fullmatch(
        manifest["base_sha"]
    ):
        return False
    if manifest["base_sha"] != expected_base_sha:
        return False
    if not isinstance(manifest["artifact_sha256"], str) or not SHA256.fullmatch(
        manifest["artifact_sha256"]
    ):
        return False
    if not isinstance(manifest["artifact_size"], int) or isinstance(
        manifest["artifact_size"], bool
    ):
        return False
    if not isinstance(artifact, bytes) or not 0 < len(artifact) <= MAX_ARTIFACT:
        return False
    return (
        manifest["artifact_size"] == len(artifact)
        and hashlib.sha256(artifact).hexdigest() == manifest["artifact_sha256"]
    )


def main() -> int:
    """Accept only explicit local files and print no artifact contents."""
    if len(sys.argv) != 4:
        print("DENIED: expected manifest, artifact and issue snapshot", file=sys.stderr)
        return 1
    try:
        manifest_path, artifact_path, issue_path = map(Path, sys.argv[1:])
        if manifest_path.stat().st_size > MAX_MANIFEST:
            raise ValueError("manifest too large")
        if artifact_path.stat().st_size > MAX_ARTIFACT:
            raise ValueError("artifact too large")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        issue = json.loads(issue_path.read_text(encoding="utf-8"))
        artifact = artifact_path.read_bytes()
        expected_run = os.environ["OPENCODE_EXPECTED_RUN_ID"]
        if not expected_run.isascii() or not expected_run.isdecimal():
            raise ValueError("invalid trusted run ID")
        expected_base = os.environ["OPENCODE_EXPECTED_BASE_SHA"]
        if not verify(manifest, artifact, issue, int(expected_run), expected_base):
            raise ValueError("artifact mismatch")
    except (OSError, ValueError, TypeError, UnicodeError):
        print("DENIED: artifact identity verification failed", file=sys.stderr)
        return 1
    print("ALLOWED: artifact identity matches manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
