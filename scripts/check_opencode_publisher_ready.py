#!/usr/bin/env python3
"""Single read-only publisher readiness check.

Checks GitHub state and independently anchored artifact/worktree validation.
Does not push branches, create PRs, execute project code or expose secrets.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

from github_opencode_publisher_preflight import preflight as github_preflight
from review_opencode_proposal import review as review_proposal
from verify_opencode_run_provenance import verify_run


def check(
    repository: Path, manifest: Path, archive: Path, issue_snapshot: Path,
    proposal: dict, issue_number: int, run_id: int, base_sha: str,
    read_token: str, github_get=None, verify_provenance=None,
) -> list[str]:
    """Fail closed unless both GitHub state and patch checks pass."""
    if not isinstance(issue_number, int) or isinstance(issue_number, bool):
        raise ValueError("invalid issue number")
    if github_get is None:
        from github_opencode_publisher_preflight import github_get
    if not github_preflight(
        proposal, issue_number, run_id, base_sha, read_token, github_get
    ):
        raise ValueError("GitHub publication state denied")
    if verify_provenance is None:
        verify_provenance = verify_run
    if not verify_provenance(run_id, base_sha, read_token, github_get):
        raise ValueError("GitHub Actions run provenance denied")
    return review_proposal(
        repository, manifest, archive, issue_snapshot, run_id, base_sha
    )


def main() -> int:
    """CLI: repo manifest artifact issue-snapshot publication-proposal."""
    if len(sys.argv) != 6:
        return 1
    try:
        run_text = os.environ["OPENCODE_EXPECTED_RUN_ID"]
        issue_text = os.environ["OPENCODE_EXPECTED_ISSUE"]
        base = os.environ["OPENCODE_EXPECTED_BASE_SHA"]
        token = os.environ["GH_READ_TOKEN"]
        if not all(
            value.isascii() and value.isdecimal()
            for value in (run_text, issue_text)
        ):
            raise ValueError("invalid trusted identifiers")
        proposal_path = Path(sys.argv[5])
        if proposal_path.stat().st_size > 4096:
            raise ValueError("proposal too large")
        proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
        paths = check(
            Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]),
            Path(sys.argv[4]), proposal, int(issue_text), int(run_text),
            base, token,
        )
    except (
        OSError, ValueError, TypeError, UnicodeError, zipfile.BadZipFile,
        subprocess.CalledProcessError, subprocess.TimeoutExpired,
    ):
        print("DENIED: read-only publisher readiness check failed", file=sys.stderr)
        return 1
    print(f"PASS: {len(paths)} files verified; no write operations performed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
