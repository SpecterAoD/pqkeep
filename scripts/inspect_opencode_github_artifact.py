#!/usr/bin/env python3
"""Read-only end-to-end publisher review of a GitHub Actions ZIP.

Trusted issue/run/base/artifact IDs must be independently sourced. The GitHub
token is only used for read API calls and is never passed to patch execution.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from check_opencode_publisher_ready import check
from download_opencode_artifact import download
from github_opencode_publisher_preflight import github_get
from unpack_opencode_github_artifact import unpack
from verify_opencode_artifact_origin import verify_artifact_listing
from verify_opencode_run_provenance import verify_run


def inspect(
    repository: Path, issue_snapshot: Path, proposal: dict,
    issue: int, run: int, base: str, artifact_id: int, token: str,
    get=github_get, fetch=download, expected_comment_id=None,
) -> list[str]:
    """Bind remote run/artifact, download once, unpack and validate patch."""
    if type(expected_comment_id) is not int or expected_comment_id <= 0:
        raise ValueError("trusted comment identity missing")
    if not verify_run(run, base, token, get):
        raise ValueError("run provenance rejected")
    if not verify_artifact_listing(issue, run, base, artifact_id, token, get):
        raise ValueError("artifact provenance rejected")
    with tempfile.TemporaryDirectory(prefix="opencode-github-review-") as temp:
        root = Path(temp)
        outer = root / "github-artifact.zip"
        fetch(artifact_id, token, outer)
        payload_dir = root / "payload"
        payload_dir.mkdir(mode=0o700)
        manifest, inner = unpack(outer, payload_dir)
        return check(
            repository, manifest, inner, issue_snapshot, proposal,
            issue, run, base, token, artifact_id, get,
            expected_comment_id=expected_comment_id,
        )


def main() -> int:
    """CLI: trusted repository, issue snapshot, publication proposal."""
    if len(sys.argv) != 4:
        return 1
    try:
        from json import loads
        run = os.environ["OPENCODE_EXPECTED_RUN_ID"]
        issue = os.environ["OPENCODE_EXPECTED_ISSUE"]
        artifact = os.environ["OPENCODE_EXPECTED_ARTIFACT_ID"]
        comment = os.environ["OPENCODE_EXPECTED_COMMENT_ID"]
        if not all(value.isascii() and value.isdecimal() and
                   int(value) > 0 for value in (run, issue, artifact, comment)):
            raise ValueError("invalid trusted IDs")
        proposal_path = Path(sys.argv[3])
        if proposal_path.stat().st_size > 4096:
            raise ValueError("oversized proposal")
        proposal = loads(proposal_path.read_text(encoding="utf-8"))
        paths = inspect(
            Path(sys.argv[1]), Path(sys.argv[2]), proposal,
            int(issue), int(run), os.environ["OPENCODE_EXPECTED_BASE_SHA"],
            int(artifact), os.environ["GH_READ_TOKEN"],
            expected_comment_id=int(comment),
        )
    except (
        OSError, ValueError, TypeError, UnicodeError, KeyError,
        zipfile.BadZipFile, subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ):
        print("DENIED: end-to-end publisher review failed", file=sys.stderr)
        return 1
    print(f"PASS: {len(paths)} allowed files; no publication performed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
