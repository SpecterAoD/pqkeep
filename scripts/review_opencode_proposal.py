#!/usr/bin/env python3
"""Complete read-only validation of an AI patch artifact.

The caller supplies expected run/base from an independent trusted context.
This script does not create a PR, push a branch, or run repository code.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import zipfile

from extract_opencode_artifact import extract
from publisher_opencode_preflight import preflight
from review_opencode_patch import review_patch


def review(
    repository: Path, manifest: Path, archive: Path, issue: Path,
    expected_run: int, expected_base: str,
) -> list[str]:
    """Verify artifact first, then apply and validate only in a temp worktree."""
    preflight(manifest, archive, issue, expected_run, expected_base)
    with tempfile.TemporaryDirectory(prefix="opencode-review-") as directory:
        patch_path = Path(directory) / "proposal.patch"
        extract(archive, patch_path)
        return review_patch(repository, patch_path, expected_base)


def main() -> int:
    """CLI: repository, manifest, ZIP artifact, issue snapshot."""
    if len(sys.argv) != 5:
        return 1
    try:
        run = os.environ["OPENCODE_EXPECTED_RUN_ID"]
        base = os.environ["OPENCODE_EXPECTED_BASE_SHA"]
        if not run.isascii() or not run.isdecimal():
            raise ValueError("invalid trusted run")
        paths = review(
            Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]),
            Path(sys.argv[4]), int(run), base,
        )
    except (
        OSError, ValueError, TypeError, UnicodeError, zipfile.BadZipFile,
    ):
        print("DENIED: AI proposal rejected", file=sys.stderr)
        return 1
    except Exception as exc:
        # Git failures must also fail closed, without leaking patch contents.
        import subprocess
        if isinstance(exc, (subprocess.CalledProcessError,
                            subprocess.TimeoutExpired)):
            print("DENIED: Git patch verification failed", file=sys.stderr)
            return 1
        raise
    print(f"PASS: {len(paths)} documentation paths validated; no publication")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
