#!/usr/bin/env python3
"""Offline publisher preflight: verify identity, then safely unpack inert patch.

This stage does not apply a patch, run project code, or publish anything.
The caller MUST supply expected run/base from a trusted source, not the ZIP.
"""
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path

from extract_opencode_artifact import extract
from verify_opencode_artifact import MAX_MANIFEST, verify


def preflight(
    manifest_path: Path, archive_path: Path, issue_path: Path,
    expected_run_id: int, expected_base_sha: str,
) -> int:
    """Verify archive identity before unpacking its single patch member."""
    if manifest_path.stat().st_size > MAX_MANIFEST:
        raise ValueError("manifest too large")
    if issue_path.stat().st_size > 16_384:
        raise ValueError("issue snapshot too large")
    if archive_path.stat().st_size > 120_000:
        raise ValueError("archive too large")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    issue = json.loads(issue_path.read_text(encoding="utf-8"))
    archive = archive_path.read_bytes()
    if not verify(manifest, archive, issue, expected_run_id, expected_base_sha):
        raise ValueError("untrusted artifact identity")
    with tempfile.TemporaryDirectory(prefix="opencode-preflight-") as directory:
        destination = Path(directory) / "proposal.patch"
        patch_size = extract(archive_path, destination)
        if patch_size == 0:
            raise ValueError("empty patch")
        # Deliberately never execute or apply the patch here.
        return patch_size


def main() -> int:
    """Fail closed unless independently supplied expected run/base are valid."""
    if len(sys.argv) != 4:
        return 1
    try:
        run = os.environ["OPENCODE_EXPECTED_RUN_ID"]
        base = os.environ["OPENCODE_EXPECTED_BASE_SHA"]
        if not run.isascii() or not run.isdecimal():
            raise ValueError("invalid run ID")
        size = preflight(
            Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]),
            int(run), base,
        )
    except (OSError, ValueError, TypeError, UnicodeError, zipfile.BadZipFile):
        print("DENIED: publisher preflight failed", file=sys.stderr)
        return 1
    print(f"PASS: verified artifact and extracted {size} inert patch bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
