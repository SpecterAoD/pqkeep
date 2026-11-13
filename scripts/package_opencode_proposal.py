#!/usr/bin/env python3
"""Package inert model output for the existing read-only publisher preflight.

This is NOT an agent runner. No model credentials, GitHub token or Git commands.
The trusted publisher must independently validate the patch and event identity.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import zipfile

from validate_opencode_patch_headers import validate_headers
from verify_opencode_artifact import COMMIT, MAX_ARTIFACT


def package(patch: bytes, issue_number: int, run_id: int,
            base_sha: str) -> tuple[bytes, bytes]:
    """Produce deterministic single-member ZIP and its integrity manifest."""
    if type(issue_number) is not int or issue_number <= 0:
        raise ValueError("invalid issue")
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("invalid run")
    if not isinstance(base_sha, str) or not COMMIT.fullmatch(base_sha):
        raise ValueError("invalid base")
    validate_headers(patch)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        member = zipfile.ZipInfo("proposal.patch")
        member.compress_type = zipfile.ZIP_STORED
        member.external_attr = 0o100644 << 16
        archive.writestr(member, patch)
    data = buffer.getvalue()
    if not 0 < len(data) <= MAX_ARTIFACT:
        raise ValueError("archive exceeds policy")
    manifest = {
        "repository": "SpecterAoD/pqkeep",
        "run_id": run_id,
        "issue_number": issue_number,
        "base_sha": base_sha,
        "artifact_sha256": hashlib.sha256(data).hexdigest(),
        "artifact_size": len(data),
    }
    encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":"))
               + "\n").encode("utf-8")
    return data, encoded


def main() -> int:
    """CLI: patch issue run base output-zip output-manifest."""
    if len(sys.argv) != 7:
        return 1
    try:
        patch = Path(sys.argv[1])
        if patch.is_symlink() or not 0 < patch.stat().st_size <= 100_000:
            raise ValueError("invalid patch")
        issue, run = sys.argv[2:4]
        if not all(x.isascii() and x.isdecimal() for x in (issue, run)):
            raise ValueError("invalid identifiers")
        archive, manifest = package(
            patch.read_bytes(), int(issue), int(run), sys.argv[4],
        )
        destinations = (Path(sys.argv[5]), Path(sys.argv[6]))
        if destinations[0] == destinations[1]:
            raise ValueError("duplicate destinations")
        if any(path.exists() or path.is_symlink() for path in destinations):
            raise ValueError("destination already exists")
        created = []
        try:
            for destination, data in zip(destinations, (archive, manifest)):
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(destination, flags, 0o600)
                created.append(destination)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
        except BaseException:
            for destination in created:
                destination.unlink(missing_ok=True)
            raise
    except (OSError, ValueError, TypeError, UnicodeError):
        print("DENIED: proposal packaging failed", file=sys.stderr)
        return 1
    print("PASS: inert proposal artifact created (no publication)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
