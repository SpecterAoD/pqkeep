#!/usr/bin/env python3
"""Build a deterministic GitHub Actions artifact ZIP from inert proposal data.

No network, model execution, Git commands or publication. This is only a
transport format; publisher still verifies run provenance and patch policy.
"""
import io
import json
from pathlib import Path
import zipfile

from package_opencode_proposal import package
from unpack_opencode_github_artifact import MAX_OUTER, MEMBERS


def build_outer(patch: bytes, issue_number: int, run_id: int,
                base_sha: str) -> bytes:
    """Create exact two-member ZIP accepted by the outer artifact verifier."""
    inner, manifest = package(patch, issue_number, run_id, base_sha)
    payloads = {"manifest.json": manifest, "proposal.zip": inner}
    if any(not 0 < len(data) <= MEMBERS[name]
           for name, data in payloads.items()):
        raise ValueError("artifact member exceeds limit")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in payloads.items():
            entry = zipfile.ZipInfo(name)
            entry.compress_type = zipfile.ZIP_STORED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
    result = buffer.getvalue()
    if not 0 < len(result) <= MAX_OUTER:
        raise ValueError("outer archive exceeds limit")
    return result


def build_outer_from_file(patch_path: Path, issue: int, run: int,
                          base: str) -> bytes:
    """Refuse links and oversized patch inputs before reading bytes."""
    if patch_path.is_symlink() or not patch_path.is_file():
        raise ValueError("invalid patch file")
    if not 0 < patch_path.stat().st_size <= 100_000:
        raise ValueError("invalid patch size")
    return build_outer(patch_path.read_bytes(), issue, run, base)
