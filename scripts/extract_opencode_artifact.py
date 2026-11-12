#!/usr/bin/env python3
"""Extract a single untrusted patch file from a bounded ZIP artifact.

Never extract arbitrary paths. The result is data only and must still pass
the trusted Git patch validator before any publication.
"""
import os
import stat
import sys
import zipfile
from pathlib import Path

MAX_ZIP_BYTES = 120_000
MAX_PATCH_BYTES = 100_000
EXPECTED_NAME = "proposal.patch"


def extract(archive: Path, destination: Path) -> int:
    """Reject archive tricks, symlinks, duplicates, and compression bombs."""
    if archive.is_symlink() or destination.is_symlink():
        raise ValueError("symlink path")
    if archive.stat().st_size > MAX_ZIP_BYTES:
        raise ValueError("archive too large")
    if destination.exists():
        raise ValueError("destination already exists")
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) != 1:
            raise ValueError("exactly one artifact member required")
        info = infos[0]
        if info.filename != EXPECTED_NAME or info.is_dir():
            raise ValueError("unexpected artifact member")
        if info.flag_bits & 0x1:
            raise ValueError("encrypted archive")
        if info.file_size == 0 or info.file_size > MAX_PATCH_BYTES:
            raise ValueError("patch size outside policy")
        if info.compress_size == 0:
            raise ValueError("invalid compressed size")
        if info.file_size > info.compress_size * 100:
            raise ValueError("suspicious compression ratio")
        mode = (info.external_attr >> 16) & 0xFFFF
        if mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG):
            raise ValueError("non-regular archive member")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise ValueError("unsupported compression")
        with zf.open(info) as member:
            data = member.read(MAX_PATCH_BYTES + 1)
            if len(data) != info.file_size or member.read(1):
                raise ValueError("artifact size mismatch")
    # Exclusive creation prevents accidental overwrites.
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return len(data)


def main() -> int:
    """CLI wrapper with no extraction of user-controlled paths."""
    if len(sys.argv) != 3:
        return 1
    try:
        count = extract(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile):
        print("DENIED: untrusted artifact archive", file=sys.stderr)
        return 1
    print(f"ALLOWED: extracted {count} patch bytes as inert data")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
