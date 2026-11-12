#!/usr/bin/env python3
"""Safely unpack GitHub's outer artifact ZIP into two inert data files.

Expected archive: manifest.json and proposal.zip. No paths are taken from
archive members. The inner ZIP is subsequently checked by existing gates.
"""
import os
from pathlib import Path
import stat
import sys
import zipfile

MAX_OUTER = 120_000
MEMBERS = {"manifest.json": 4_096, "proposal.zip": 100_000}


def unpack(outer: Path, destination: Path) -> tuple[Path, Path]:
    """Reject duplicate, unexpected, encrypted and oversized entries."""
    if outer.is_symlink() or not outer.is_file():
        raise ValueError("invalid outer artifact")
    if not 0 < outer.stat().st_size <= MAX_OUTER:
        raise ValueError("outer artifact size rejected")
    if destination.is_symlink() or not destination.is_dir():
        raise ValueError("invalid output directory")
    if any((destination / name).exists() or
           (destination / name).is_symlink() for name in MEMBERS):
        raise ValueError("output already exists")
    payloads = {}
    with zipfile.ZipFile(outer) as archive:
        entries = archive.infolist()
        if len(entries) != len(MEMBERS):
            raise ValueError("unexpected member count")
        for entry in entries:
            if entry.filename not in MEMBERS or entry.filename in payloads:
                raise ValueError("unexpected or duplicate member")
            limit = MEMBERS[entry.filename]
            mode = (entry.external_attr >> 16) & 0xFFFF
            if (entry.is_dir() or entry.flag_bits & 1 or
                    stat.S_IFMT(mode) not in (0, stat.S_IFREG) or
                    entry.compress_type not in (
                        zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED
                    ) or not 0 < entry.file_size <= limit or
                    entry.compress_size <= 0 or
                    entry.file_size > entry.compress_size * 100):
                raise ValueError("unsafe member")
            with archive.open(entry) as stream:
                data = stream.read(limit + 1)
                if len(data) != entry.file_size or stream.read(1):
                    raise ValueError("member size mismatch")
                payloads[entry.filename] = data
    created = []
    try:
        for name, data in payloads.items():
            path = destination / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "wb") as output:
                output.write(data)
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return destination / "manifest.json", destination / "proposal.zip"


def main() -> int:
    if len(sys.argv) != 3:
        return 1
    try:
        unpack(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile):
        print("DENIED: outer GitHub artifact ZIP rejected", file=sys.stderr)
        return 1
    print("PASS: outer artifact unpacked as inert data")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
