#!/usr/bin/env python3
"""Verpackt ein Release-Binary reproduzierbar / packages a release binary reproducibly.

DE: Erzeugt `pqkeep-<version>-<ziel>.tar.gz` (Linux) bzw. `.zip` (Windows) mit Binary, LICENSE,
    NOTICE und README.md. Feste Reihenfolge, feste Zeitstempel (SOURCE_DATE_EPOCH), keine
    Benutzer-/Gruppennamen – gleiche Eingaben ergeben ein bitgleiches Archiv.
EN: Creates `pqkeep-<version>-<target>.tar.gz` (Linux) or `.zip` (Windows) with binary, LICENSE,
    NOTICE and README.md. Fixed order, fixed timestamps (SOURCE_DATE_EPOCH), no user/group
    names – equal inputs give a bit-identical archive.

Aufruf / usage:
    python3 scripts/release_package.py <binary> <version> <target> <out-dir> [--dry-run]
    --dry-run  DE: nur Archivname und Inhalt anzeigen / EN: only show archive name and content
"""

import gzip
import io
import os
import sys
import tarfile
import zipfile

EXTRA_FILES = ["LICENSE", "NOTICE", "README.md"]


def epoch() -> int:
    """DE/EN: SOURCE_DATE_EPOCH oder 0 / SOURCE_DATE_EPOCH or 0."""
    return int(os.environ.get("SOURCE_DATE_EPOCH", "0"))


def archive_name(version: str, target: str) -> str:
    """DE/EN: Dateiname des Archivs / archive file name."""
    ext = "zip" if "windows" in target else "tar.gz"
    return f"pqkeep-{version}-{target}.{ext}"


def members(binary: str, root: str) -> list:
    """DE/EN: (Name im Archiv, Pfad, Modus) in fester Reihenfolge / in fixed order."""
    name = os.path.basename(binary)
    items = [(name, binary, 0o755)]
    items += [(f, os.path.join(root, f), 0o644) for f in EXTRA_FILES]
    return sorted(items)


def write_tar_gz(path: str, prefix: str, items: list, mtime: int) -> None:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, src, mode in items:
            data = open(src, "rb").read()
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size, info.mtime, info.mode = len(data), mtime, mode
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    with open(path, "wb") as out:
        # DE: Kein Dateiname/Zeitstempel im gzip-Kopf. EN: No file name/timestamp in gzip header.
        with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=mtime, compresslevel=9) as gz:
            gz.write(raw.getvalue())


def write_zip(path: str, prefix: str, items: list, mtime: int) -> None:
    import time

    # DE: ZIP kennt nur Zeiten ab 1980. EN: ZIP only supports times from 1980.
    stamp = time.gmtime(max(mtime, 315532800))[:6]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, src, mode in items:
            info = zipfile.ZipInfo(f"{prefix}/{name}", date_time=stamp)
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, open(src, "rb").read())


def main(argv: list) -> int:
    dry = "--dry-run" in argv
    args = [a for a in argv if a != "--dry-run"]
    if len(args) != 4:
        print(__doc__)
        return 2
    binary, version, target, out_dir = args
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    name = archive_name(version, target)
    prefix = name.rsplit(".zip", 1)[0].rsplit(".tar.gz", 1)[0]
    items = members(binary, root)
    print(f"{name}: " + ", ".join(i[0] for i in items))
    if dry:
        return 0
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    writer = write_zip if name.endswith(".zip") else write_tar_gz
    writer(path, prefix, items, epoch())
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
