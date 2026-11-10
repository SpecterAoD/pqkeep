#!/usr/bin/env python3
"""Prüft GNU/Linux-Release-Ziel, glibc-Basis und optional die Archividentität.

Ergänzt check_binary.py; ersetzt oder lockert dessen Härtungsprüfung nicht.
--native verlangt einen Linux-Host derselben ISA. Das ersetzt keinen Smoke-Test.
--archive vergleicht das verpackte Programm ohne Extraktion mit dem geprüften Binary.
"""

import argparse
import hashlib
from pathlib import Path
import platform
import re
import struct
import subprocess
import tarfile

from check_binary import readelf


TARGETS = {
    "x86_64-unknown-linux-gnu": (62, "x86_64", "/lib64/ld-linux-x86-64.so.2"),
    "aarch64-unknown-linux-gnu": (183, "aarch64", "/lib/ld-linux-aarch64.so.1"),
}
GLIBC_MAX = (2, 35, 0)


def check_header(data: bytes, target: str) -> None:
    """ELF64, Little Endian, PIE-Typ und numerische Maschinenkennung prüfen."""
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("ELF64 Little Endian erwartet")
    kind, machine = struct.unpack_from("<HH", data, 16)
    if kind != 3 or machine != TARGETS[target][0]:
        raise ValueError(f"ELF-Typ/Maschine passt nicht zu {target}")


def check_abi(headers: str, versions: str, target: str) -> str:
    """Passenden GNU-Loader und ausschließlich glibc-Symbolversionen bis 2.35 zulassen."""
    loaders = re.findall(r"Requesting program interpreter:\s*([^\]]+)\]", headers)
    if loaders != [TARGETS[target][2]]:
        raise ValueError("GNU-Loader fehlt oder passt nicht zum Ziel")
    names = set(re.findall(r"\bName:\s+(GLIBC_\S+)", versions))
    if not names:
        raise ValueError("Keine glibc-Symbolanforderungen gefunden")
    parsed = []
    for name in names:
        if not re.fullmatch(r"GLIBC_\d+\.\d+(?:\.\d+)?", name):
            raise ValueError(f"Nicht unterstützte glibc-Anforderung: {name}")
        parts = tuple(int(x) for x in name.removeprefix("GLIBC_").split("."))
        version = parts + (0,) * (3 - len(parts))
        if version > GLIBC_MAX:
            raise ValueError(f"{name} überschreitet die Release-Basis glibc 2.35")
        parsed.append((version, name))
    return max(parsed)[1]


def check_native(target: str) -> None:
    """Linux und passende Host-ISA verlangen; Emulation allein damit nicht ausschließen."""
    if platform.system() != "Linux" or platform.machine() != TARGETS[target][1]:
        raise ValueError(f"Kein nativer Linux-Host für {target}")


def check_archive(binary: Path, archive: Path) -> str:
    """Reguläres Einzel-Binary im erwarteten Archivpfad bytegenau vergleichen."""
    expected = f"{archive.name.removesuffix('.tar.gz')}/pqkeep"
    with tarfile.open(archive, "r:gz") as tar:
        matches = [m for m in tar.getmembers() if m.name == expected]
        if len(matches) != 1 or not matches[0].isfile():
            raise ValueError("Archiv-Binary fehlt, ist doppelt oder keine reguläre Datei")
        with tar.extractfile(matches[0]) as source:
            packaged = source.read()
    original = binary.read_bytes()
    if packaged != original:
        raise ValueError("Archiv-Binary weicht vom geprüften Binary ab")
    return hashlib.sha256(original).hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("target", choices=TARGETS)
    parser.add_argument("--native", action="store_true")
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args(argv)
    try:
        with args.binary.open("rb") as source:
            check_header(source.read(64), args.target)
        abi = check_abi(readelf(str(args.binary), "-lW"),
                        readelf(str(args.binary), "--version-info"), args.target)
        if args.native:
            check_native(args.target)
        digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
        if args.archive:
            digest = check_archive(args.binary, args.archive)
        print(f"OK: {args.target}, {abi}, SHA-256={digest}, native={args.native}")
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as err:
        print(f"FEHLER: {err}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
