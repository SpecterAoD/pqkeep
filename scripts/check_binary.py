#!/usr/bin/env python3
"""Prüft Härtungsmerkmale eines gebauten Binaries / checks hardening features of a built binary.

DE: Linux (ELF, über `readelf`): PIE, Full RELRO (GNU_RELRO + BIND_NOW), nicht ausführbarer Stack.
    Windows (PE, ohne Zusatzwerkzeuge): ASLR (DYNAMIC_BASE, HIGH_ENTROPY_VA), DEP (NX_COMPAT),
    Control Flow Guard (GUARD_CF). Exit 1, wenn ein Merkmal fehlt.
EN: Linux (ELF, via `readelf`): PIE, full RELRO (GNU_RELRO + BIND_NOW), non-executable stack.
    Windows (PE, no extra tools): ASLR (DYNAMIC_BASE, HIGH_ENTROPY_VA), DEP (NX_COMPAT),
    Control Flow Guard (GUARD_CF). Exit 1 if a feature is missing.

Aufruf / usage:  python3 scripts/check_binary.py <binary> [--dry-run]
    --dry-run  DE: nur Merkmale anzeigen, immer Exit 0 / EN: only show features, always exit 0
"""

import os
import struct
import subprocess
import sys

PE_FLAGS = {
    "HIGH_ENTROPY_VA (ASLR 64 bit)": 0x0020,
    "DYNAMIC_BASE (ASLR)": 0x0040,
    "NX_COMPAT (DEP)": 0x0100,
    "GUARD_CF (Control Flow Guard)": 0x4000,
}


def pe_features(data: bytes) -> dict:
    """DE/EN: DllCharacteristics aus dem PE-Optional-Header lesen / read from PE optional header."""
    if data[:2] != b"MZ":
        raise ValueError("kein PE / not a PE file")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("PE-Signatur fehlt / PE signature missing")
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("unbekannter Optional Header / unknown optional header")
    characteristics = struct.unpack_from("<H", data, optional + 70)[0]
    return {name: bool(characteristics & bit) for name, bit in PE_FLAGS.items()}


def elf_features(dynamic: str, headers: str, file_header: str) -> dict:
    """DE/EN: Merkmale aus `readelf -d`, `-lW` und `-h` / features from readelf output."""
    stack = [line for line in headers.splitlines() if "GNU_STACK" in line]
    return {
        "PIE": "DYN" in file_header and "PIE" in dynamic,
        "RELRO": "GNU_RELRO" in headers,
        "BIND_NOW (Full RELRO)": "BIND_NOW" in dynamic or " NOW" in dynamic,
        "NX stack": bool(stack) and "RWE" not in stack[0],
    }


def readelf(path: str, flag: str) -> str:
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run(["readelf", flag, path], capture_output=True, text=True,
                          check=True, env=env).stdout


def main(argv: list) -> int:
    args = [a for a in argv if a != "--dry-run"]
    dry_run = len(args) != len(argv)
    if len(args) != 1:
        print(__doc__)
        return 2
    path = args[0]
    with open(path, "rb") as f:
        head = f.read(4096)
    if head[:4] == b"\x7fELF":
        features = elf_features(readelf(path, "-d"), readelf(path, "-lW"), readelf(path, "-h"))
    else:
        features = pe_features(head)
    missing = [name for name, ok in features.items() if not ok]
    for name, ok in features.items():
        print(f"{'OK  ' if ok else 'FEHLT/MISSING'} {name}")
    if missing and not dry_run:
        print(f"FEHLER / ERROR: {path}: {', '.join(missing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
