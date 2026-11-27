#!/usr/bin/env python3
"""DE: Unabhängige PADMÉ-Referenz (Nikitin u. a. 2019) für Format v4 (#316, Testkatalog P06).
Gibt die Referenzwerte aus oder prüft mit --check, dass die Werte in
src/files/format_v4_tests.rs (PADME_VECTORS) dazu passen.
EN: Independent PADMÉ reference (Nikitin et al. 2019) for format v4 (#316, test catalogue P06).
Prints the reference values or, with --check, verifies the values in src/files/format_v4_tests.rs.

Aufruf / usage: python3 scripts/v4_padme_reference.py [--check]
"""
import math
import re
import sys
from pathlib import Path

LENGTHS = [24, 25, 31, 1000, 1024, 65_560, 1_000_000, 123_456_789, 2**40 + 1, 2**62 + 12345]


def padme(length: int) -> int:
    """DE/EN: PADMÉ nach der Formel aus dem Artikel / PADMÉ per the paper's formula."""
    if length < 2:
        return length
    e = math.floor(math.log2(length))
    if 2**e > length:  # DE/EN: Rundungsschutz / rounding guard
        e -= 1
    s = math.floor(math.log2(e)) + 1
    last_bits = e - s
    mask = (1 << last_bits) - 1
    return (length + mask) & ~mask


def vectors() -> list[tuple[int, int]]:
    return [(n, padme(n)) for n in LENGTHS]


def rust_vectors(path: Path) -> list[tuple[int, int]]:
    text = path.read_text(encoding="utf-8")
    block = re.search(r"PADME_VECTORS: &\[\(u64, u64\)\] = &\[(.*?)\];", text, re.S)
    if not block:
        raise SystemExit("PADME_VECTORS nicht gefunden / not found")
    pairs = re.findall(r"\(\s*([0-9_]+)\s*,\s*([0-9_]+)\s*\)", block.group(1))
    return [(int(a.replace("_", "")), int(b.replace("_", ""))) for a, b in pairs]


def main() -> int:
    if "--check" in sys.argv[1:]:
        root = Path(__file__).resolve().parents[1]
        found = rust_vectors(root / "src/files/format_v4_tests.rs")
        if found != vectors():
            print("FEHLER / ERROR: PADME_VECTORS weichen ab / differ")
            return 1
        print(f"OK: {len(found)} PADMÉ-Werte / values")
        return 0
    for n, p in vectors():
        print(f"({n:_}, {p:_}),")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
