#!/usr/bin/env python3
"""Fehlerhafte Testpakete für die Lebenszyklus-Prüfung erzeugen; installiert nichts.

DE: Leitet aus einem geprüften Kandidaten gezielt unbrauchbare Pakete ab (abgeschnitten,
    verfälscht, unerfüllbare Abhängigkeit) und baut ein fremdes Paket, das `/usr/bin/pqkeep`
    besitzt. Alle Ergebnisse tragen Testnamen und entstehen nur in einem Arbeitsverzeichnis.
EN: Derives deliberately unusable packages from a checked candidate (truncated, corrupted,
    unsatisfiable dependency) and builds a foreign package owning `/usr/bin/pqkeep`. All results
    carry test names and are created in a work directory only.
"""

from pathlib import Path
import subprocess

MISSING = "pqkeep-test-missing-dependency"
CONFLICT = "pqkeep-test-conflict"
STUB = b"#!/bin/sh\nexit 97\n"


def field(package: Path, name: str) -> str:
    """Ein Steuerfeld lesen, ohne das Paket zu entpacken."""
    return subprocess.check_output(["dpkg-deb", "-f", str(package), name], text=True).strip()


def build(tree: Path, package: Path) -> Path:
    """Baum mit root:root verpacken; die Ausgabe darf noch nicht existieren."""
    if package.exists():
        raise FileExistsError(package)
    subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(tree), str(package)],
                   check=True, stdout=subprocess.DEVNULL)
    return package


def damaged(package: Path, work: Path) -> dict[str, Path]:
    """Abgeschnittene Kopie und Kopie mit einem verfälschten Byte im Datenteil."""
    data = package.read_bytes()
    position = len(data) * 3 // 4
    flipped = bytearray(data)
    flipped[position] ^= 0xFF
    result = {"abgeschnitten": work / "pqkeep-test-truncated.deb",
              "verfälscht": work / "pqkeep-test-corrupted.deb"}
    result["abgeschnitten"].write_bytes(data[:len(data) // 2])
    result["verfälscht"].write_bytes(bytes(flipped))
    return result


def missing_dependency(package: Path, work: Path) -> Path:
    """Gleicher Inhalt, aber zusätzlich eine Abhängigkeit, die kein Archiv erfüllen kann."""
    tree = work / "missing-dependency"
    subprocess.run(["dpkg-deb", "--raw-extract", str(package), str(tree)], check=True)
    control = tree / "DEBIAN/control"
    lines = control.read_text().splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith("Depends: "))
    lines[index] += f", {MISSING} (>= 1)"
    control.write_text("\n".join(lines) + "\n")
    return build(tree, work / "pqkeep-test-missing-dependency.deb")


def conflicting(work: Path) -> Path:
    """Fremdes Paket, dem `/usr/bin/pqkeep` bereits gehört."""
    tree = work / "conflict"
    binary = tree / "usr/bin/pqkeep"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(STUB)
    (tree / "DEBIAN").mkdir()
    (tree / "DEBIAN/control").write_text(
        f"Package: {CONFLICT}\nVersion: 1\nArchitecture: all\n"
        "Maintainer: PQKeep test fixture <fixture@pqkeep.invalid>\n"
        "Description: PQKeep lifecycle test fixture, never published\n")
    for path in (tree, *tree.rglob("*")):
        path.chmod(0o755 if path.is_dir() or path == binary else 0o644)
    return build(tree, work / "pqkeep-test-conflict.deb")
