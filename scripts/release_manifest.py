#!/usr/bin/env python3
"""Artefaktmanifest des Releases prüfen / check the release artifact manifest.

DE: Das Manifest ist fest im Skript hinterlegt: fünf Nutzartefakte (Linux-Archiv AMD64 und
    ARM64, Windows-ZIP, Debian-Paket amd64 und arm64) und je eine CycloneDX-SBOM. Fehlende,
    zusätzliche, doppelte oder falsch zugeordnete Dateien führen zum Abbruch.
EN: The manifest is fixed in this script: five user artifacts (Linux archive AMD64 and ARM64,
    Windows ZIP, Debian package amd64 and arm64) and one CycloneDX SBOM each. Missing,
    additional, duplicate or wrongly assigned files abort the run.

Aufruf / usage:
    python3 scripts/release_manifest.py collect <downloads> <dist> <version> <commit>
        DE: Build-Artefakte (ein Ordner je Ziel) prüfen und nach <dist> übernehmen.
        EN: check the build artifacts (one directory per target) and copy them to <dist>.
    python3 scripts/release_manifest.py verify <dist> <version>
        DE: fertiges Bündel mit SHA256SUMS und Sigstore-Bundles prüfen.
        EN: check the finished bundle with SHA256SUMS and Sigstore bundles.
"""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import release_sbom
from release_deb_check import TARGETS, check_package

WINDOWS = "x86_64-pc-windows-msvc"
SUMS = "SHA256SUMS"


def manifest(version: str) -> dict[str, dict[str, str]]:
    """Je Build-Artefakt: Dateiname → Art (`archive`, `deb`, `sbom`, `deb-sbom`)."""
    base = f"pqkeep-{version}-"
    result = {"dist-" + WINDOWS: {f"{base}{WINDOWS}.zip": "archive",
                                  f"{base}{WINDOWS}.cdx.json": "sbom"}}
    for target, arch in TARGETS.items():
        result["dist-" + target] = {
            f"{base}{target}.tar.gz": "archive", f"{base}{target}.cdx.json": "sbom",
            f"{base}{arch}.deb": "deb", f"{base}{arch}.deb.cdx.json": "deb-sbom"}
    return result


def names(version: str, kinds: tuple[str, ...]) -> set[str]:
    return {n for files in manifest(version).values() for n, kind in files.items() if kind in kinds}


def listing(directory: Path, expected: set[str], what: str) -> None:
    """Genau die erwarteten Einträge; keine Links, Sonderdateien oder leeren Dateien."""
    found = {p.name for p in directory.iterdir()}
    if found != expected:
        raise ValueError(f"{what}: fehlend {sorted(expected - found)}, zusätzlich {sorted(found - expected)}")
    for path in directory.iterdir():
        if path.is_symlink():
            raise ValueError(f"{what}: Link nicht zulässig: {path.name}")


def regular(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"Reguläre, nicht leere Datei erwartet: {path.name}")
    return path.read_bytes()


def deb_identity(package: Path, arch: str, binary_sha256: str) -> str:
    """Paketinhalt und -architektur prüfen; liefert die Debian-Version."""
    check_package(package, arch, binary_sha256)
    return subprocess.check_output(["dpkg-deb", "-f", str(package), "Version"], text=True).strip()


def archive_binary(path: Path, version: str, target: str) -> str:
    """SHA-256 des Programms im Linux-Archiv."""
    with tarfile.open(path, mode="r:gz") as archive:
        member = archive.extractfile(f"pqkeep-{version}-{target}/pqkeep")
        if member is None:
            raise ValueError(f"Programm fehlt im Archiv: {path.name}")
        return hashlib.sha256(member.read()).hexdigest()


def check_target(directory: Path, version: str, target: str, commit: str) -> None:
    """Zuordnung: SBOM ↔ Ziel und Commit, Paket ↔ Architektur und Programm des Archivs."""
    base = f"pqkeep-{version}-"
    sbom = json.loads(regular(directory / f"{base}{target}.cdx.json"))
    if sbom.get("serialNumber") != release_sbom.serial(version, target, commit):
        raise ValueError(f"SBOM gehört nicht zu {target} und diesem Commit")
    arch = TARGETS.get(target)
    if arch is None:
        return
    binary = archive_binary(directory / f"{base}{target}.tar.gz", version, target)
    deb_version = deb_identity(directory / f"{base}{arch}.deb", arch, binary)
    deb_sbom = json.loads(regular(directory / f"{base}{arch}.deb.cdx.json"))
    properties = [p for p in deb_sbom.get("metadata", {}).get("properties", [])
                  if p.get("name", "").startswith(release_sbom.DEB_PREFIX)]
    if (deb_sbom.get("serialNumber") != release_sbom.deb_serial(deb_version, arch, commit)
            or properties != release_sbom.deb_properties(deb_version, arch, binary)):
        raise ValueError(f"Paket-SBOM gehört nicht zum Debian-Paket {arch}")


def collect(downloads: Path, dist: Path, version: str, commit: str) -> None:
    """Jedes Build-Artefakt einzeln prüfen, erst danach gemeinsam bereitstellen."""
    expected = manifest(version)
    listing(downloads, set(expected), "Build-Artefakte")
    digests = {}
    for name, files in expected.items():
        if (downloads / name).is_symlink() or not (downloads / name).is_dir():
            raise ValueError(f"Ordner erwartet: {name}")
        listing(downloads / name, set(files), name)
        for file in files:
            digests.setdefault(hashlib.sha256(regular(downloads / name / file)).hexdigest(), []).append(file)
        check_target(downloads / name, version, name.removeprefix("dist-"), commit)
    doubles = [sorted(files) for files in digests.values() if len(files) > 1]
    if doubles:
        raise ValueError(f"Doppelter Inhalt: {doubles}")
    dist.mkdir(parents=True)
    for name, files in expected.items():
        for file in files:
            shutil.copyfile(downloads / name / file, dist / file)
    print(f"Manifest erfüllt / manifest satisfied: {sum(map(len, expected.values()))} Dateien / files")


def verify(dist: Path, version: str) -> None:
    """Fertiges Bündel: genau Manifest, SHA256SUMS und je ein Sigstore-Bundle."""
    artifacts, listed = names(version, ("archive", "deb")), names(version, ("archive", "deb", "sbom", "deb-sbom"))
    bundles = {n + ".sigstore.json" for n in artifacts | {SUMS}}
    listing(dist, listed | bundles | {SUMS}, "Release-Bündel")
    lines = regular(dist / SUMS).decode().splitlines()
    sums = dict(reversed(line.split("  ", 1)) for line in lines if "  " in line)
    if len(sums) != len(lines) or set(sums) != listed:
        raise ValueError("SHA256SUMS deckt nicht genau das Manifest ab")
    for name in sorted(listed | bundles):
        data = regular(dist / name)
        if name in sums and hashlib.sha256(data).hexdigest() != sums[name]:
            raise ValueError(f"Prüfsumme weicht ab: {name}")
    if len(set(sums.values())) != len(sums):
        raise ValueError("Doppelter Inhalt im Release-Bündel")
    print(f"Release-Bündel vollständig / release bundle complete: {len(listed | bundles) + 1} Dateien / files")


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 5 and argv[0] == "collect":
            collect(Path(argv[1]), Path(argv[2]), argv[3], argv[4])
        elif len(argv) == 3 and argv[0] == "verify":
            verify(Path(argv[1]), argv[2])
        else:
            print(__doc__)
            return 2
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"FEHLER / ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
