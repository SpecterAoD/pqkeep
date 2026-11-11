#!/usr/bin/env python3
"""Debian-Inhalt vor Installation prüfen, ohne Dateien aus dem Archiv zu extrahieren."""

import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

from release_elf import check_header


TARGETS = {"x86_64-unknown-linux-gnu": "amd64", "aarch64-unknown-linux-gnu": "arm64"}
DOC = "usr/share/doc/pqkeep/"
REQUIRED = {
    "usr/bin/pqkeep", "usr/share/man/man1/pqkeep.1.gz", "usr/share/man/de/man1/pqkeep.1.gz",
    "usr/share/bash-completion/completions/pqkeep", "usr/share/zsh/vendor-completions/_pqkeep",
    "usr/share/fish/vendor_completions.d/pqkeep.fish",
    *(DOC + name for name in ("LICENSE", "NOTICE", "README.md.gz", "LICENSES-wordlists.md",
                              "CC-BY-4.0", "copyright", "changelog.gz", "changelog.Debian.gz",
                              "license-inventory.json", "licenses.tar.gz", "rust-licenses/COPYRIGHT-library.html")),
}
DIRECTORIES = {str(p) for name in REQUIRED for p in PurePosixPath(name).parents}
DIRECTORIES |= {"", DOC + "rust-licenses/licenses"}


def check_licenses(data: dict[str, bytes], target: str) -> None:
    """Original-Lizenzdateien vollständig gegen das mitgelieferte Inventar prüfen."""
    inventory = json.loads(data[DOC + "license-inventory.json"])
    if inventory["target"] != target or not inventory["crates"]:
        raise ValueError("Lizenzinventar fehlt oder gehört zum falschen Ziel")
    expected = {}
    for crate in inventory["crates"]:
        for name, digest in crate["license_files"].items():
            path = f"cargo-licenses/{crate['name']}-{crate['version']}/{name}"
            if path in expected:
                raise ValueError("Doppelter Lizenzeintrag")
            expected[path] = digest
    found = {}
    with tarfile.open(fileobj=io.BytesIO(data[DOC + "licenses.tar.gz"]), mode="r:gz") as archive:
        for member in archive:
            if (not member.isfile() or member.name not in expected or member.name in found
                    or member.mode != 0o644 or member.uid != 0 or member.gid != 0):
                raise ValueError("Unerwarteter Eintrag im Original-Lizenzarchiv")
            found[member.name] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
    if found != expected:
        raise ValueError("Original-Lizenzdateien fehlen oder wurden verändert")
    rust_files = {DOC + "rust-licenses/" + n: digest for n, digest in inventory["rust_license_files"].items()}
    actual = {n: hashlib.sha256(b).hexdigest() for n, b in data.items() if n.startswith(DOC + "rust-licenses/")}
    if rust_files != actual:
        raise ValueError("Rust-Lizenzdateien fehlen oder wurden verändert")


def read_tar(data: bytes, control: bool = False) -> dict[str, bytes]:
    """Nur reguläre, eindeutige Dateien und Verzeichnisse mit sicheren Paketrechten."""
    files, seen = {}, set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            name = member.name.removeprefix("./").rstrip("/")
            if name in ("", ".") and member.isdir():
                name = ""
            elif (name.startswith("/") or ".." in PurePosixPath(name).parts
                  or str(PurePosixPath(name)) != name):
                raise ValueError("Unsicherer Paketpfad")
            if name in seen or not (member.isdir() or member.isfile()):
                raise ValueError("Doppelter Pfad, Link oder Sonderdatei im Paket")
            if member.pax_headers:
                raise ValueError("Zusätzliche Archivattribute sind nicht zulässig")
            if member.isdir() and name not in ({""} if control else DIRECTORIES):
                raise ValueError("Unerwartetes Paketverzeichnis")
            seen.add(name)
            mode = 0o755 if member.isdir() or (not control and name == "usr/bin/pqkeep") else 0o644
            if member.uid != 0 or member.gid != 0 or member.mode != mode:
                raise ValueError(f"Falsche Eigentümer oder Rechte: {name}")
            if member.isfile():
                files[name] = archive.extractfile(member).read()
    return files


def check_package(package: Path, arch: str, binary_sha256: str | None = None) -> dict[str, bytes]:
    """Keine Maintainerskripte/Conffiles; Inhalt, ELF-Ziel und alle MD5-Einträge prüfen."""
    controls = read_tar(subprocess.check_output(["dpkg-deb", "--ctrl-tarfile", str(package)]), True)
    if set(controls) != {"control", "md5sums"}:
        raise ValueError("Unerwartete Steuerdateien oder Maintainerskripte")
    fields = dict(line.split(": ", 1) for line in controls["control"].decode().splitlines()
                  if line and not line.startswith(" ") and ": " in line)
    if fields.get("Package") != "pqkeep" or fields.get("Architecture") != arch:
        raise ValueError("Paketname oder Architektur falsch")
    data = read_tar(subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)]))
    extras = set(data) - REQUIRED
    if not REQUIRED <= set(data) or any(str(PurePosixPath(n).parent) != DOC + "rust-licenses/licenses"
                                        or not n.endswith(".txt") for n in extras):
        raise ValueError("Fehlende oder unerwartete Paketdateien")
    sums = controls["md5sums"].decode().splitlines()
    expected = [hashlib.md5(data[n], usedforsecurity=False).hexdigest() + "  " + n for n in sorted(data)]
    if sums != expected:
        raise ValueError("Dateiprüfsummen fehlen oder weichen ab")
    target = next(target for target, deb_arch in TARGETS.items() if deb_arch == arch)
    check_header(data["usr/bin/pqkeep"][:64], target)
    check_licenses(data, target)
    digest = hashlib.sha256(data["usr/bin/pqkeep"]).hexdigest()
    if binary_sha256 is not None and digest != binary_sha256:
        raise ValueError("Binary im Debian-Paket wurde verändert")
    print(f"Paket geprüft: {arch}, {len(data)} Dateien, Binary-SHA-256={digest}")
    return data
