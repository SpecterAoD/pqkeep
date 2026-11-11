#!/usr/bin/env python3
"""Debian-CI-Kandidat aus einem nativ geprüften GNU-Release-Binary erzeugen.

Keine Installation, Maintainerskripte oder Änderungen an Nutzerdateien.
Gemeinsame Paketlogik für amd64 und arm64; jede Architektur wird nativ gebaut und geprüft.
"""

import argparse
from datetime import datetime, timezone
from email.utils import format_datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import check_binary
import release_elf
from release_deb_check import TARGETS, check_package
from release_deb_licenses import write_licenses
from release_package import EXTRA_FILES, epoch


DOC = "usr/share/doc/pqkeep"


def regular(path: Path) -> Path:
    """Keine Symlinks, Sonderdateien oder fremd beschreibbaren Eingaben übernehmen."""
    path = path.absolute()
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
        raise ValueError(f"Reguläre Datei ohne Symlink erwartet: {path}")
    if path.stat().st_mode & 0o022:
        raise ValueError(f"Unsichere Schreibrechte: {path}")
    return path


def deb_version(upstream: str, revision: str, stamp: int, sha: str) -> str:
    """SemVer-Prerelease vor finaler Version; CI vor der eigentlichen Paketrevision."""
    pattern = r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?"
    match = re.fullmatch(pattern, upstream)
    if not match or not re.fullmatch(r"[1-9]\d*", revision):
        raise ValueError("Ungültige Upstream-Version oder Paketrevision")
    pre = match[4]
    if pre and any(not part or (part.isdigit() and len(part) > 1 and part[0] == "0")
                   for part in pre.split(".")):
        raise ValueError("Ungültige Prerelease-Kennung")
    if not re.fullmatch(r"[0-9a-f]{7,40}", sha) or not 0 <= stamp <= 4102444800:
        raise ValueError("Ungültiger Commit oder SOURCE_DATE_EPOCH")
    date = datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y%m%d%H%M%S")
    version = upstream.replace("-", "~", 1) if pre else upstream
    return f"{version}-{revision}~ci.{date}.{sha[:12]}"


def put(stage: Path, name: str, data: bytes, mode: int = 0o644) -> None:
    """Nur intern festgelegte Paketpfade beschreiben."""
    path = stage / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def docs(stage: Path, root: Path, binary: Path, version: str,
         metadata: dict, stamp: int) -> None:
    """Vorhandene Texte und CLI-Generatoren wiederverwenden, gzip ohne Zeitstempel."""
    for name, source in EXTRA_FILES:
        data = regular(root / source).read_bytes()
        if name == "README.md":
            name, data = name + ".gz", gzip.compress(data, compresslevel=9, mtime=0)
        put(stage, f"{DOC}/{name}", data)
    for lang, directory in (("en", "man1"), ("de", "de/man1")):
        data = subprocess.check_output([str(binary), "--lang", lang, "man"])
        if b".TH" not in data:
            raise ValueError("Manpage fehlt")
        put(stage, f"usr/share/man/{directory}/pqkeep.1.gz", gzip.compress(data, mtime=0))
    completions = {"bash": "bash-completion/completions/pqkeep",
                   "zsh": "zsh/vendor-completions/_pqkeep",
                   "fish": "fish/vendor_completions.d/pqkeep.fish"}
    for shell, path in completions.items():
        data = subprocess.check_output([str(binary), "--lang", "en", "completions", shell])
        if b"pqkeep" not in data:
            raise ValueError("Completion fehlt")
        put(stage, "usr/share/" + path, data)
    notes = regular(root / "CHANGELOG.md").read_bytes()
    put(stage, f"{DOC}/changelog.gz", gzip.compress(notes, mtime=0))
    date = format_datetime(datetime.fromtimestamp(stamp, timezone.utc))
    changes = (f"pqkeep ({version}) UNRELEASED; urgency=medium\n\n"
               "  * Debian-CI-Kandidat / Debian CI candidate; native GNU binary.\n\n"
               f" -- {metadata['maintainer']}  {date}\n")
    put(stage, f"{DOC}/changelog.Debian.gz", gzip.compress(changes.encode(), mtime=0))
    put(stage, f"{DOC}/CC-BY-4.0", regular(root / "packaging/debian/CC-BY-4.0").read_bytes())


def dependencies(stage: Path, work: Path) -> str:
    """Symbolabhängigkeiten mit der nativen dpkg-Datenbank bestimmen; Fehler sind fatal."""
    (work / "debian").mkdir(exist_ok=True)
    (stage / "DEBIAN").mkdir(exist_ok=True)
    (work / "debian/control").write_text("Source: pqkeep\n\nPackage: pqkeep\nArchitecture: any\n")
    result = subprocess.check_output(
        ["dpkg-shlibdeps", "-O", "-e" + str(stage / "usr/bin/pqkeep")], cwd=work, text=True)
    if not result.startswith("shlibs:Depends=") or len(result.splitlines()) != 1:
        raise ValueError("Unerwartete dpkg-shlibdeps-Ausgabe")
    depends = result.strip().removeprefix("shlibs:Depends=")
    parts = depends.split(", ")
    if not any(p.startswith("libc6 (") for p in parts) or not all(
        re.fullmatch(r"[a-z0-9][a-z0-9+.-]+(?: \(>= [0-9][A-Za-z0-9.+:~\-]*\))?", p)
        for p in parts
    ):
        raise ValueError("Ungültige oder unvollständige Paketabhängigkeiten")
    return depends


def control(stage: Path, arch: str, version: str, depends: str, metadata: dict) -> None:
    """Metadaten und Dateiprüfsummen; keine Installationsskripte oder Conffiles."""
    files = sorted(p for p in stage.rglob("*") if p.is_file())
    size = sum((p.stat().st_size + 1023) // 1024 for p in files)
    text = (f"Package: pqkeep\nVersion: {version}\nArchitecture: {arch}\n"
            f"Maintainer: {metadata['maintainer']}\nSection: utils\nPriority: optional\n"
            f"Homepage: {metadata['homepage']}\nInstalled-Size: {size}\n"
            f"Depends: {depends}\nDescription: {metadata['description']}\n")
    put(stage, "DEBIAN/control", text.encode())
    sums = "".join(hashlib.md5(p.read_bytes(), usedforsecurity=False).hexdigest()
                   + "  " + p.relative_to(stage).as_posix() + "\n" for p in files)
    put(stage, "DEBIAN/md5sums", sums.encode())


def normalize(stage: Path, stamp: int) -> None:
    """Einheitliche Rechte und Zeiten; keine Set-ID-Bits oder symbolischen Links."""
    for path in [stage, *stage.rglob("*")]:
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("Unerwarteter Eintrag im Paketbaum")
        path.chmod(0o755 if path.is_dir() or path == stage / "usr/bin/pqkeep" else 0o644)
        os.utime(path, (stamp, stamp))


def build(binary: Path, target: str, out: Path, sha: str, root: Path) -> Path:
    """Isoliert bauen und erst nach Erfolg atomar ohne Überschreiben bereitstellen."""
    if os.geteuid() == 0:
        raise ValueError("Paketbau muss ohne Root-Rechte erfolgen")
    binary = regular(binary)
    release_elf.check_native(target)
    if release_elf.main([str(binary), target, "--native"]) or check_binary.main([str(binary)]):
        raise ValueError("Binary-Ziel, ABI oder Härtung fehlerhaft")
    arch = TARGETS[target]
    if subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip() != arch:
        raise ValueError("dpkg-Architektur passt nicht zum Binary")
    metadata = json.loads(regular(root / "packaging/debian/metadata.json").read_text())
    if not re.fullmatch(r"[^<>\r\n]+ <[^<>\s]+@[^<>\s]+>", metadata["maintainer"]):
        raise ValueError("Ungültiger Maintainer-Kontakt")
    upstream = re.search(r'^version = "([^"]+)"$', (root / "Cargo.toml").read_text(), re.M)[1]
    stamp = epoch()
    if "SOURCE_DATE_EPOCH" not in os.environ:
        raise ValueError("SOURCE_DATE_EPOCH muss ausdrücklich gesetzt sein")
    version = deb_version(upstream, metadata["revision"], stamp, sha)
    if subprocess.check_output([str(binary), "--version"], text=True).strip() != "pqkeep " + upstream:
        raise ValueError("Binary-Version passt nicht zu Cargo.toml")
    if any(p.is_symlink() for p in (out.absolute(), *out.absolute().parents)):
        raise ValueError("Ausgabepfad enthält einen Symlink")
    out.mkdir(parents=True, exist_ok=True)
    destination = out.absolute() / f"pqkeep_{version}_{arch}.deb"
    if destination.exists():
        raise FileExistsError(destination)
    with tempfile.TemporaryDirectory(prefix=".pqkeep-deb-", dir=out) as directory:
        work = Path(directory).absolute()
        stage = work / "debian/pqkeep"
        put(stage, "usr/bin/pqkeep", binary.read_bytes(), 0o755)
        staged = stage / "usr/bin/pqkeep"
        docs(stage, root, staged, version, metadata, stamp)
        write_licenses(root, target, stage / DOC)
        control(stage, arch, version, dependencies(stage, work), metadata)
        normalize(stage, stamp)
        package = work / "candidate.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "-Zxz", "-z9",
                        "--uniform-compression", "--build", str(stage), str(package)], check=True)
        check_package(package, arch, hashlib.sha256(binary.read_bytes()).hexdigest())
        os.link(package, destination)
    print(destination)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("target", choices=TARGETS)
    parser.add_argument("out", type=Path)
    parser.add_argument("--ci-sha", required=True)
    args = parser.parse_args()
    try:
        build(args.binary, args.target, args.out, args.ci_sha, Path(__file__).resolve().parents[1])
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"FEHLER: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
