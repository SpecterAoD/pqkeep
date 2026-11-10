#!/usr/bin/env python3
"""Lizenzinventar aus gesperrtem Cargo-Abhängigkeitsbaum; keine neuen Downloads."""

import hashlib
import json
from pathlib import Path
import re
import subprocess

from release_package import write_tar_gz


APACHE = re.compile(r"Apache License\s+Version 2\.0, January 2004\s+"
                    r"https?://www\.apache\.org/licenses/?\s+TERMS AND CONDITIONS"
                    r".*?END OF TERMS AND CONDITIONS", re.S)


def apache_reference(text: str) -> str:
    """Nur den geprüften Standardtext ersetzen; Hinweise und Ausnahmen bleiben erhalten."""
    canonical = APACHE.search((Path(__file__).resolve().parents[1] / "LICENSE").read_text())[0]

    def normalized(value: str) -> str:
        # enumflags2 lässt lediglich die Absatzmarker (a)–(d) weg.
        value = re.sub(r"(?m)^\s*\([a-d]\)\s+", "", value)
        return " ".join(value.replace("https://", "http://").split())

    def replace(match: re.Match) -> str:
        if normalized(match[0]) != normalized(canonical):
            raise ValueError("Abweichender Apache-Text benötigt ein ausdrückliches Lizenzreview")
        return ("Apache-2.0: see /usr/share/common-licenses/Apache-2.0.\n"
                "The unchanged upstream file is also preserved in licenses.tar.gz.")

    return APACHE.sub(replace, text)


def indented(text: str) -> str:
    """Mehrzeiliges Debian-Feld, leere Absätze nach DEP-5 darstellen."""
    return "\n".join(" " + (line if line.strip() else ".") for line in text.splitlines())

def cargo(root: Path, *args: str) -> str:
    """Cargo nur offline und mit unverändertem Lockfile abfragen."""
    return subprocess.check_output(["cargo", *args, "--offline", "--locked"],
                                   cwd=root, text=True)


def license_files(directory: Path) -> list[Path]:
    """Alle mitgelieferten Lizenz-/Hinweisdateien einschließen, Symlinks ablehnen."""
    names = ("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE")
    files = sorted(p for p in directory.rglob("*") if p.name.upper().startswith(names)
                   and not p.is_dir())
    if not files:
        raise ValueError(f"Lizenzdateien fehlen: {directory.name}")
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Keine reguläre Lizenzdatei: {path.name}")
    return files


def crate_notice(package: dict) -> tuple[str, dict]:
    """Originaltexte und Copyright-Hinweise ohne erfundene Rechteinhaber übernehmen."""
    directory = Path(package["manifest_path"]).parent
    expression = package["license"]
    if not expression or "\n" in expression:
        raise ValueError(f"Lizenzangabe fehlt: {package['name']}")
    texts, hashes, notices = [], {}, set()
    for path in license_files(directory):
        data = path.read_bytes()
        name = path.relative_to(directory).as_posix()
        text = data.decode("utf-8")
        hashes[name] = hashlib.sha256(data).hexdigest()
        texts.append(f"--- {name} ---\n{apache_reference(text)}")
        notices.update(line.strip() for line in text.splitlines()
                       if re.match(r"(?i)^\s*(copyright\s*(?:\(c\)|©|\d{4})|©|\(c\)\s*\d{4})", line))
    owner = "\n ".join(sorted(notices)) or "See the verbatim upstream notices below."
    license_name = expression.replace("/", " or ").replace(" OR ", " or ")
    license_name = license_name.replace(" AND ", " and ").replace(" WITH ", " with ")
    body = indented("\n".join(texts))
    stanza = (f"\nFiles: cargo/{package['name']}-{package['version']}/*\n"
              f"Copyright: {owner}\nLicense: {license_name}\n{body}\n")
    record = {key: package[key] for key in ("name", "version", "license", "source")}
    record["license_files"] = hashes
    return stanza, record


def write_licenses(root: Path, target: str, doc: Path) -> None:
    """Zielabhängige Crates und Lizenzinformationen der tatsächlich benutzten Toolchain."""
    before = (root / "Cargo.lock").read_bytes()
    tree = cargo(root, "tree", "--target", target, "--edges", "normal,build",
                 "--prefix", "none", "--format", "{p}", "--no-dedupe")
    selected = {tuple(line.split()[:2]) for line in tree.splitlines()}
    metadata = json.loads(cargo(root, "metadata", "--format-version", "1",
                                "--filter-platform", target))
    features = {node["id"]: node["features"] for node in metadata["resolve"]["nodes"]}
    packages = [p for p in metadata["packages"] if p["name"] != "pqkeep"
                and (p["name"], "v" + p["version"]) in selected]
    if len(packages) + 1 != len(selected):
        raise ValueError("Abhängigkeitsbaum und Cargo-Metadaten stimmen nicht überein")
    text = (root / "packaging/debian/copyright").read_text(encoding="utf-8")
    text += indented((root / "data/wordlists/LICENSES.md").read_text(encoding="utf-8") + "\n"
                     + (root / "packaging/debian/CC-BY-4.0").read_text(encoding="utf-8")) + "\n"
    records, originals = [], []
    for package in sorted(packages, key=lambda p: (p["name"], p["version"])):
        stanza, record = crate_notice(package)
        record["metadata_features"] = features[package["id"]]
        text += stanza
        records.append(record)
        originals += [(f"{package['name']}-{package['version']}/{name}",
                       str(Path(package["manifest_path"]).parent / name), 0o644)
                      for name in record["license_files"]]
    write_tar_gz(str(doc / "licenses.tar.gz"), "cargo-licenses", sorted(originals), 0)
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    rustdoc = sysroot / "share/doc/rust"
    sources = [rustdoc / "COPYRIGHT-library.html", *sorted((rustdoc / "licenses").glob("*.txt"))]
    if len(sources) < 2:
        raise ValueError("Lizenztexte der Rust-Standardbibliothek fehlen")
    rust_hashes = {}
    for source in sources:
        if source.is_symlink() or not source.is_file():
            raise ValueError("Ungültiger Rust-Lizenzpfad")
        dest = doc / "rust-licenses" / source.relative_to(rustdoc)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(source.read_bytes())
        rust_hashes[source.relative_to(rustdoc).as_posix()] = hashlib.sha256(source.read_bytes()).hexdigest()
    inventory = {"target": target, "cargo_lock_sha256": hashlib.sha256(before).hexdigest(),
                 "rustc": subprocess.check_output(["rustc", "-vV"], text=True),
                 "selection": "default features; normal/build dependencies; Cargo metadata feature union",
                 "rust_license_files": rust_hashes, "crates": records}
    (doc / "copyright").write_text(text, encoding="utf-8")
    (doc / "license-inventory.json").write_text(
        json.dumps(inventory, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if (root / "Cargo.lock").read_bytes() != before:
        raise ValueError("Cargo.lock wurde verändert")
