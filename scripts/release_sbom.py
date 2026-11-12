#!/usr/bin/env python3
"""Ergänzt eine CycloneDX-SBOM reproduzierbar / completes a CycloneDX SBOM reproducibly.

DE: `cargo-cyclonedx` schreibt keine `serialNumber`, die `actions/attest` aber verlangt, und
    setzt die aktuelle Uhrzeit als Zeitstempel. Dieses Skript ergänzt eine deterministische
    `serialNumber` (UUIDv5 aus Repository, Version, Ziel und Commit) und setzt den Zeitstempel
    auf SOURCE_DATE_EPOCH – gleiche Eingaben ergeben dieselbe SBOM.
EN: `cargo-cyclonedx` writes no `serialNumber`, which `actions/attest` requires, and uses the
    current time as timestamp. This script adds a deterministic `serialNumber` (UUIDv5 from
    repository, version, target and commit) and sets the timestamp to SOURCE_DATE_EPOCH – equal
    inputs give the same SBOM.

    Für ein Debian-Paket entsteht aus der SBOM des zugehörigen Archivs eine eigene SBOM mit
    eigener `serialNumber` und der Paketidentität (Name, Debian-Version, Architektur,
    SHA-256 des enthaltenen Programms) als `metadata.properties`.
    For a Debian package, the SBOM of the matching archive yields a separate SBOM with its own
    `serialNumber` and the package identity (name, Debian version, architecture, SHA-256 of
    the contained program) as `metadata.properties`.

Aufruf / usage:  python3 scripts/release_sbom.py <sbom.json> <version> <target> <commit> [--dry-run]
                 python3 scripts/release_sbom.py --deb <sbom.json> <out.json> <debian-version>
                                                 <arch> <binary-sha256> <commit>
    --dry-run  DE: nur die Werte anzeigen / EN: only show the values
"""

import copy
import datetime
import json
import os
import re
import sys
import uuid

REPO = "https://github.com/SpecterAoD/pqkeep"
DEB_PREFIX = "pqkeep:debian:"


def serial(version: str, target: str, commit: str) -> str:
    """DE/EN: Deterministische Seriennummer / deterministic serial number."""
    return "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{REPO}/sbom/{version}/{target}/{commit}"))


def timestamp() -> str:
    """DE/EN: SOURCE_DATE_EPOCH als ISO-8601 (UTC) / SOURCE_DATE_EPOCH as ISO 8601 (UTC)."""
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def complete(sbom: dict, version: str, target: str, commit: str) -> dict:
    """DE/EN: Ergänzt die Felder, lehnt Nicht-CycloneDX ab / adds fields, rejects non-CycloneDX."""
    if sbom.get("bomFormat") != "CycloneDX" or not sbom.get("specVersion"):
        raise ValueError("keine CycloneDX-SBOM / not a CycloneDX SBOM")
    sbom["serialNumber"] = serial(version, target, commit)
    sbom.setdefault("metadata", {})["timestamp"] = timestamp()
    return sbom


def deb_serial(version: str, arch: str, commit: str) -> str:
    """DE/EN: Eigene Seriennummer je Debian-Paket / separate serial number per Debian package."""
    return "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{REPO}/sbom/deb/{version}/{arch}/{commit}"))


def deb_properties(version: str, arch: str, binary_sha256: str) -> list:
    """DE/EN: Paketidentität als CycloneDX-Eigenschaften / package identity as properties."""
    values = {"package": "pqkeep", "version": version, "architecture": arch,
              "binary-sha256": binary_sha256}
    return [{"name": DEB_PREFIX + key, "value": value} for key, value in values.items()]


def for_deb(sbom: dict, version: str, arch: str, binary_sha256: str, commit: str) -> dict:
    """DE/EN: SBOM des Archivs auf das Paket umschreiben / derive the package SBOM."""
    if sbom.get("bomFormat") != "CycloneDX" or not sbom.get("specVersion"):
        raise ValueError("keine CycloneDX-SBOM / not a CycloneDX SBOM")
    if (arch not in ("amd64", "arm64") or not re.fullmatch(r"[0-9a-f]{64}", binary_sha256)
            or not re.fullmatch(r"[0-9][0-9A-Za-z.+~-]*", version)):
        raise ValueError("ungültige Paketangaben / invalid package data")
    result = copy.deepcopy(sbom)
    metadata = result.setdefault("metadata", {})
    kept = [p for p in metadata.get("properties", []) if not str(p.get("name", "")).startswith(DEB_PREFIX)]
    metadata["properties"] = kept + deb_properties(version, arch, binary_sha256)
    metadata["timestamp"] = timestamp()
    result["serialNumber"] = deb_serial(version, arch, commit)
    return result


def main_deb(args: list) -> int:
    """DE/EN: Paket-SBOM schreiben, nie überschreiben / write the package SBOM, never overwrite."""
    if len(args) != 6:
        print(__doc__)
        return 2
    source, out, version, arch, binary_sha256, commit = args
    with open(source, encoding="utf-8") as f:
        sbom = for_deb(json.load(f), version, arch, binary_sha256, commit)
    with open(out, "x", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"serialNumber={sbom['serialNumber']} deb={version} arch={arch}")
    return 0


def main(argv: list) -> int:
    if argv[:1] == ["--deb"]:
        return main_deb(argv[1:])
    dry = "--dry-run" in argv
    args = [a for a in argv if a != "--dry-run"]
    if len(args) != 4:
        print(__doc__)
        return 2
    path, version, target, commit = args
    with open(path, encoding="utf-8") as f:
        sbom = complete(json.load(f), version, target, commit)
    print(f"serialNumber={sbom['serialNumber']} timestamp={sbom['metadata']['timestamp']}")
    if not dry:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2, ensure_ascii=False)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
