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

Aufruf / usage:  python3 scripts/release_sbom.py <sbom.json> <version> <target> <commit> [--dry-run]
    --dry-run  DE: nur die Werte anzeigen / EN: only show the values
"""

import datetime
import json
import os
import sys
import uuid

REPO = "https://github.com/SpecterAoD/pqkeep"


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


def main(argv: list) -> int:
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
