#!/usr/bin/env python3
"""DE: Gepinnte Provider-Herkunft und exakt reviewte Patches. EN: Verify pinned provider patches."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "vendor"


def verify():
    """DE/EN: Keine unbekannten/fehlenden Providerdateien / no unknown or missing provider files."""
    original = json.loads((ROOT / "upstream-sha256.json").read_text())
    patched = json.loads((ROOT / "patches-sha256.json").read_text())
    for package, files in original.items():
        expected = dict(files)
        expected.update(patched.get(package, {}))
        actual = {str(p.relative_to(ROOT / package)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in (ROOT / package).rglob("*") if p.is_file()}
        if actual != expected:
            raise ValueError(f"Providerdateien abweichend / provider files differ: {package}")
    if set(patched) - set(original):
        raise ValueError("Unbekannte Provider / unknown providers")


if __name__ == "__main__":
    verify()
    print("OK: Provider-Herkunft und Patches / provider provenance and patches")
