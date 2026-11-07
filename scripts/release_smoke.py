#!/usr/bin/env python3
"""Rauchtest eines gebauten Release-Binaries / smoke test of a built release binary.

DE: Führt die Beispiele aus der README mit dem echten Binary aus: Version, Passphrase erzeugen,
    Schlüssel erzeugen und exportieren, Datei verschlüsseln und entschlüsseln (Passphrase und
    Empfänger), Vergleich mit dem Original. Unter Linux muss `--verbose` eine aktive Seccomp-
    Sandbox melden. Passphrasen entstehen zur Laufzeit. Exit 1 bei einem Fehler.
EN: Runs the README examples with the real binary: version, generate a passphrase, generate and
    export a key, encrypt and decrypt a file (passphrase and recipient), compare with the original.
    On Linux `--verbose` must report an active seccomp sandbox. Passphrases are created at run
    time. Exit 1 on failure.

Aufruf / usage:  python3 scripts/release_smoke.py <binary> [--dry-run]
    --dry-run  DE: nur die Schritte anzeigen / EN: only list the steps
"""

import os
import subprocess
import sys
import tempfile

STEPS = [
    "--version",
    "passphrase",
    "generate + export",
    "encrypt/decrypt (passphrase)",
    "encrypt/decrypt (recipient)",
    "sandbox status (Linux)",
]


def run(binary: str, args: list, cwd: str, stdin: str = "") -> subprocess.CompletedProcess:
    """DE/EN: Startet pqkeep, bricht bei Exit ≠ 0 ab / runs pqkeep, aborts on exit ≠ 0."""
    cmd = [binary, "--lang", "en"] + args
    # DE: UTF-8 ausdrücklich (Windows nutzt sonst cp1252). EN: UTF-8 explicitly (Windows uses cp1252).
    res = subprocess.run(
        cmd, cwd=cwd, input=stdin, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=600,
    )
    if res.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} -> {res.returncode}: {res.stderr.strip()[:300]}")
    return res


def smoke(binary: str, tmp: str) -> None:
    print(run(binary, ["--version"], tmp).stdout.strip())
    pw = run(binary, ["passphrase"], tmp).stdout.strip()
    line = pw + "\n"
    run(binary, ["generate", "--name", "Smoke Test", "--out", "k.json", "--passphrase-stdin"], tmp, line)
    run(binary, ["export", "k.json", "--out", "k.pub.json"], tmp)
    original = os.urandom(200_000)
    with open(os.path.join(tmp, "data.bin"), "wb") as f:
        f.write(original)
    run(binary, ["encrypt", "data.bin", "--out", "p.pqkf", "--passphrase-stdin"], tmp, line)
    run(binary, ["decrypt", "p.pqkf", "--out", "p.bin", "--passphrase-stdin"], tmp, line)
    run(binary, ["encrypt", "data.bin", "--to", "k.pub.json", "--out", "r.pqkf"], tmp)
    run(binary, ["decrypt", "r.pqkf", "--key", "k.json", "--out", "r.bin", "--passphrase-stdin"], tmp, line)
    for name in ["p.bin", "r.bin"]:
        with open(os.path.join(tmp, name), "rb") as f:
            if f.read() != original:
                raise RuntimeError(f"{name}: Inhalt weicht ab / content differs")
    if sys.platform.startswith("linux"):
        err = run(binary, ["--verbose", "validate", "--passphrase-stdin"], tmp, line).stderr
        if "seccomp=full" not in err:
            raise RuntimeError(f"Sandbox nicht aktiv / sandbox not active: {err.strip()[:300]}")


def main(argv: list) -> int:
    dry = "--dry-run" in argv
    args = [a for a in argv if a != "--dry-run"]
    if len(args) != 1:
        print(__doc__)
        return 2
    if dry:
        print("\n".join(STEPS))
        return 0
    binary = os.path.abspath(args[0])
    with tempfile.TemporaryDirectory() as tmp:
        try:
            smoke(binary, tmp)
        except RuntimeError as e:
            print(f"FEHLER / ERROR: {e}", file=sys.stderr)
            return 1
    print("Rauchtest bestanden / smoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
