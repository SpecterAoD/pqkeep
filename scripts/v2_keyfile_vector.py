#!/usr/bin/env python3
"""Unabhängiger Vektor einer Schlüsseldatei v2 (C07) / independent vector of a key file v2 (C07).

DE: Erzeugt `tests/kat/v2_keyfile.json`: eine vollständige `*.key.json` im Format v2 (AES-256,
    Passphrase + Faktordatei), gebaut ohne den Rust-Code: Header und AAD aus `v2_reference.py`,
    Schlüssel aus `tests/kat/v2_argon2id.json` (argon2pure, Fall „key“ mit Faktor), AES-256-GCM
    aus Python `cryptography`. Der Rust-Test `tests/envelope_v2_kat.rs` muss diese Datei
    entsperren. AES-256, weil dafür kein öffentlicher Schlüssel nötig ist (ML-KEM/ML-DSA gibt es
    in der Standardbibliothek nicht). Nur öffentliche Testbytes, keine echten Geheimnisse.
    Gehört nicht zur CI (braucht `cryptography`); überschreibt nie.
    Aufruf (einmalig): python3 scripts/v2_keyfile_vector.py tests/kat/v2_keyfile.json [--dry-run]
EN: Creates `tests/kat/v2_keyfile.json`: a complete `*.key.json` in format v2 (AES-256,
    passphrase + factor file), built without the Rust code: header and AAD from
    `v2_reference.py`, key from `tests/kat/v2_argon2id.json` (argon2pure, case "key" with
    factor), AES-256-GCM from Python `cryptography`. The Rust test `tests/envelope_v2_kat.rs`
    must unlock this file. AES-256 because it needs no public key (the standard library has no
    ML-KEM/ML-DSA). Public test bytes only, no real secrets. Not part of CI (needs
    `cryptography`); never overwrites. Usage: see above.
"""

import base64
import json
import pathlib
import sys

import v2_argon2_vectors as argon
import v2_reference as ref

KAT = pathlib.Path(__file__).resolve().parent.parent / "tests/kat/v2_argon2id.json"
ALGORITHM = "AES-256"
IDENT = bytes(range(96, 128))
CREATED = "2026-11-13T00:00:00Z"
METADATA = {"name": "Testvektor v2 – öffentlich / public", "department": "KAT"}
NONCE = bytes(range(200, 212))
PLAIN = bytes(range(160, 192))
MEMORY, ITERATIONS, PARALLELISM = 65536, 3, 4


def b64(data):
    return base64.b64encode(data).decode()


def aad():
    """DE: AAD mit Header v2 (kein öffentlicher Schlüssel bei AES). EN: AAD with the v2 header."""
    header = ref.key_header(IDENT, CREATED, METADATA, b"")
    return ref.key_aad(ALGORITHM, MEMORY, ITERATIONS, PARALLELISM, argon.SALT, header)


def document(sealed):
    """DE: JSON-Text wie ihn PQKeep schreibt (2 Leerzeichen, Feldreihenfolge, Zeilenende).
    EN: JSON text as PQKeep writes it (2 spaces, field order, trailing newline)."""
    doc = {
        "magic": ref.KEY_MAGIC.decode(), "format_version": ref.VERSION, "algorithm": ALGORITHM,
        "key_id": IDENT.hex(), "created_utc": CREATED, "metadata": METADATA, "public_key": "",
        "kdf": {"algorithm": "argon2id", "version": 0x13, "memory_kib": MEMORY,
                "iterations": ITERATIONS, "parallelism": PARALLELISM, "salt": b64(argon.SALT),
                "factor": "file-32"},
        "cipher": {"algorithm": "aes-256-gcm", "nonce": b64(NONCE), "ciphertext": b64(sealed)},
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def build(wrap_secret, seal):
    """DE: Ganze Datei; `seal(schlüssel, nonce, klartext, aad)` ist AES-256-GCM.
    EN: Whole file; `seal(key, nonce, plaintext, aad)` is AES-256-GCM."""
    return document(seal(wrap_secret, NONCE, PLAIN, aad()))


def aes_gcm(secret, nonce, plaintext, associated):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(secret).encrypt(nonce, plaintext, associated)


def main(argv):
    dry = "--dry-run" in argv
    paths = [a for a in argv[1:] if a != "--dry-run"]
    if len(paths) != 1:
        raise SystemExit(__doc__)
    case = json.loads(KAT.read_text(encoding="utf-8"))["cases"][2]
    if (case["domain"], case["factor"], case["parallelism"]) != ("key", 1, PARALLELISM):
        raise SystemExit("FEHLER / ERROR: unerwarteter dritter Fall / unexpected third case")
    text = build(bytes.fromhex(case["hkdf_hex"]), aes_gcm)
    if dry:
        print("Probelauf / dry run:", len(text.encode()), "Bytes")
        return 0
    import cryptography

    out = {"source": f"cryptography {cryptography.__version__} + v2_reference.py "
                     "(scripts/v2_keyfile_vector.py)",
           "plain_hex": PLAIN.hex(), "document_hex": text.encode().hex()}
    with open(paths[0], "x", encoding="utf-8") as handle:
        json.dump(out, handle, indent=2)
        handle.write("\n")
    print("geschrieben / written:", paths[0])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
