#!/usr/bin/env python3
"""Unabhängiger Vektor für eine ganze v2-Datei (C02) / independent vector of a whole v2 file (C02).

DE: Erzeugt `tests/kat/v2_content.json`: eine vollständige `.pqkf` im Format v2 (Passphrase-Zugang
    mit Faktordatei, Inhalt = eine kleine Datei), gebaut ohne den Rust-Code: Header aus
    `v2_reference.py`, Packschlüssel aus `tests/kat/v2_argon2id.json` (argon2pure, erster Fall),
    AES-256-GCM für Hülle und Inhalt aus Python `cryptography`, Archiv und STREAM-Nonce
    (Präfix ‖ Zähler ‖ Endmarke) nach docs/FILE_FORMAT.md hier nachgebaut. Der Rust-Test
    `tests/files_v2_kat.rs` muss diese Datei öffnen. Nur öffentliche Testbytes, keine echten
    Geheimnisse. Gehört nicht zur CI (braucht `cryptography`); überschreibt nie.
    Aufruf (einmalig): python3 scripts/v2_content_vector.py tests/kat/v2_content.json [--dry-run]
EN: Creates `tests/kat/v2_content.json`: a complete `.pqkf` in format v2 (passphrase slot with
    factor file, content = one small file), built without the Rust code: header from
    `v2_reference.py`, wrapping key from `tests/kat/v2_argon2id.json` (argon2pure, first case),
    AES-256-GCM for wrap and content from Python `cryptography`, archive and STREAM nonce
    (prefix ‖ counter ‖ last flag) rebuilt here per docs/FILE_FORMAT.md. The Rust test
    `tests/files_v2_kat.rs` must open this file. Public test bytes only, no real secrets. Not
    part of CI (needs `cryptography`); never overwrites. Usage: see above.
"""

import hashlib
import json
import pathlib
import sys

import v2_argon2_vectors as argon
import v2_reference as ref

KAT = pathlib.Path(__file__).resolve().parent.parent / "tests/kat/v2_argon2id.json"
PREFIX = bytes(range(64, 71))
WRAP_NONCE = bytes(range(200, 212))
CONTENT_SECRET = bytes(range(160, 192))
NAME = "vektor.txt"
PLAIN = "PQKeep v2 – öffentlicher Testinhalt / public test content\n".encode() * 3
TAG_LEN = 16


def meta():
    """DE: M mit einem Passphrase-Zugang (Faktor, 64 MiB, t=3, p=1). EN: M with one slot."""
    slot = ref.kdf_slot(ref.FACTOR_FILE, 65536, 3, 1, argon.SALT, WRAP_NONCE)
    return ref.metadata(1, PREFIX, [slot])


def archive():
    """DE: Archiv mit einer Datei: 2 | U16 Pfadlänge | Pfad | U64 Größe | Inhalt | SHA3-256,
    dann Ende 0 | U64 Anzahl. EN: Archive with one file, then the end marker."""
    name = NAME.encode()
    entry = (b"\x02" + ref.uint(len(name), 16) + name + ref.uint(len(PLAIN), 64) + PLAIN
             + hashlib.sha3_256(PLAIN).digest())
    return entry + b"\x00" + ref.uint(1, 64)


def stream_nonce(counter, last):
    """DE: 7 Byte Präfix ‖ Zähler (Big Endian) ‖ Endmarke. EN: prefix ‖ counter (BE) ‖ last."""
    return PREFIX + counter.to_bytes(4, "big") + bytes([1 if last else 0])


def build(wrap_secret, seal):
    """DE: Ganze Datei; `seal(schlüssel, nonce, klartext, aad)` ist AES-256-GCM.
    EN: Whole file; `seal(key, nonce, plaintext, aad)` is AES-256-GCM."""
    m = meta()
    wrap = seal(wrap_secret, WRAP_NONCE, CONTENT_SECRET, ref.wrap_aad("file", m, 0))
    full = ref.header(m, [wrap], 1)
    plain = archive()
    if len(plain) >= ref.CHUNK:
        raise ValueError("nur ein Block / single chunk only")
    return full + seal(CONTENT_SECRET, stream_nonce(0, True), plain, ref.stream_aad(full))


def aes_gcm(secret, nonce, plaintext, aad):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(secret).encrypt(nonce, plaintext, aad)


def main(argv):
    dry = "--dry-run" in argv
    paths = [a for a in argv[1:] if a != "--dry-run"]
    if len(paths) != 1:
        raise SystemExit(__doc__)
    case = json.loads(KAT.read_text(encoding="utf-8"))["cases"][0]
    if (case["domain"], case["factor"], case["parallelism"]) != ("file", 1, 1):
        raise SystemExit("FEHLER / ERROR: unerwarteter erster Fall / unexpected first case")
    data = build(bytes.fromhex(case["hkdf_hex"]), aes_gcm)
    if dry:
        print("Probelauf / dry run:", len(data), "Bytes")
        return 0
    import cryptography

    out = {"source": f"cryptography {cryptography.__version__} + v2_reference.py "
                     "(scripts/v2_content_vector.py)",
           "name": NAME, "plain_hex": PLAIN.hex(), "file_hex": data.hex()}
    with open(paths[0], "x", encoding="utf-8") as handle:
        json.dump(out, handle, indent=2)
        handle.write("\n")
    print("geschrieben / written:", paths[0])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
