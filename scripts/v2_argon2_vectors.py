#!/usr/bin/env python3
"""Unabhängige Argon2id-Sollwerte für v2 (C01) / independent Argon2id vectors for v2 (C01).

DE: Erzeugt `tests/kat/v2_argon2id.json` mit `argon2pure` (reines Python, unabhängig von der
    Rust-Crate) bei den echten Mindestparametern (64 MiB, t = 3) samt Secret (Faktordatei) und
    Associated Data nach docs/V2_DRAFT.md; der HKDF-Schritt kommt aus `v2_reference.py`
    (hashlib/hmac). Vor dem Rechnen wird `argon2pure` gegen RFC 9106, Abschnitt 5.3 geprüft.
    Nur öffentliche Testbytes, keine echten Geheimnisse. Läuft einige Minuten und gehört nicht
    zur CI; die Rust-Tests lesen nur die erzeugte Datei. Überschreibt nie.
    Aufruf (einmalig, in einer venv mit `pip install argon2pure`):
      .venv/bin/python scripts/v2_argon2_vectors.py tests/kat/v2_argon2id.json [--dry-run]
EN: Creates `tests/kat/v2_argon2id.json` with `argon2pure` (pure Python, independent of the Rust
    crate) at the real minimum parameters (64 MiB, t = 3) including secret (factor file) and
    associated data per docs/V2_DRAFT.md; the HKDF step comes from `v2_reference.py`. Before
    computing, `argon2pure` is checked against RFC 9106, section 5.3. Public test bytes only, no
    real secrets. Takes several minutes and is not part of CI; the Rust tests only read the
    generated file. Never overwrites. Usage: see above.
"""

import json
import sys

import v2_reference as ref

RFC9106_TAG = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
PASSPHRASE = "PQKeep v2 Testvektor – nicht geheim".encode()
SALT = bytes(range(32, 64))
FACTOR = bytes(range(128, 160))
# DE: (Domäne, Faktor, m in KiB, t, p). EN: (domain, factor, m in KiB, t, p).
CASES = (("file", 1, 65536, 3, 1), ("file", 0, 65536, 3, 1), ("key", 1, 65536, 3, 4))


def argon2id(password, salt, t, m, p, secret, ad):
    import argon2pure

    return argon2pure.argon2(password, salt, t, m, p, tag_length=32, secret=secret,
                             associated_data=ad, type_code=argon2pure.ARGON2ID)


def self_check():
    """DE: RFC 9106, 5.3 (mit Secret und AD). EN: RFC 9106, 5.3 (with secret and AD)."""
    tag = argon2id(b"\x01" * 32, b"\x02" * 16, 3, 32, 4, b"\x03" * 8, b"\x04" * 12)
    if tag.hex() != RFC9106_TAG:
        raise SystemExit("FEHLER / ERROR: argon2pure weicht von RFC 9106 ab")


def case(kind, factor, memory, iterations, parallelism):
    secret = FACTOR if factor else b""
    b = argon2id(PASSPHRASE, SALT, iterations, memory, parallelism, secret, ref.argon2_ad(kind))
    wrap_key = ref.hkdf_sha3(b, SALT, ref.kdf_slot_info(kind, factor))
    return {"domain": kind, "factor": factor, "memory_kib": memory, "iterations": iterations,
            "parallelism": parallelism, "argon2id": b.hex(), "hkdf_hex": wrap_key.hex()}


def main(argv):
    dry = "--dry-run" in argv
    paths = [a for a in argv[1:] if a != "--dry-run"]
    if len(paths) != 1:
        raise SystemExit(__doc__)
    self_check()
    if dry:
        print("Probelauf / dry run: RFC 9106 ok,", len(CASES), "Fälle / cases")
        return 0
    data = {"source": "argon2pure 1.3 + hashlib/hmac (scripts/v2_argon2_vectors.py)",
            "passphrase_hex": PASSPHRASE.hex(), "salt_hex": SALT.hex(),
            "factor_hex": FACTOR.hex(), "cases": [case(*c) for c in CASES]}
    with open(paths[0], "x", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    print("geschrieben / written:", paths[0])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
