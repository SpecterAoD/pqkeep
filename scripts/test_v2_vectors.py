#!/usr/bin/env python3
"""V07: HKDF-SHA3-256-Sollwerte für docs/V2_DRAFT.md / HKDF-SHA3-256 expected values.

DE: Unabhängig am 08.11.2026 mit `cryptography` 41.0.7 (HKDF, SHA3_256) berechnet; der Test selbst
    nutzt nur hashlib/hmac. Öffentliche Testbytes: B=0..31, S=32..63, ss=64..95, ID=96..127,
    KEM-Chiffrat = i mod 256 (1568 Byte). Keine echten Geheimnisse.
EN: Independently computed on 2026-11-08 with `cryptography` 41.0.7; the test itself uses only
    hashlib/hmac. Public test bytes as above. No real secrets.
"""

import json
import pathlib
import unittest

import v2_argon2_vectors as argon
import v2_reference as ref

KAT = pathlib.Path(__file__).resolve().parent.parent / "tests/kat/v2_argon2id.json"

KDF_SLOT = {
    ("file", 0): "4f41ede1889d37fa2f68f1031731f3ea4cc88ab7454660cb7f2821f282f3cedc",
    ("file", 1): "c40e01558262cea41d40fba3465a8b2c32ce672d2a10a53b45957298a37a8fc0",
    ("key", 0): "8cb9342828047ad1138230e9b69f1b3acbc5dd74cd1d2c6b3c043aad423d715b",
    ("key", 1): "3d9c5c935d84946e6cbdcab4922bd2a617fd926c36d0909dd9d85fc012dd95ba",
}
RECIPIENT = "f9b1412d2ef25deb302da555f52f68e8b6dd4650f6f12f2cbcac0e8676524cf1"


class V2VectorTests(unittest.TestCase):
    def test_V07_hkdf_vectors(self):
        b, s = bytes(range(32)), bytes(range(32, 64))
        for (kind, factor), expected in KDF_SLOT.items():
            with self.subTest(kind=kind, factor=factor):
                out = ref.hkdf_sha3(b, s, ref.kdf_slot_info(kind, factor))
                self.assertEqual(out.hex(), expected)
        ss, rid = bytes(range(64, 96)), bytes(range(96, 128))
        ct = bytes(i % 256 for i in range(1568))
        self.assertEqual(ref.hkdf_sha3(ss, ct, ref.recipient_info(rid)).hex(), RECIPIENT)

    def test_C01_kat_file_is_consistent(self):
        """DE: Die Datei passt zum Erzeugungsskript; der HKDF-Schritt wird nachgerechnet (Argon2id
        selbst prüft der Rust-Test). EN: File matches the generator; HKDF step is recomputed."""
        data = json.loads(KAT.read_text(encoding="utf-8"))
        self.assertEqual(data["passphrase_hex"], argon.PASSPHRASE.hex())
        self.assertEqual(data["salt_hex"], argon.SALT.hex())
        self.assertEqual(data["factor_hex"], argon.FACTOR.hex())
        self.assertEqual(len(data["cases"]), len(argon.CASES))
        for case, expected in zip(data["cases"], argon.CASES):
            got = tuple(case[k] for k in ("domain", "factor", "memory_kib", "iterations", "parallelism"))
            self.assertEqual(got, expected)
            wrap_key = ref.hkdf_sha3(bytes.fromhex(case["argon2id"]), argon.SALT,
                                     ref.kdf_slot_info(case["domain"], case["factor"]))
            self.assertEqual(wrap_key.hex(), case["hkdf_hex"])


if __name__ == "__main__":
    unittest.main()
