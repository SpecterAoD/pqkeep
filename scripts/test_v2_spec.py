#!/usr/bin/env python3
"""Referenztests V01–V06, V08, V09 für docs/V2_DRAFT.md / reference tests for the v2 draft.

DE: Prüfen Kodierung, Regeln, Grenzen und AAD-Bindung – nicht Rust, nicht Kryptografie-Sicherheit.
EN: Check encoding, rules, limits and AAD binding – not Rust, not cryptographic security.
Aufruf / usage: python3 -m unittest discover -s scripts -p 'test_v2_*.py'
"""

import hashlib
import unittest

import v2_reference as ref

NONCE = bytes(range(12))
SALT = bytes(range(32, 64))


def pslot(factor=1):
    return ref.kdf_slot(factor, 65536, 3, 1, SALT, NONCE)


def rslot(first_byte, kem=3):
    rid = bytes([first_byte]) + bytes(31)
    return ref.recipient_slot(kem, rid, bytes(ref.KEM_CT[kem]), NONCE)


class V2SpecTests(unittest.TestCase):
    def test_V01_slot_bytes(self):
        expected = ("0101" "00000100" "03000000" "01000000" "20" + SALT.hex() + NONCE.hex())
        self.assertEqual(pslot().hex(), expected)
        self.assertEqual(pslot(0)[1], 0)
        for kem, size in ref.KEM_CT.items():
            with self.subTest(kem=kem):
                self.assertEqual(len(rslot(1, kem)), 1 + 1 + 32 + size + 12)
        for bad in (2, True, -1):
            with self.subTest(factor=bad), self.assertRaises(ValueError):
                ref.kdf_slot(bad, 65536, 3, 1, SALT, NONCE)
        for kem in (0, 4, True):
            with self.subTest(kem=kem), self.assertRaises(ValueError):
                ref.recipient_slot(kem, bytes(32), bytes(1568), NONCE)

    def test_V02_metadata_bytes(self):
        meta = ref.metadata(1, bytes(range(7)), [pslot()])
        head = "50514b46454e4300" "0200" "01" "00000100" "00010203040506" "01"
        self.assertEqual(meta.hex(), head + pslot().hex())

    def test_V02_shared_digests(self):
        # DE: Dieselben Sollwerte prüft der Rust-Core in tests/files_v2_header.rs.
        # EN: The Rust core checks the same expected values in tests/files_v2_header.rs.
        slots = [pslot()] + [rslot(k, kem=k) for k in (1, 2, 3)]
        meta = ref.metadata(2, bytes(range(7)), slots)
        full = ref.header(meta, [bytes([i]) * 48 for i in range(4)], 4)
        self.assertEqual((len(meta), len(full)), (3644, 3836))
        digests = [hashlib.sha3_256(meta).hexdigest(), ref.stream_aad(full).hex(),
                   hashlib.sha3_256(ref.wrap_aad("file", meta, 3)).hexdigest()]
        self.assertEqual(digests, [
            "5925f33cd2bae61bce5cc87f7b4631ec23ae35c729f9a9374165fed6e98b5425",
            "2ec08e1891cf6491066fee1bbd158476605bc7b3be07c7b87dae898214b6f471",
            "2d0755aefd77e20c590465cc412f0d28259b5e23672003f4ddb0410d1f1d306a"])

    def test_V03_slot_rules(self):
        ok = [[pslot()], [rslot(1)], [pslot(), rslot(1), rslot(2)]]
        for slots in ok:
            ref.check_slots(slots)
        bad = {
            "empty": [],
            "two passphrases": [pslot(), pslot()],
            "passphrase not first": [rslot(1), pslot()],
            "unsorted": [rslot(2), rslot(1)],
            "duplicate": [rslot(1), rslot(1)],
            "reserved tpm": [bytes([3]) + bytes(10)],
            "reserved fido2": [bytes([4]) + bytes(10)],
            "unknown": [bytes([9]) + bytes(10)],
        }
        for name, slots in bad.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                ref.check_slots(slots)

    def test_V04_recipient_and_header_limits(self):
        many = [rslot(i, kem=1) for i in range(1, 65)]
        ref.check_slots(many)
        ref.check_slots([pslot()] + many)
        with self.assertRaises(ValueError):
            ref.check_slots(many + [rslot(200, kem=1)])
        big = [rslot(i) for i in range(1, 65)]
        meta = ref.metadata(2, bytes(7), [pslot()] + big)
        full = ref.header(meta, [bytes(48)] * 65, 65)
        self.assertLessEqual(len(full), ref.HEADER_LIMIT)
        self.assertEqual(ref.bounded(bytes(ref.HEADER_LIMIT)), bytes(ref.HEADER_LIMIT))
        with self.assertRaises(ValueError):
            ref.bounded(bytes(ref.HEADER_LIMIT + 1))
        with self.assertRaises(ValueError):
            ref.header(meta, [bytes(48)] * 64, 65)

    def test_V05_wrap_aad_binds_header_and_index(self):
        meta = ref.metadata(1, bytes(7), [pslot(), rslot(1)])
        base = ref.wrap_aad("file", meta, 0)
        self.assertNotEqual(base, ref.wrap_aad("file", meta, 1))
        self.assertNotEqual(base, ref.wrap_aad("key", meta, 0))
        for i in range(len(meta)):
            changed = bytearray(meta)
            changed[i] ^= 1
            self.assertNotEqual(ref.wrap_aad("file", bytes(changed), 0), base, i)

    def test_V06_stream_aad_binds_every_wrap(self):
        meta = ref.metadata(1, bytes(7), [pslot(), rslot(1)])
        wraps = [bytes(48), bytes(range(48))]
        base = ref.stream_aad(ref.header(meta, wraps, 2))
        for w in range(2):
            for i in range(48):
                changed = [bytearray(x) for x in wraps]
                changed[w][i] ^= 1
                full = ref.header(meta, [bytes(x) for x in changed], 2)
                self.assertNotEqual(ref.stream_aad(full), base, (w, i))

    def test_V08_domains(self):
        for kind in ("file", "key"):
            self.assertLessEqual(len(ref.argon2_ad(kind)), 32)
            self.assertNotIn(b"v1", ref.DOMAINS[kind])
        infos = {ref.kdf_slot_info(k, f) for k in ("file", "key") for f in (0, 1)}
        infos.add(ref.recipient_info(bytes(32)))
        self.assertEqual(len(infos), 5)

    def test_V09_factor_file(self):
        self.assertEqual(ref.factor_file(bytes(32)), bytes(32))
        for size in (0, 31, 33, 4096):
            with self.subTest(size=size), self.assertRaises(ValueError):
                ref.factor_file(bytes(size))

    def test_C07_key_file_header_and_aad(self):
        """DE: Header und AAD der Schlüsseldatei v2: exakte Bytes, jedes Feld gebunden.
        EN: Header and AAD of key file v2: exact bytes, every field bound."""
        meta = {"name": "A", "company": "Ä"}
        head = ref.key_header(bytes(32), "t", meta, b"pk")
        expected = (ref.uint(10, 64) + b"PQKEEP-KEY" + ref.uint(2, 32) + ref.uint(32, 64) + bytes(32)
                    + ref.uint(1, 64) + b"t" + b"\x01" + ref.uint(1, 64) + b"A" + b"\x00"
                    + b"\x01" + ref.uint(2, 64) + "Ä".encode() + b"\x00\x00"
                    + ref.uint(2, 64) + b"pk" + b"\x01")
        self.assertEqual(head, expected)
        aad = ref.key_aad("AES-256", 65536, 3, 4, b"salt", head)
        self.assertEqual(aad, b"PQKeep/key/v2\0aad/key\0" + ref.uint(7, 64) + b"AES-256"
                         + ref.uint(65536, 32) + ref.uint(3, 32) + ref.uint(4, 32)
                         + ref.uint(4, 64) + b"salt" + ref.uint(len(head), 64) + head)
        others = [ref.key_aad("AES-256", 65536, 3, 4, b"salt",
                              ref.key_header(bytes(32), "t", dict(meta, department="x"), b"pk")),
                  ref.key_aad("ML-KEM-768", 65536, 3, 4, b"salt", head),
                  ref.key_aad("AES-256", 65537, 3, 4, b"salt", head),
                  ref.key_aad("AES-256", 65536, 4, 4, b"salt", head),
                  ref.key_aad("AES-256", 65536, 3, 1, b"salt", head),
                  ref.key_aad("AES-256", 65536, 3, 4, b"Salt", head)]
        self.assertEqual(len({aad, *others}), 7)
        for bad in ({}, {"name": None}, {"name": "A", "other": "x"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ref.key_header(bytes(32), "t", bad, b"")
        with self.assertRaises(ValueError):
            ref.key_header(bytes(31), "t", meta, b"")


if __name__ == "__main__":
    unittest.main()
