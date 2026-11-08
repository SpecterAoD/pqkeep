"""DE: #39 Referenzfälle R01–R13, ohne Hardware/Produktionsparser.
EN: #39 reference cases R01–R13, without hardware/production parser.
"""

import hashlib
import unittest

import factor_spec_reference as ref


class FactorSpecTests(unittest.TestCase):
    def test_R01_length_prefix(self):
        for raw, expected in [(b"", "00000000"), (b"A", "0100000041"),
                              ("ä".encode(), "02000000c3a4")]:
            with self.subTest(raw=raw):
                self.assertEqual(ref.field(raw).hex(), expected)
        for value in (-1, 2**32, True, 1.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ref.uint(value, 32)
        self.assertEqual(ref.uint(2**32 - 1, 32), b"\xff" * 4)

    def test_R02_descriptor_exact(self):
        normal = bytes(range(12))
        expected = "010100000000000000000101000102030405060708090a0b"
        self.assertEqual(ref.descriptor("file", b"", normal).hex(), expected)
        metadata = ref.file_metadata(1, bytes(range(7)), 65536, 3, 1,
                                     bytes(range(16)), bytes.fromhex(expected))
        prefix = "50514b46454e4300020001010000010000010203040506"
        kdf = "00000100030000000100000010000102030405060708090a0b0c0d0e0f"
        self.assertEqual(metadata.hex(), prefix + kdf + expected)

    def test_R03_domains_profiles_roles(self):
        outputs = []
        for profile in ref.PROFILES:
            hardware = profile != "file"
            descriptor = ref.descriptor(profile, b"provider" if hardware else b"",
                                        bytes(range(12)), b"r" * 12 if hardware else None)
            for kind in ("key", "file"):
                for role in (1, 2) if hardware else (1,):
                    outputs.append(ref.wrap_aad(kind, descriptor, role))
        self.assertEqual(len(set(outputs)), 10)
        self.assertEqual(ref.wrap_aad("key", b"X", 1),
                         b"PQKeep/key/v2/factor\0aad/wrap\0\x01\0\0\0X\x01")

    def test_R04_invalid_values(self):
        for profile in ("", "tpm", "unknown"):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                ref.descriptor(profile, b"", b"n" * 12)
        for size in (0, 11, 13):
            with self.subTest(size=size), self.assertRaises(ValueError):
                ref.descriptor("file", b"", bytes(size))
        for size in (0, 47, 49):
            with self.subTest(size=size), self.assertRaises(ValueError):
                ref.header(b"M", bytes(size))
        for role in (0, 3, True):
            with self.subTest(role=role), self.assertRaises(ValueError):
                ref.wrap_aad("key", b"M", role)
        with self.assertRaises(ValueError):
            ref.wrap_aad("unknown", b"M", 1)

    def test_R05_profile_shape(self):
        invalid = [("file", b"x", b"n" * 12, None),
                   ("file", b"", b"n" * 12, b"r" * 12)]
        for profile in ("file-tpm", "file-fido2"):
            invalid += [(profile, b"", b"n" * 12, b"r" * 12),
                        (profile, b"x", b"n" * 12, None),
                        (profile, b"x", b"n" * 12, b"r" * 11)]
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(ValueError):
                ref.descriptor(*args)

    def test_R06_nonce_collision(self):
        for profile in ("file-tpm", "file-fido2"):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                ref.descriptor(profile, b"data", b"n" * 12, b"n" * 12)

    def test_R07_header_budget(self):
        for size in (65535, 65536):
            self.assertEqual(len(ref.header(bytes(size - 48), bytes(48))), size)
        with self.assertRaises(ValueError):
            ref.header(bytes(65536 - 47), bytes(48))
        with self.assertRaises(ValueError):
            ref.descriptor("file-tpm", bytes(65537), b"n" * 12, b"r" * 12)
        with self.assertRaises(ValueError):
            ref.payload_aad("key", bytes(65537))

    def test_R08_metadata_mutations(self):
        for profile in ref.PROFILES:
            hardware = profile != "file"
            descriptor = ref.descriptor(profile, b"provider" if hardware else b"",
                                        b"n" * 12, b"r" * 12 if hardware else None)
            metadata = ref.file_metadata(2, b"p" * 7, 65536, 3, 1, b"s" * 32, descriptor)
            for kind in ("key", "file"):
                original = ref.wrap_aad(kind, metadata, 1)
                for index in range(len(metadata)):
                    with self.subTest(profile=profile, kind=kind, offset=index):
                        changed = bytearray(metadata)
                        changed[index] ^= 1
                        self.assertNotEqual(ref.wrap_aad(kind, bytes(changed), 1), original)

    def test_R09_both_wraps_bound(self):
        metadata = b"public fixture metadata"
        for kind in ("key", "file"):
            aad = ref.wrap_aad(kind, metadata, 1)
            original = ref.header(metadata, b"n" * 48, b"r" * 48)
            for index in range(len(metadata), len(original)):
                with self.subTest(kind=kind, offset=index):
                    changed = bytearray(original)
                    changed[index] ^= 1
                    self.assertNotEqual(ref.payload_aad(kind, bytes(changed)),
                                        ref.payload_aad(kind, original))
                    self.assertEqual(ref.wrap_aad(kind, bytes(changed[:len(metadata)]), 1), aad)

    def test_R10_rfc5869(self):
        expected = ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                    "34007208d5b887185865")
        actual = ref.hkdf_reference(bytes([11]) * 22, bytes(range(13)),
                                    bytes(range(240, 250)), 42, hashlib.sha256)
        self.assertEqual(actual.hex(), expected)
        for length in (0, -1, 8161, True):
            with self.subTest(length=length), self.assertRaises(ValueError):
                ref.hkdf_reference(b"", b"", b"", length)

    def test_R12_recovery_size(self):
        raw = bytes(range(32))
        text = ref.recovery_text(raw)
        self.assertEqual(len(text), 63)
        self.assertEqual(ref.recovery_parse(text), raw)
        for size in (0, 31, 33):
            with self.subTest(size=size), self.assertRaises(ValueError):
                ref.recovery_text(bytes(size))
        for changed in (text.replace(b"-1:", b"-2:"), text[:-1], text + b"\n"):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                ref.recovery_parse(changed)

    def test_R13_recovery_canonical(self):
        text = ref.recovery_text(bytes(32))
        # DE: AB= statt AA= hat unzulässige Pad-Bits. EN: AB= has nonzero pad bits.
        variants = [text[:-3] + b"B=\n", text.replace(b"\n", b"\r\n"),
                    b"\xef\xbb\xbf" + text, b" " + text, text + text,
                    text[:-2] + b"!\n", text[:-2] + b"\n", text[:-1] + b" "]
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                ref.recovery_parse(changed)

    def test_reference_kdf_boundaries(self):
        base = [1, b"p" * 7, 65536, 3, 1, b"s" * 16, b""]
        for position, lower, upper in ((2, 65536, 1048576), (3, 3, 10), (4, 1, 16)):
            for value in (lower - 1, lower, upper, upper + 1):
                args = list(base)
                args[position] = value
                with self.subTest(position=position, value=value):
                    if value in (lower, upper):
                        ref.file_metadata(*args)
                    else:
                        with self.assertRaises(ValueError):
                            ref.file_metadata(*args)
        for size in (15, 16, 64, 65):
            args = list(base)
            args[5] = bytes(size)
            with self.subTest(salt=size):
                if size in (16, 64):
                    ref.file_metadata(*args)
                else:
                    with self.assertRaises(ValueError):
                        ref.file_metadata(*args)


if __name__ == "__main__":
    unittest.main()
