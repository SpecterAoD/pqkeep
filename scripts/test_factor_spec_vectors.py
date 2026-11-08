"""DE: R11: öffentliche KAT-Daten, unabhängig mit cryptography 41.0.7 berechnet.
EN: R11: public KAT data, independently calculated with cryptography 41.0.7.
No cryptography dependency is needed to run these tests.
"""

import unittest

import factor_spec_reference as ref


EXPECTED = {
    ("key", "file"): "de825c738bfa2986f06528fbcac1ff9eb886841ecedd235464dfd3c3e36dfc7f",
    ("key", "tpm"): "1f214567257844a2eb4f16d8a13c57134103454e2889d5435acbe7ff090c78af",
    ("key", "fido2"): "9baa7ca44ddf25112b2afc66eb29411e0559d2667cb5dee018aa895fba06fe6a",
    ("key", "recovery"): "7fa300fee2b9cb529a2eba831b2146ff98c07cf8cfd076dbcb43f14cca6fe4c6",
    ("file", "file"): "a266dba3c9a5746b5973e6f4462c38ed40c280fd23eefc2df683f5c1ffadd594",
    ("file", "tpm"): "38f3bf927ab8e61f12a13d207347d7d5eebe77ad96807575e2534644366c94c6",
    ("file", "fido2"): "491cf21a282959856f4db7d2eecc59ef73b51e8904c7b8b94b2bc8e2dd08e29b",
    ("file", "recovery"): "0ca82b93986beffe1fee95185c28a94f549f080f5305911609f11cb89e11f6e1",
}


class FactorVectorTests(unittest.TestCase):
    def test_R11_independent_hkdf_vectors(self):
        # DE: Zur Laufzeit erzeugte öffentliche Testbytes, keine echten Geheimnisse.
        # EN: Runtime-generated public test bytes, never real secrets.
        base, salt = bytes(range(32)), bytes(range(32, 64))
        extras = {"file": b"", "tpm": bytes(range(64, 96)),
                  "fido2": bytes(range(96, 128)), "recovery": bytes(range(128, 160))}
        outputs = []
        for (kind, role), expected in EXPECTED.items():
            with self.subTest(kind=kind, role=role):
                info = ref.domain(kind) + b"wrap/" + role.encode() + b"\0"
                output = ref.hkdf_reference(base + extras[role], salt, info)
                self.assertEqual(output.hex(), expected)
                outputs.append(output)
        self.assertEqual(len(set(outputs)), 8)


if __name__ == "__main__":
    unittest.main()
