"""Reject tampered and replayed event bindings."""
import unittest

from attest_opencode_event import sign, verify

KEY = b"test-key-not-a-production-secret-123456789"
OTHER = b"other-test-key-not-a-production-secret-123456"
RECORD = {
    "repository": "SpecterAoD/pqkeep",
    "workflow": ".github/workflows/opencode.yml",
    "run_id": 12345, "issue_number": 93, "comment_id": 42,
    "base_sha": "a" * 40, "event": "issue_comment",
    "actor_id": 77644070,
}


class AttestationTests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(verify(sign(RECORD.copy(), KEY), KEY, RECORD))

    def test_signed_binding_is_not_mutable_alias(self):
        original = RECORD.copy()
        envelope = sign(original, KEY)
        original["comment_id"] = 99
        self.assertEqual(envelope["binding"]["comment_id"], 42)
        self.assertTrue(verify(envelope, KEY, RECORD))

    def test_tampered_comment(self):
        envelope = sign(RECORD.copy(), KEY)
        envelope["binding"]["comment_id"] = 43
        self.assertFalse(verify(envelope, KEY, RECORD))

    def test_replayed_run(self):
        self.assertFalse(verify(
            sign(RECORD.copy(), KEY), KEY, dict(RECORD, run_id=12346)
        ))

    def test_replayed_issue(self):
        self.assertFalse(verify(
            sign(RECORD.copy(), KEY), KEY, dict(RECORD, issue_number=94)
        ))

    def test_other_base(self):
        self.assertFalse(verify(
            sign(RECORD.copy(), KEY), KEY, dict(RECORD, base_sha="b" * 40)
        ))

    def test_wrong_key(self):
        self.assertFalse(verify(sign(RECORD.copy(), KEY), OTHER, RECORD))

    def test_extra_field(self):
        with self.assertRaises(ValueError):
            sign(dict(RECORD, arbitrary="malicious"), KEY)

    def test_boolean_identity(self):
        with self.assertRaises(ValueError):
            sign(dict(RECORD, comment_id=True), KEY)

    def test_bad_signature(self):
        envelope = sign(RECORD.copy(), KEY)
        envelope["mac_sha256"] = "0" * 64
        self.assertFalse(verify(envelope, KEY, RECORD))

    def test_short_key(self):
        with self.assertRaises(ValueError):
            sign(RECORD.copy(), b"short")


if __name__ == "__main__":
    unittest.main()
