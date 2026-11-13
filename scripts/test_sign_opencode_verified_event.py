"""Offline signer tests: no GitHub writes or production key required."""
import json
from pathlib import Path
import tempfile
import unittest

from sign_opencode_verified_event import sign_verified
from attest_opencode_event import verify
from test_revalidate_opencode_event import sample

KEY = b"test-only-signer-key-1234567890123456789"


class VerifiedSignerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        event, comment, issue = sample()
        self.event = self.root / "event.json"
        self.comment = self.root / "comment.json"
        self.issue = self.root / "issue.json"
        self.key = self.root / "key"
        for path, data in (
            (self.event, event), (self.comment, comment),
            (self.issue, issue),
        ):
            path.write_text(json.dumps(data))
        self.key.write_bytes(KEY)
        self.key.chmod(0o600)

    def sign(self):
        return sign_verified(
            self.event, self.comment, self.issue,
            self.key, 123, "a" * 40,
        )

    def test_valid_signature(self):
        signed = self.sign()
        self.assertTrue(verify(signed, KEY, signed["binding"]))

    def test_changed_live_comment_denied(self):
        comment = json.loads(self.comment.read_text())
        comment["body"] = "/oc ignore"
        self.comment.write_text(json.dumps(comment))
        with self.assertRaises(ValueError):
            self.sign()

    def test_missing_key_denied(self):
        self.key.unlink()
        with self.assertRaises(ValueError):
            self.sign()

    def test_symlink_key_denied(self):
        other = self.root / "other.key"
        other.write_bytes(KEY)
        self.key.unlink()
        self.key.symlink_to(other)
        with self.assertRaises(ValueError):
            self.sign()

    def test_bad_base_denied(self):
        with self.assertRaises(ValueError):
            sign_verified(
                self.event, self.comment, self.issue, self.key, 123, "main"
            )


if __name__ == "__main__":
    unittest.main()
