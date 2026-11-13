"""Offline event-binding gate regression tests."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from attest_opencode_event import sign
from verify_opencode_event_binding import verify_files

KEY = b"local-test-key-with-adequate-length-123456"
EVENT = {
    "repository": "SpecterAoD/pqkeep",
    "workflow": ".github/workflows/opencode.yml",
    "run_id": 12345,
    "issue_number": 93,
    "comment_id": 42,
    "base_sha": "a" * 40,
    "event": "issue_comment",
    "actor_id": 77644070,
}


class EventBindingGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.envelope = root / "envelope.json"
        self.expected = root / "expected.json"
        self.key = root / "secret.key"
        self.envelope.write_text(json.dumps(sign(EVENT.copy(), KEY)))
        self.expected.write_text(json.dumps(EVENT))
        self.key.write_bytes(KEY)
        self.key.chmod(0o600)

    def check(self):
        return verify_files(self.envelope, self.expected, self.key)

    def test_valid(self):
        self.assertTrue(self.check())

    def test_modified_expected_run(self):
        self.expected.write_text(json.dumps(dict(EVENT, run_id=12346)))
        self.assertFalse(self.check())

    def test_modified_expected_comment(self):
        self.expected.write_text(json.dumps(dict(EVENT, comment_id=43)))
        self.assertFalse(self.check())

    def test_tampered_signed_binding(self):
        envelope = json.loads(self.envelope.read_text())
        envelope["binding"]["issue_number"] = 94
        self.envelope.write_text(json.dumps(envelope))
        self.assertFalse(self.check())

    def test_wrong_key(self):
        self.key.write_bytes(b"another-test-key-with-adequate-length-1234")
        self.assertFalse(self.check())

    def test_key_symlink(self):
        other = self.key.parent / "other.key"
        other.write_bytes(KEY)
        self.key.unlink()
        self.key.symlink_to(other)
        self.assertFalse(self.check())

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_world_readable_key(self):
        self.key.chmod(0o644)
        self.assertFalse(self.check())

    def test_oversized_envelope(self):
        self.envelope.write_bytes(b"x" * 4097)
        self.assertFalse(self.check())

    def test_malformed_json(self):
        self.expected.write_text("{")
        self.assertFalse(self.check())

    def test_missing_expected(self):
        self.expected.unlink()
        self.assertFalse(self.check())


if __name__ == "__main__":
    unittest.main()
