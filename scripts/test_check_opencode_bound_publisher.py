"""Publisher must deny unbound or replayed requests before any API access."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from attest_opencode_event import sign
from check_opencode_bound_publisher import check_bound

KEY = b"offline-only-test-key-1234567890123456789"
IDENTITY = {
    "repository": "SpecterAoD/pqkeep",
    "workflow": ".github/workflows/opencode.yml",
    "run_id": 123, "issue_number": 93, "comment_id": 456,
    "base_sha": "a" * 40, "event": "issue_comment", "actor_id": 77644070,
}


class BoundPublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.envelope = root / "signed.json"
        self.expected = root / "expected.json"
        self.key = root / "key"
        self.envelope.write_text(json.dumps(sign(IDENTITY, KEY)))
        self.expected.write_text(json.dumps(IDENTITY))
        self.key.write_bytes(KEY)
        self.key.chmod(0o600)
        self.root = root

    def invoke(self, **changes):
        arguments = dict(
            repository=self.root, manifest=self.root / "manifest",
            archive=self.root / "archive", issue_snapshot=self.root / "issue",
            proposal={}, issue_number=93, run_id=123,
            base_sha="a" * 40, read_token="test", artifact_id=777,
            comment_id=456, envelope_path=self.envelope,
            expected_path=self.expected, key_path=self.key,
        )
        arguments.update(changes)
        return check_bound(**arguments)

    @patch("check_opencode_bound_publisher.check")
    def test_valid_binding_reaches_read_only_preflight(self, check):
        check.return_value = ["docs/guide.md"]
        self.assertEqual(self.invoke(), ["docs/guide.md"])
        check.assert_called_once()

    @patch("check_opencode_bound_publisher.check")
    def test_tampered_binding_denied_before_preflight(self, check):
        envelope = json.loads(self.envelope.read_text())
        envelope["binding"]["comment_id"] = 999
        self.envelope.write_text(json.dumps(envelope))
        with self.assertRaises(ValueError):
            self.invoke()
        check.assert_not_called()

    @patch("check_opencode_bound_publisher.check")
    def test_replayed_run_denied_before_preflight(self, check):
        with self.assertRaises(ValueError):
            self.invoke(run_id=124)
        check.assert_not_called()

    @patch("check_opencode_bound_publisher.check")
    def test_replayed_comment_denied_before_preflight(self, check):
        with self.assertRaises(ValueError):
            self.invoke(comment_id=457)
        check.assert_not_called()

    @patch("check_opencode_bound_publisher.check")
    def test_replayed_base_denied_before_preflight(self, check):
        with self.assertRaises(ValueError):
            self.invoke(base_sha="b" * 40)
        check.assert_not_called()

    @patch("check_opencode_bound_publisher.check")
    def test_missing_key_denied_before_preflight(self, check):
        self.key.unlink()
        with self.assertRaises(ValueError):
            self.invoke()
        check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
