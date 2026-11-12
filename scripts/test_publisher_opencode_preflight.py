"""End-to-end offline tests for artifact identity + ZIP extraction."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from publisher_opencode_preflight import preflight


class PublisherPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / "proposal.zip"
        self.manifest = self.root / "manifest.json"
        self.issue = self.root / "issue.json"
        self.issue.write_text(json.dumps({"number": 93}), encoding="utf-8")
        self.build([("proposal.patch", b"diff --git a/docs/a.md b/docs/a.md\n")])

    def build(self, entries):
        with zipfile.ZipFile(self.archive, "w") as zf:
            for name, content in entries:
                zf.writestr(name, content)
        data = self.archive.read_bytes()
        self.manifest.write_text(json.dumps({
            "repository": "SpecterAoD/pqkeep",
            "run_id": 12345,
            "issue_number": 93,
            "base_sha": "a" * 40,
            "artifact_sha256": hashlib.sha256(data).hexdigest(),
            "artifact_size": len(data),
        }), encoding="utf-8")

    def check(self):
        return preflight(
            self.manifest, self.archive, self.issue, 12345, "a" * 40
        )

    def test_valid_archive(self):
        self.assertGreater(self.check(), 0)

    def test_tampered_archive(self):
        self.archive.write_bytes(self.archive.read_bytes() + b"x")
        with self.assertRaises(ValueError):
            self.check()

    def test_fake_run_with_matching_hash(self):
        payload = json.loads(self.manifest.read_text())
        payload["run_id"] = 999
        self.manifest.write_text(json.dumps(payload))
        with self.assertRaises(ValueError):
            self.check()

    def test_fake_base_with_matching_hash(self):
        payload = json.loads(self.manifest.read_text())
        payload["base_sha"] = "b" * 40
        self.manifest.write_text(json.dumps(payload))
        with self.assertRaises(ValueError):
            self.check()

    def test_traversal_with_valid_hash(self):
        self.build([("../proposal.patch", b"bad")])
        with self.assertRaises(ValueError):
            self.check()

    def test_multiple_files_with_valid_hash(self):
        self.build([
            ("proposal.patch", b"good"), ("secret.txt", b"bad"),
        ])
        with self.assertRaises(ValueError):
            self.check()


if __name__ == "__main__":
    unittest.main()
