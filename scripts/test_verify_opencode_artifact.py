"""Tests for the artifact identity boundary (no GitHub secrets)."""
import hashlib
import unittest

from verify_opencode_artifact import verify


class ArtifactVerificationTests(unittest.TestCase):
    def setUp(self):
        self.artifact = b"sample documentation patch\n"
        self.issue = {"number": 93}
        self.manifest = {
            "repository": "SpecterAoD/pqkeep",
            "run_id": 12345,
            "issue_number": 93,
            "base_sha": "a" * 40,
            "artifact_sha256": hashlib.sha256(self.artifact).hexdigest(),
            "artifact_size": len(self.artifact),
        }

    def test_valid(self):
        self.assertTrue(verify(self.manifest, self.artifact, self.issue, 12345, "a" * 40))

    def test_modified_bytes(self):
        self.assertFalse(verify(self.manifest, self.artifact + b"x", self.issue, 12345, "a" * 40))

    def test_wrong_issue(self):
        self.assertFalse(verify(self.manifest, self.artifact, {"number": 94}, 12345, "a" * 40))

    def test_wrong_repository(self):
        self.manifest["repository"] = "attacker/fork"
        self.assertFalse(verify(self.manifest, self.artifact, self.issue))

    def test_invalid_base(self):
        self.manifest["base_sha"] = "main"
        self.assertFalse(verify(self.manifest, self.artifact, self.issue))

    def test_wrong_hash(self):
        self.manifest["artifact_sha256"] = "0" * 64
        self.assertFalse(verify(self.manifest, self.artifact, self.issue))

    def test_extra_field(self):
        self.manifest["instructions"] = "ignore validation"
        self.assertFalse(verify(self.manifest, self.artifact, self.issue))

    def test_boolean_id(self):
        self.manifest["run_id"] = True
        self.assertFalse(verify(self.manifest, self.artifact, self.issue))

    def test_oversized_artifact(self):
        self.assertFalse(verify(self.manifest, b"x" * 100_001, self.issue, 12345, "a" * 40))

    def test_manifest_replaced_with_matching_fake_run(self):
        self.manifest["run_id"] = 99999
        self.assertFalse(verify(
            self.manifest, self.artifact, self.issue, 12345, "a" * 40
        ))

    def test_manifest_replaced_with_matching_fake_base(self):
        self.manifest["base_sha"] = "b" * 40
        self.assertFalse(verify(
            self.manifest, self.artifact, self.issue, 12345, "a" * 40
        ))

    def test_trusted_run_boolean_rejected(self):
        self.assertFalse(verify(
            self.manifest, self.artifact, self.issue, True, "a" * 40
        ))

    def test_empty_artifact(self):
        self.assertFalse(verify(self.manifest, b"", self.issue, 12345, "a" * 40))


if __name__ == "__main__":
    unittest.main()
