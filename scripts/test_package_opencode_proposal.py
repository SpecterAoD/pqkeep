"""Round-trip offline proposal packaging into the existing verifier."""
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from package_opencode_proposal import package
from publisher_opencode_preflight import preflight
from verify_opencode_artifact import verify

BASE = "a" * 40
PATCH = (
    b"diff --git a/docs/guide.md b/docs/guide.md\n"
    b"index 1111111..2222222 100644\n"
    b"--- a/docs/guide.md\n+++ b/docs/guide.md\n"
    b"@@ -1 +1 @@\n-before\n+after\n"
)


class ProposalPackagingTests(unittest.TestCase):
    def test_roundtrip_through_publisher_preflight(self):
        data, encoded = package(PATCH, 93, 123, BASE)
        self.assertEqual(package(PATCH, 93, 123, BASE), (data, encoded))
        manifest = json.loads(encoded)
        self.assertTrue(verify(manifest, data, {"number": 93}, 123, BASE))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_bytes(encoded)
            (root / "proposal.zip").write_bytes(data)
            (root / "issue.json").write_text('{"number":93}')
            self.assertEqual(preflight(
                root / "manifest.json", root / "proposal.zip",
                root / "issue.json", 123, BASE,
            ), len(PATCH))
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(archive.namelist(), ["proposal.patch"])
            self.assertEqual(archive.read("proposal.patch"), PATCH)

    def test_source_patch_rejected(self):
        with self.assertRaises(ValueError):
            package(PATCH.replace(b"docs/guide.md", b"src/lib.rs"), 93, 123, BASE)

    def test_boolean_identifiers_rejected(self):
        for issue, run in ((True, 123), (93, True), (0, 123), (93, 0)):
            with self.subTest(issue=issue, run=run):
                with self.assertRaises(ValueError):
                    package(PATCH, issue, run, BASE)

    def test_wrong_base_rejected(self):
        with self.assertRaises(ValueError):
            package(PATCH, 93, 123, "main")

    def test_manifest_tampering_rejected(self):
        data, encoded = package(PATCH, 93, 123, BASE)
        manifest = json.loads(encoded)
        manifest["artifact_sha256"] = "0" * 64
        self.assertFalse(verify(manifest, data, {"number": 93}, 123, BASE))


if __name__ == "__main__":
    unittest.main()
