"""Offline outer GitHub artifact roundtrip and tamper rejection."""
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from build_opencode_github_artifact import build_outer
from publisher_opencode_preflight import preflight
from unpack_opencode_github_artifact import unpack
from verify_opencode_artifact import verify
from test_package_opencode_proposal import PATCH, BASE


class GithubArtifactBuildTests(unittest.TestCase):
    def test_complete_outer_to_inner_preflight(self):
        outer = build_outer(PATCH, 93, 123, BASE)
        self.assertEqual(outer, build_outer(PATCH, 93, 123, BASE))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "outer.zip").write_bytes(outer)
            (root / "issue.json").write_text('{"number":93}')
            manifest_path, inner_path = unpack(root / "outer.zip", root)
            manifest = json.loads(manifest_path.read_text())
            self.assertTrue(verify(
                manifest, inner_path.read_bytes(), {"number": 93}, 123, BASE,
            ))
            self.assertEqual(preflight(
                manifest_path, inner_path, root / "issue.json", 123, BASE,
            ), len(PATCH))

    def test_tampered_inner_is_rejected(self):
        outer = build_outer(PATCH, 93, 123, BASE)
        with zipfile.ZipFile(io.BytesIO(outer)) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            inner = bytearray(archive.read("proposal.zip"))
        inner[-1] ^= 1
        self.assertFalse(verify(manifest, bytes(inner), {"number": 93}, 123, BASE))

    def test_rejects_forbidden_path(self):
        with self.assertRaises(ValueError):
            build_outer(PATCH.replace(b"docs/guide.md", b"src/lib.rs"),
                        93, 123, BASE)

    def test_rejects_wrong_identifiers(self):
        for issue, run in ((True, 123), (93, True), (0, 123)):
            with self.subTest(issue=issue, run=run):
                with self.assertRaises(ValueError):
                    build_outer(PATCH, issue, run, BASE)

    def test_outer_contains_only_expected_members(self):
        with zipfile.ZipFile(io.BytesIO(build_outer(PATCH, 93, 123, BASE))) as zf:
            self.assertEqual(set(zf.namelist()), {
                "manifest.json", "proposal.zip",
            })


if __name__ == "__main__":
    unittest.main()
