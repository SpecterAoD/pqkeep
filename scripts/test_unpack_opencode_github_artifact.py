"""Adversarial tests for the outer GitHub artifact ZIP."""
import io
from pathlib import Path
import tempfile
import unittest
import zipfile

from unpack_opencode_github_artifact import unpack


class OuterArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.outer = self.root / "github.zip"
        self.output = self.root / "out"
        self.output.mkdir()

    def build(self, entries):
        with zipfile.ZipFile(self.outer, "w") as archive:
            for name, data in entries:
                archive.writestr(name, data)

    def valid(self):
        return [("manifest.json", b'{"test":true}'),
                ("proposal.zip", b"fake inner zip bytes")]

    def test_valid(self):
        self.build(self.valid())
        manifest, inner = unpack(self.outer, self.output)
        self.assertEqual(manifest.read_bytes(), b'{"test":true}')
        self.assertEqual(inner.read_bytes(), b"fake inner zip bytes")

    def test_traversal(self):
        self.build([("../manifest.json", b"x"),
                    ("proposal.zip", b"y")])
        with self.assertRaises(ValueError):
            unpack(self.outer, self.output)

    def test_extra_member(self):
        self.build(self.valid() + [("secret.txt", b"x")])
        with self.assertRaises(ValueError):
            unpack(self.outer, self.output)

    def test_duplicate_member(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            self.build([("manifest.json", b"a"),
                        ("manifest.json", b"b")])
        with self.assertRaises(ValueError):
            unpack(self.outer, self.output)

    def test_oversized_manifest(self):
        self.build([("manifest.json", b"x" * 4097),
                    ("proposal.zip", b"y")])
        with self.assertRaises(ValueError):
            unpack(self.outer, self.output)

    def test_existing_output(self):
        self.build(self.valid())
        (self.output / "manifest.json").write_bytes(b"existing")
        with self.assertRaises(ValueError):
            unpack(self.outer, self.output)

    def test_bad_zip(self):
        self.outer.write_bytes(b"not zip")
        with self.assertRaises(zipfile.BadZipFile):
            unpack(self.outer, self.output)


if __name__ == "__main__":
    unittest.main()
