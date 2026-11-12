"""Adversarial ZIP artifact extraction tests."""
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from extract_opencode_artifact import extract


class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / "input.zip"
        self.destination = self.root / "output.patch"

    def make_zip(self, members):
        with zipfile.ZipFile(self.archive, "w") as zf:
            for name, data in members:
                zf.writestr(name, data)

    def test_valid(self):
        self.make_zip([("proposal.patch", b"diff --git a/x b/x\n")])
        self.assertGreater(extract(self.archive, self.destination), 0)
        self.assertTrue(self.destination.exists())

    def test_traversal(self):
        self.make_zip([("../proposal.patch", b"payload")])
        with self.assertRaises(ValueError):
            extract(self.archive, self.destination)

    def test_multiple_files(self):
        self.make_zip([("proposal.patch", b"valid"), ("evil.sh", b"evil")])
        with self.assertRaises(ValueError):
            extract(self.archive, self.destination)

    def test_duplicate_members(self):
        self.make_zip([("proposal.patch", b"one"), ("proposal.patch", b"two")])
        with self.assertRaises(ValueError):
            extract(self.archive, self.destination)

    def test_symlink_member(self):
        info = zipfile.ZipInfo("proposal.patch")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(self.archive, "w") as zf:
            zf.writestr(info, b"../../etc/passwd")
        with self.assertRaises(ValueError):
            extract(self.archive, self.destination)

    def test_oversized_member(self):
        self.make_zip([("proposal.patch", b"x" * 100_001)])
        with self.assertRaises(ValueError):
            extract(self.archive, self.destination)

    def test_existing_destination(self):
        self.make_zip([("proposal.patch", b"valid")])
        self.destination.write_bytes(b"existing")
        with self.assertRaises(ValueError):
            extract(self.archive, self.destination)
        self.assertEqual(self.destination.read_bytes(), b"existing")

    def test_empty_patch(self):
        self.make_zip([("proposal.patch", b"")])
        with self.assertRaises(ValueError):
            extract(self.archive, self.destination)


if __name__ == "__main__":
    unittest.main()
