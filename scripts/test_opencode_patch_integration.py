"""End-to-end tests for the committed AI patch security boundary."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from validate_opencode_patch import validate


class GitPatchIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Security Test")
        self.write("docs/guide.md", "before\n")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(
            ["git", *args], cwd=self.root, stderr=subprocess.DEVNULL
        ).decode()

    def write(self, name, content):
        file = self.root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf-8")

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "candidate")

    def check(self):
        with patch.dict(os.environ, {}, clear=False):
            old = Path.cwd()
            try:
                os.chdir(self.root)
                return validate(self.base)
            finally:
                os.chdir(old)

    def test_valid_documentation(self):
        self.write("docs/guide.md", "after\n")
        self.commit()
        self.assertEqual(self.check(), ["docs/guide.md"])

    def test_reject_source_code(self):
        self.write("src/lib.rs", "fn backdoor() {}\n")
        self.commit()
        with self.assertRaises(ValueError):
            self.check()

    def test_reject_security_document(self):
        self.write("docs/CRYPTO.md", "changed\n")
        self.commit()
        with self.assertRaises(ValueError):
            self.check()

    def test_reject_symlink(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        os.symlink("guide.md", self.root / "docs" / "link.md")
        self.commit()
        with self.assertRaises(ValueError):
            self.check()

    def test_reject_executable(self):
        self.write("docs/new.md", "text\n")
        (self.root / "docs/new.md").chmod(0o755)
        self.commit()
        with self.assertRaises(ValueError):
            self.check()

    def test_reject_untracked_file(self):
        self.write("docs/guide.md", "after\n")
        self.commit()
        self.write("docs/untracked.md", "not committed\n")
        with self.assertRaises(ValueError):
            self.check()

    def test_reject_multi_commit(self):
        self.write("docs/guide.md", "after\n")
        self.commit()
        self.write("docs/guide.md", "again\n")
        self.commit()
        with self.assertRaises(ValueError):
            self.check()

    def test_reject_delete(self):
        (self.root / "docs/guide.md").unlink()
        self.commit()
        with self.assertRaises(ValueError):
            self.check()


if __name__ == "__main__":
    unittest.main()
