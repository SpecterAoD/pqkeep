"""Integration tests for disposable-worktree AI patch review."""
import os
from unittest.mock import patch
from pathlib import Path
import subprocess
import tempfile
import unittest

from review_opencode_patch import review_patch


class ReviewPatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "guide.md").write_text("before\n")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.patch = Path(self.tmp.name) / "proposal.patch"

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *args],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()

    def make_patch(self, path="docs/guide.md", content="after\n"):
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content)
        self.patch.write_bytes(subprocess.check_output(
            ["git", "-C", str(self.repo), "diff", "--", path]
        ))
        self.git("checkout", "--", path) if path == "docs/guide.md" else file.unlink()

    def test_valid_patch(self):
        self.make_patch()
        self.assertEqual(
            review_patch(self.repo, self.patch, self.base), ["docs/guide.md"]
        )
        self.assertEqual(self.git("rev-parse", "HEAD"), self.base)
        self.assertEqual((self.repo / "docs" / "guide.md").read_text(), "before\n")

    def test_inherited_git_config_is_ignored(self):
        self.make_patch()
        with tempfile.TemporaryDirectory() as tmp:
            injected = Path(tmp) / "global.gitconfig"
            injected.write_text(
                "[user]\\n\\tname = Injected\\n\\temail = attacker@example.invalid\\n"
            )
            with patch.dict(os.environ, {
                "GIT_CONFIG_GLOBAL": str(injected),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.hooksPath",
                "GIT_CONFIG_VALUE_0": str(Path(tmp) / "hooks"),
            }):
                self.assertEqual(
                    review_patch(self.repo, self.patch, self.base),
                    ["docs/guide.md"],
                )

    def test_reject_source_patch(self):
        # New source file is staged only for creating a diff, never committed.
        file = self.repo / "src" / "lib.rs"
        file.parent.mkdir()
        file.write_text("fn main() {}\n")
        self.git("add", "src/lib.rs")
        self.patch.write_bytes(subprocess.check_output(
            ["git", "-C", str(self.repo), "diff", "--cached", "--", "src/lib.rs"]
        ))
        self.git("reset", "-q", "HEAD", "--", "src/lib.rs")
        file.unlink()
        with self.assertRaises(ValueError):
            review_patch(self.repo, self.patch, self.base)

    def test_reject_malformed_patch(self):
        self.patch.write_bytes(b"not a git patch\n")
        with self.assertRaises(subprocess.CalledProcessError):
            review_patch(self.repo, self.patch, self.base)

    def test_reject_wrong_base(self):
        self.make_patch()
        with self.assertRaises(ValueError):
            review_patch(self.repo, self.patch, "main")

    def test_reject_oversized_patch(self):
        self.patch.write_bytes(b"x" * 100_001)
        with self.assertRaises(ValueError):
            review_patch(self.repo, self.patch, self.base)


if __name__ == "__main__":
    unittest.main()
