"""End-to-end tests for artifact-to-disposable-worktree validation."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from review_opencode_proposal import review


class FullReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "guide.md").write_text("before\n")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.archive = self.root / "artifact.zip"
        self.manifest = self.root / "manifest.json"
        self.issue = self.root / "issue.json"
        self.issue.write_text(json.dumps({"number": 93}))
        self.make_patch()

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *args],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()

    def make_patch(self, forbidden=False):
        if forbidden:
            path = self.repo / "src" / "lib.rs"
            path.parent.mkdir(exist_ok=True)
            path.write_text("fn bad() {}\n")
            self.git("add", "src/lib.rs")
            patch = subprocess.check_output([
                "git", "-C", str(self.repo), "diff", "--cached",
            ])
            self.git("reset", "-q", "HEAD", "--", "src/lib.rs")
            path.unlink()
        else:
            path = self.repo / "docs" / "guide.md"
            path.write_text("after\n")
            patch = subprocess.check_output([
                "git", "-C", str(self.repo), "diff",
            ])
            self.git("checkout", "--", "docs/guide.md")
        with zipfile.ZipFile(self.archive, "w") as zf:
            zf.writestr("proposal.patch", patch)
        payload = self.archive.read_bytes()
        self.manifest.write_text(json.dumps({
            "repository": "SpecterAoD/pqkeep", "run_id": 12345,
            "issue_number": 93, "base_sha": self.base,
            "artifact_sha256": hashlib.sha256(payload).hexdigest(),
            "artifact_size": len(payload),
        }))

    def check(self):
        return review(
            self.repo, self.manifest, self.archive, self.issue,
            12345, self.base,
        )

    def test_valid(self):
        self.assertEqual(self.check(), ["docs/guide.md"])
        self.assertEqual(self.git("rev-parse", "HEAD"), self.base)

    def test_forbidden_source_even_with_valid_hash(self):
        self.make_patch(forbidden=True)
        with self.assertRaises(ValueError):
            self.check()

    def test_swapped_artifact(self):
        self.archive.write_bytes(self.archive.read_bytes() + b"bad")
        with self.assertRaises(ValueError):
            self.check()

    def test_wrong_trusted_base(self):
        with self.assertRaises(ValueError):
            review(
                self.repo, self.manifest, self.archive, self.issue,
                12345, "b" * 40,
            )

    def test_wrong_trusted_run(self):
        with self.assertRaises(ValueError):
            review(
                self.repo, self.manifest, self.archive, self.issue,
                999, self.base,
            )


if __name__ == "__main__":
    unittest.main()
