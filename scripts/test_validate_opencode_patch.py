"""Negative tests for strict AI patch path/status validation."""
import os
from unittest.mock import patch
import subprocess
import tempfile
from pathlib import Path
import unittest

from validate_opencode_patch import allowed_path, parse_changes, git


class PatchPolicyTests(unittest.TestCase):
    def test_validator_ignores_git_config_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            previous = os.getcwd()
            try:
                os.chdir(repo)
                with patch.dict(os.environ, {
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "alias.status",
                    "GIT_CONFIG_VALUE_0": "!false",
                }):
                    self.assertEqual(git("status", "--porcelain"), b"")
            finally:
                os.chdir(previous)


    def test_allowed_docs(self):
        self.assertTrue(allowed_path("docs/USER_GUIDE.md"))
        self.assertEqual(parse_changes(b"M\0docs/USER_GUIDE.md\0"), ["docs/USER_GUIDE.md"])

    def test_protected(self):
        for path in (
            ".github/workflows/ci.yml", "opencode.json", "Cargo.toml",
            "Cargo.lock", "src/lib.rs", "scripts/check_limits.sh",
            "docs/SPEC.md", "docs/CRYPTO.md", "docs/THREAT_MODEL.md",
            "docs/OPENCODE_AGENT_SECURITY_PLAN.md",
            "docs/OPENCODE_AGENT_ISOLATION.md",
            "docs/OPENCODE_AGENT_SECURITY_REVIEW.md",
            "docs/../src/lib.rs",
            "docs//guide.md", "docs/a\\b.md", "docs/evil\nname.md",
            "docs/ä.md", "docs/file.MD", "docs/file.md/other",
        ):
            with self.subTest(path=path):
                self.assertFalse(allowed_path(path))

    def test_reject_nonstandard_status(self):
        for status in (b"D", b"R100", b"C100", b"T", b"U", b"??"):
            with self.subTest(status=status):
                with self.assertRaises(ValueError):
                    parse_changes(status + b"\0docs/USER_GUIDE.md\0")

    def test_reject_malformed(self):
        for payload in (b"", b"M\0docs/USER_GUIDE.md", b"M\0"):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    parse_changes(payload)

    def test_reject_duplicate(self):
        with self.assertRaises(ValueError):
            parse_changes(
                b"M\0docs/USER_GUIDE.md\0A\0docs/user_guide.md\0"
            )

    def test_reject_too_many(self):
        data = b"".join(
            f"A\0docs/guide_{i}.md\0".encode() for i in range(11)
        )
        with self.assertRaises(ValueError):
            parse_changes(data)


if __name__ == "__main__":
    unittest.main()
