"""Regression tests: preflight must never execute AI or receive secrets."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "opencode.yml"


class SafeHoldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        # Comments are documentation, not executable workflow configuration.
        cls.active = "\n".join(
            line for line in cls.source.splitlines()
            if not line.lstrip().startswith("#")
        )

    def test_exact_trigger(self):
        self.assertIn("issue_comment:", self.active)
        self.assertIn("types: [created]", self.active)
        self.assertIn("github.event.comment.body == '/oc'", self.active)
        self.assertIn("github.event.sender.id == 77644070", self.active)

    def test_no_write_permissions(self):
        self.assertIn("permissions: {}", self.active)
        self.assertIn("contents: read", self.active)
        self.assertIn("issues: read", self.active)
        self.assertNotIn("contents: write", self.active)
        self.assertNotIn("pull-requests: write", self.active)

    def test_no_ai_execution_or_secret(self):
        for forbidden in (
            "GEMINI_API_KEY:", "OPENROUTER_API_KEY:",
            "opencode run", "gh pr create", "git push",
            "pull_request_target:", "workflow_run:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.active)

    def test_checkout_credentials_not_persisted(self):
        self.assertIn("persist-credentials: false", self.active)
        self.assertIn("scripts/revalidate_opencode_event.py", self.active)


if __name__ == "__main__":
    unittest.main()
