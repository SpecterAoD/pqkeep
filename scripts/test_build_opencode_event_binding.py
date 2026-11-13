"""Test binding construction from independently revalidated GitHub data."""
import copy
import unittest

from build_opencode_event_binding import build_binding
from test_revalidate_opencode_event import sample


class BuildBindingTests(unittest.TestCase):
    def test_valid_binding(self):
        event, comment, issue = sample()
        result = build_binding(event, comment, issue, 123, "a" * 40)
        self.assertEqual(result["issue_number"], 93)
        self.assertEqual(result["comment_id"], 1001)
        self.assertEqual(result["run_id"], 123)
        self.assertEqual(result["base_sha"], "a" * 40)

    def test_reject_foreign_comment(self):
        event, comment, issue = sample()
        comment["issue_url"] = comment["issue_url"].replace("/93", "/94")
        with self.assertRaises(ValueError):
            build_binding(event, comment, issue, 123, "a" * 40)

    def test_reject_modified_issue(self):
        event, comment, issue = sample()
        issue["body"] = "injected"
        with self.assertRaises(ValueError):
            build_binding(event, comment, issue, 123, "a" * 40)

    def test_reject_invalid_run_and_sha(self):
        event, comment, issue = sample()
        for run in (0, True, -1, "123"):
            with self.subTest(run=run), self.assertRaises(ValueError):
                build_binding(event, comment, issue, run, "a" * 40)
        for sha in ("main", "a" * 39, "A" * 40):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                build_binding(event, comment, issue, 123, sha)


if __name__ == "__main__":
    unittest.main()
