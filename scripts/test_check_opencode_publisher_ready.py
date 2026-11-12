"""Combined publisher readiness gate tests without real network access."""
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from check_opencode_publisher_ready import check
from verify_opencode_issue import snapshot


def proposal():
    return {
        "repository": "SpecterAoD/pqkeep",
        "base": "main", "base_sha": "a" * 40,
        "head": "opencode/issue-93-run-12345",
        "draft": True, "maintainer_can_modify": False,
        "issue_number": 93, "run_id": 12345,
        "method": "POST",
        "endpoint": "/repos/SpecterAoD/pqkeep/pulls",
    }


def github_get(path, token):
    if path == "/actions/runs/12345/artifacts?per_page=100&page=1":
        return 200, {"total_count": 1, "artifacts": [{
            "id": 456, "name": "opencode-issue-93-run-12345",
            "expired": False, "size_in_bytes": 1000,
            "workflow_run": {"id": 12345, "head_sha": "a" * 40,
                             "repository_id": 77},
        }]}
    if path == "/actions/runs/12345":
        return 200, {
            "id": 12345, "event": "issue_comment", "status": "completed",
            "conclusion": "success", "path": ".github/workflows/opencode.yml",
            "head_sha": "a" * 40, "actor": {"id": 77644070},
            "triggering_actor": {"id": 77644070},
            "repository": {"full_name": "SpecterAoD/pqkeep"},
            "head_repository": {"full_name": "SpecterAoD/pqkeep"},
        }
    if path == "/issues/comments/42":
        return 200, {"id": 42, "user": {"id": 77644070},
                     "body": "/oc", "created_at": "2026-11-13T00:00:00Z",
                     "updated_at": "2026-11-13T00:00:00Z",
                     "issue_url": "https://api.github.com/repos/SpecterAoD/pqkeep/issues/93"}
    if path == "/issues/93":
        return 200, {"number": 93, "user": {"id": 77644070},
                     "title": "Safe documentation", "body": "Document flow",
                     "updated_at": "2026-11-13T00:00:00Z"}
    if path == "/branches/main":
        return 200, {"commit": {"sha": "a" * 40}}
    return 404, {}


class CombinedGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.snapshot = Path(self.temp.name) / "issue.json"
        self.snapshot.write_text(__import__("json").dumps(snapshot(
            github_get("/issues/93", "token")[1], "SpecterAoD/pqkeep"
        )), encoding="utf-8")

    @patch("check_opencode_publisher_ready.review_proposal")
    def test_valid_checks_patch(self, review):
        review.return_value = ["docs/guide.md"]
        result = check(None, None, None, self.snapshot, proposal(),
                       93, 12345, "a" * 40, "read-token", 456, github_get, expected_comment_id=42)
        self.assertEqual(result, ["docs/guide.md"])
        review.assert_called_once()

    @patch("check_opencode_publisher_ready.review_proposal")
    def test_changed_main_blocks_before_patch(self, review):
        def changed(path, token):
            if path == "/branches/main":
                return 200, {"commit": {"sha": "b" * 40}}
            return 404, {}
        with self.assertRaises(ValueError):
            check(None, None, None, None, proposal(),
                  93, 12345, "a" * 40, "read-token", 456, changed, expected_comment_id=42)
        review.assert_not_called()

    @patch("check_opencode_publisher_ready.review_proposal")
    def test_existing_branch_blocks_before_patch(self, review):
        def existing(path, token):
            if path == "/branches/main":
                return 200, {"commit": {"sha": "a" * 40}}
            return 200, {"ref": "refs/heads/opencode/issue-93-run-12345"}
        with self.assertRaises(ValueError):
            check(None, None, None, None, proposal(),
                  93, 12345, "a" * 40, "read-token", 456, existing, expected_comment_id=42)
        review.assert_not_called()

    @patch("check_opencode_publisher_ready.review_proposal")
    def test_non_draft_blocks_before_patch(self, review):
        data = proposal()
        data["draft"] = False
        with self.assertRaises(ValueError):
            check(None, None, None, None, data,
                  93, 12345, "a" * 40, "read-token", 456, github_get)
        review.assert_not_called()

    @patch("check_opencode_publisher_ready.review_proposal")
    def test_invalid_issue_type_blocks(self, review):
        with self.assertRaises(ValueError):
            check(None, None, None, None, proposal(),
                  True, 12345, "a" * 40, "read-token", github_get)
        review.assert_not_called()

    @patch("check_opencode_publisher_ready.review_proposal")
    def test_wrong_issue_snapshot_denied(self, review):
        self.snapshot.write_text('{"number": 94}', encoding="utf-8")
        with self.assertRaises(ValueError):
            check(None, None, None, self.snapshot, proposal(),
                  93, 12345, "a" * 40, "read-token", 456, github_get)
        review.assert_not_called()

    @patch("check_opencode_publisher_ready.review_proposal")
    def test_issue_modified_on_github_denied(self, review):
        def modified(path, token):
            status, data = github_get(path, token)
            if path == "/issues/93":
                data = dict(data, body="Modified after agent run")
            return status, data
        with self.assertRaises(ValueError):
            check(None, None, None, self.snapshot, proposal(),
                  93, 12345, "a" * 40, "read-token", 456, modified)
        review.assert_not_called()

    @patch("check_opencode_publisher_ready.review_proposal")
    def test_patch_failure_is_propagated(self, review):
        review.side_effect = ValueError("forbidden source change")
        with self.assertRaises(ValueError):
            check(None, None, None, None, proposal(),
                  93, 12345, "a" * 40, "read-token", github_get)


if __name__ == "__main__":
    unittest.main()
