"""Read-only GitHub publisher preflight regression tests."""
import unittest

from github_opencode_publisher_preflight import preflight


def proposal():
    return {
        "repository": "SpecterAoD/pqkeep",
        "base": "main",
        "base_sha": "a" * 40,
        "head": "opencode/issue-93-run-12345",
        "draft": True,
        "maintainer_can_modify": False,
        "issue_number": 93,
        "run_id": 12345,
        "method": "POST",
        "endpoint": "/repos/SpecterAoD/pqkeep/pulls",
    }


class GithubPreflightTests(unittest.TestCase):
    def check(self, branch_status=404, base_sha=None):
        calls = []
        def fake_get(path, token):
            calls.append(path)
            if path == "/branches/main":
                return 200, {"commit": {"sha": base_sha or "a" * 40}}
            return branch_status, {}
        result = preflight(proposal(), 93, 12345, "a" * 40,
                           "read-only-token", fake_get)
        return result, calls

    def test_new_branch(self):
        result, calls = self.check()
        self.assertTrue(result)
        self.assertEqual(calls, [
            "/branches/main", "/git/ref/heads/opencode/issue-93-run-12345",
        ])

    def test_existing_branch_denied(self):
        self.assertFalse(self.check(branch_status=200)[0])

    def test_changed_main_denied(self):
        self.assertFalse(self.check(base_sha="b" * 40)[0])

    def test_no_token_denied(self):
        self.assertFalse(preflight(
            proposal(), 93, 12345, "a" * 40, ""
        ))

    def test_unexpected_api_response_denied(self):
        self.assertFalse(self.check(branch_status=403)[0])

    def test_wrong_run_denied_before_network(self):
        def unexpected(*args):
            raise AssertionError("network must not be called")
        self.assertFalse(preflight(
            proposal(), 93, 1, "a" * 40, "token", unexpected
        ))


if __name__ == "__main__":
    unittest.main()
