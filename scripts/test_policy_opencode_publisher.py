"""Publisher policy must never authorize merges or existing branches."""
import copy
import unittest

from policy_opencode_publisher import authorized_publication


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


def allowed(data, branch_exists=False):
    return authorized_publication(data, 93, 12345, "a" * 40, branch_exists)


class PublisherPolicyTests(unittest.TestCase):
    def test_valid_new_draft(self):
        self.assertTrue(allowed(proposal()))

    def test_existing_branch_denied(self):
        self.assertFalse(allowed(proposal(), True))

    def test_main_head_denied(self):
        data = proposal()
        data["head"] = "main"
        self.assertFalse(allowed(data))

    def test_wrong_issue_or_run_denied(self):
        for key, value in (("issue_number", 94), ("run_id", 1)):
            data = proposal()
            data[key] = value
            self.assertFalse(allowed(data))

    def test_non_draft_denied(self):
        data = proposal()
        data["draft"] = False
        self.assertFalse(allowed(data))

    def test_wrong_base_denied(self):
        data = proposal()
        data["base"] = "release"
        self.assertFalse(allowed(data))

    def test_merge_endpoint_denied(self):
        data = proposal()
        data["endpoint"] = "/repos/SpecterAoD/pqkeep/pulls/171/merge"
        self.assertFalse(allowed(data))

    def test_patch_method_denied(self):
        data = proposal()
        data["method"] = "PATCH"
        self.assertFalse(allowed(data))

    def test_extra_field_denied(self):
        data = proposal()
        data["force"] = True
        self.assertFalse(allowed(data))

    def test_boolean_run_denied(self):
        data = proposal()
        data["run_id"] = True
        self.assertFalse(allowed(data))

    def test_foreign_repo_denied(self):
        data = proposal()
        data["repository"] = "other/pqkeep"
        self.assertFalse(allowed(data))

    def test_wrong_base_sha_denied(self):
        data = proposal()
        data["base_sha"] = "b" * 40
        self.assertFalse(allowed(data))


if __name__ == "__main__":
    unittest.main()
