"""Adversarial tests for a GitHub /oc trigger comment."""
import unittest

from verify_opencode_trigger_comment import verify_comment


def valid():
    return {
        "id": 42, "user": {"id": 77644070},
        "body": "/oc", "created_at": "2026-11-13T00:00:00Z",
        "updated_at": "2026-11-13T00:00:00Z",
        "issue_url": "https://api.github.com/repos/SpecterAoD/pqkeep/issues/93",
    }


class TriggerCommentTests(unittest.TestCase):
    def check(self, record, status=200):
        return verify_comment(
            93, 42, "read-token", lambda path, token: (status, record)
        )

    def test_valid(self):
        self.assertTrue(self.check(valid()))

    def test_edited_body(self):
        data = valid()
        data["body"] = "/oc do anything"
        self.assertFalse(self.check(data))

    def test_edited_timestamp(self):
        data = valid()
        data["updated_at"] = "2026-11-13T00:01:00Z"
        self.assertFalse(self.check(data))

    def test_wrong_author(self):
        data = valid()
        data["user"]["id"] = 1
        self.assertFalse(self.check(data))

    def test_other_issue(self):
        data = valid()
        data["issue_url"] = data["issue_url"].replace("93", "94")
        self.assertFalse(self.check(data))

    def test_other_comment_id(self):
        data = valid()
        data["id"] = 43
        self.assertFalse(self.check(data))

    def test_deleted(self):
        self.assertFalse(self.check({}, 404))

    def test_boolean_id(self):
        data = valid()
        data["id"] = True
        self.assertFalse(self.check(data))


if __name__ == "__main__":
    unittest.main()
