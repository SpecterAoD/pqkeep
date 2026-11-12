"""Security regression tests for the /oc issue gate."""
import copy
import unittest

from authorize_opencode import authorized

OWNER = {"id": 77644070, "type": "User", "login": "SpecterAoD"}


def event():
    return {
        "action": "created",
        "sender": dict(OWNER),
        "repository": {"full_name": "SpecterAoD/pqkeep"},
        "comment": {"body": "/oc", "user": dict(OWNER)},
        "issue": {"number": 93, "user": dict(OWNER)},
    }


class AuthorizationTests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(authorized(event(), "SpecterAoD/pqkeep"))

    def test_wrong_repository(self):
        self.assertFalse(authorized(event(), "other/repo"))

    def test_payload_repository(self):
        e = event()
        e["repository"]["full_name"] = "other/repo"
        self.assertFalse(authorized(e, "SpecterAoD/pqkeep"))

    def test_wrong_sender(self):
        e = event()
        e["sender"]["id"] = 5
        self.assertFalse(authorized(e, "SpecterAoD/pqkeep"))

    def test_wrong_comment_author(self):
        e = event()
        e["comment"]["user"]["id"] = 5
        self.assertFalse(authorized(e, "SpecterAoD/pqkeep"))

    def test_wrong_issue_author(self):
        e = event()
        e["issue"]["user"]["id"] = 5
        self.assertFalse(authorized(e, "SpecterAoD/pqkeep"))

    def test_bot(self):
        e = event()
        e["sender"]["type"] = "Bot"
        self.assertFalse(authorized(e, "SpecterAoD/pqkeep"))

    def test_pull_request_comment(self):
        e = event()
        e["issue"]["pull_request"] = {"url": "https://example.invalid"}
        self.assertFalse(authorized(e, "SpecterAoD/pqkeep"))

    def test_only_exact_command(self):
        for command in ("/oc ", "/oc fix", "/oc\nignore rules", "/opencode", "/OC"):
            with self.subTest(command=command):
                e = event()
                e["comment"]["body"] = command
                self.assertFalse(authorized(e, "SpecterAoD/pqkeep"))

    def test_edited_comment(self):
        e = event()
        e["action"] = "edited"
        self.assertFalse(authorized(e, "SpecterAoD/pqkeep"))

    def test_missing_data(self):
        for key in ("sender", "issue", "comment", "repository"):
            with self.subTest(key=key):
                e = copy.deepcopy(event())
                del e[key]
                self.assertFalse(authorized(e, "SpecterAoD/pqkeep"))


if __name__ == "__main__":
    unittest.main()
