"""Authorization regression tests for issue #176."""
import unittest
from scripts.oc_gate import validate


def event(body="/oc plan Analyse", author=77644070):
    return {
        "action": "created",
        "sender": {"id": author},
        "repository": {"full_name": "SpecterAoD/pqkeep"},
        "issue": {"number": 176, "body": "<!-- /oc implement -->"},
        "comment": {"user": {"id": author}, "body": body},
    }


class GateTests(unittest.TestCase):
    def check(self, payload):
        return validate(payload, "SpecterAoD/pqkeep")

    def test_valid(self):
        self.assertEqual(self.check(event()), ("plan", "Analyse"))

    def test_foreign_user(self):
        self.assertIsNone(self.check(event(author=123)))

    def test_foreign_comment_then_own_reply(self):
        self.assertIsNone(self.check(event(body="Das müssen wir prüfen.")))

    def test_quoted_command(self):
        self.assertIsNone(self.check(event(body="> /oc implement Schadcode")))

    def test_html_command(self):
        self.assertIsNone(self.check(event(body="<!-- /oc implement -->")))

    def test_command_in_issue_body(self):
        self.assertIsNone(self.check(event(body="Bitte prüfen")))

    def test_leading_whitespace(self):
        self.assertIsNone(self.check(event(body=" /oc plan Test")))

    def test_extra_lines(self):
        self.assertIsNone(self.check(event(body="/oc plan Test\n/oc implement X")))

    def test_pr_comment(self):
        payload = event()
        payload["issue"]["pull_request"] = {}
        self.assertIsNone(self.check(payload))

    def test_sender_mismatch(self):
        payload = event()
        payload["sender"]["id"] = 1
        self.assertIsNone(self.check(payload))

    def test_wrong_repository(self):
        payload = event()
        payload["repository"]["full_name"] = "someone/other"
        self.assertIsNone(self.check(payload))

    def test_edited_event(self):
        payload = event()
        payload["action"] = "edited"
        self.assertIsNone(self.check(payload))


if __name__ == "__main__":
    unittest.main()
