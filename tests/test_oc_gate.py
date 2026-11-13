"""Authorization regression tests for issue #176."""
import unittest
from scripts.oc_gate import validate, unchanged_comment


def event(body="/oc plan Analyse", author=77644070):
    return {
        "action": "created",
        "sender": {"id": author},
        "repository": {"full_name": "SpecterAoD/pqkeep"},
        "issue": {"number": 176, "body": "<!-- /oc implement -->"},
        "comment": {"id": 12345, "user": {"id": author}, "body": body,
                    "created_at": "2026-11-13T10:00:00Z",
                    "updated_at": "2026-11-13T10:00:00Z"},
    }


class GateTests(unittest.TestCase):
    def check(self, payload):
        return validate(payload, "SpecterAoD/pqkeep")

    def test_live_comment_matches(self):
        payload = event()
        self.assertTrue(unchanged_comment(payload, payload["comment"]))

    def test_live_comment_modified(self):
        payload = event()
        current = dict(payload["comment"], body="/oc implement malicious")
        self.assertFalse(unchanged_comment(payload, current))

    def test_live_comment_edited_then_restored(self):
        payload = event()
        current = dict(payload["comment"], updated_at="2026-11-13T10:01:00Z")
        self.assertFalse(unchanged_comment(payload, current))

    def test_live_comment_wrong_author(self):
        payload = event()
        current = dict(payload["comment"], user={"id": 12})
        self.assertFalse(unchanged_comment(payload, current))

    def test_live_comment_missing_id(self):
        payload = event()
        del payload["comment"]["id"]
        self.assertFalse(unchanged_comment(payload, payload["comment"]))

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
