"""Authorization regression tests for issue #176."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from scripts.oc_gate import validate, unchanged_comment, main


def event(body="/oc plan Analyse", author=77644070):
    return {
        "action": "created",
        "sender": {"id": author},
        "repository": {"full_name": "SpecterAoD/pqkeep"},
        "issue": {"number": 176, "body": "<!-- /oc implement -->"},
        "comment": {"id": 12345, "user": {"id": author}, "body": body,
                    "issue_url": "https://api.github.com/repos/SpecterAoD/pqkeep/issues/176",
                    "created_at": "2026-11-13T10:00:00Z",
                    "updated_at": "2026-11-13T10:00:00Z"},
    }


class GateTests(unittest.TestCase):
    def check(self, payload):
        return validate(payload, "SpecterAoD/pqkeep")

    def run_gate(self, payload, token=None, current=None):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         encoding="utf-8") as source:
            json.dump(payload, source)
            source.flush()
            environment = {"GH_TOKEN": token} if token else {}
            with patch("sys.argv", ["oc_gate.py", source.name,
                                    "SpecterAoD/pqkeep"]):
                with patch.dict(os.environ, environment, clear=True):
                    with patch("scripts.oc_gate.fetch_comment",
                               return_value=current) as fetch:
                        result = main()
                        return result, fetch.call_count

    def test_main_requires_live_token(self):
        result, fetches = self.run_gate(event())
        self.assertEqual(result, 1)
        self.assertEqual(fetches, 0)

    def test_main_denies_changed_live_comment(self):
        payload = event()
        changed = dict(payload["comment"], body="/oc plan modified")
        result, fetches = self.run_gate(payload, "synthetic-read-token", changed)
        self.assertEqual((result, fetches), (1, 1))

    def test_main_authorizes_only_matching_live_comment(self):
        payload = event()
        result, fetches = self.run_gate(payload, "synthetic-read-token",
                                        payload["comment"])
        self.assertEqual((result, fetches), (0, 1))

    def test_main_denies_api_failure(self):
        payload = event()
        with patch("scripts.oc_gate.fetch_comment",
                   side_effect=OSError("synthetic API outage")):
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                             encoding="utf-8") as source:
                json.dump(payload, source)
                source.flush()
                with patch("sys.argv", ["oc_gate.py", source.name,
                                        "SpecterAoD/pqkeep"]):
                    with patch.dict(os.environ,
                                    {"GH_TOKEN": "synthetic-read-token"},
                                    clear=True):
                        self.assertEqual(main(), 1)

    def test_live_comment_matches(self):
        payload = event()
        self.assertTrue(unchanged_comment(payload, payload["comment"]))

    def test_live_comment_other_issue_rejected(self):
        payload = event()
        current = dict(payload["comment"],
                       issue_url="https://api.github.com/repos/SpecterAoD/pqkeep/issues/177")
        self.assertFalse(unchanged_comment(payload, current))

    def test_missing_comment_id_rejected_before_model(self):
        payload = event()
        del payload["comment"]["id"]
        self.assertIsNone(self.check(payload))

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

    def test_implement_not_yet_authorized(self):
        self.assertIsNone(self.check(event(body="/oc implement change files")))

    def test_trailing_newline_rejected(self):
        self.assertIsNone(self.check(event(body="/oc plan Test\n")))

    def test_zero_width_rejected(self):
        self.assertIsNone(self.check(event(body="/oc plan Test\u200b")))

    def test_unicode_direction_override_rejected(self):
        self.assertIsNone(self.check(event(body="/oc plan Test\\u202e")))

    def test_unicode_word_joiner_rejected(self):
        self.assertIsNone(self.check(event(body="/oc plan Test\\u2060")))

    def test_unicode_line_separator_rejected(self):
        self.assertIsNone(self.check(event(body="/oc plan Test\\u2028")))

    def test_control_character_rejected(self):
        self.assertIsNone(self.check(event(body="/oc plan Test\x00")))

    def test_boolean_issue_number_rejected(self):
        payload = event()
        payload["issue"]["number"] = True
        self.assertIsNone(self.check(payload))

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

    def test_markdown_fenced_command_rejected(self):
        self.assertIsNone(self.check(event(body="```\n/oc plan Test\n```")))

    def test_unicode_homoglyph_command_rejected(self):
        self.assertIsNone(self.check(event(body="/оc plan Test")))

    def test_newline_and_hidden_command_rejected(self):
        self.assertIsNone(self.check(event(body="/oc plan Safe\n<!-- /oc implement -->")))

    def test_overlong_command_rejected(self):
        self.assertIsNone(self.check(event(body="/oc plan " + "A" * 4001)))

    def test_untrusted_issue_body_does_not_authorize(self):
        payload = event(body="Bitte prüfen")
        payload["issue"]["body"] = "/oc plan malicious"
        self.assertIsNone(self.check(payload))

    def test_comment_id_must_be_integer(self):
        payload = event()
        payload["comment"]["id"] = "12345"
        self.assertIsNone(self.check(payload))

    def test_unchanged_comment_requires_issue_url(self):
        payload = event()
        current = dict(payload["comment"])
        del current["issue_url"]
        self.assertFalse(unchanged_comment(payload, current))

    def test_edited_event(self):
        payload = event()
        payload["action"] = "edited"
        self.assertIsNone(self.check(payload))


if __name__ == "__main__":
    unittest.main()
