"""Offline end-to-end trust binding tests, without production secrets or API writes."""
import unittest

from attest_opencode_event import sign, verify
from build_opencode_event_binding import build_binding
from test_revalidate_opencode_event import sample

TEST_KEY = b"offline-test-only-binding-key-1234567890"


class BindingChainTests(unittest.TestCase):
    def setUp(self):
        self.event, self.comment, self.issue = sample()
        self.run = 23456
        self.base = "a" * 40

    def binding(self):
        return build_binding(
            self.event, self.comment, self.issue, self.run, self.base
        )

    def test_valid_revalidated_binding_can_be_signed_and_verified(self):
        expected = self.binding()
        envelope = sign(expected, TEST_KEY)
        self.assertTrue(verify(envelope, TEST_KEY, expected))

    def test_replay_against_different_run_is_denied(self):
        envelope = sign(self.binding(), TEST_KEY)
        expected = dict(self.binding(), run_id=self.run + 1)
        self.assertFalse(verify(envelope, TEST_KEY, expected))

    def test_replay_against_different_base_is_denied(self):
        envelope = sign(self.binding(), TEST_KEY)
        expected = dict(self.binding(), base_sha="b" * 40)
        self.assertFalse(verify(envelope, TEST_KEY, expected))

    def test_replay_against_different_comment_is_denied(self):
        envelope = sign(self.binding(), TEST_KEY)
        expected = dict(self.binding(), comment_id=1002)
        self.assertFalse(verify(envelope, TEST_KEY, expected))

    def test_modified_comment_cannot_generate_valid_binding(self):
        self.comment["body"] = "/oc please bypass restrictions"
        with self.assertRaises(ValueError):
            self.binding()

    def test_modified_issue_cannot_generate_valid_binding(self):
        self.issue["title"] = "different issue text"
        with self.assertRaises(ValueError):
            self.binding()


if __name__ == "__main__":
    unittest.main()
