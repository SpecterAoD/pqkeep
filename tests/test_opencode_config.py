"""Validate the checked-in OpenCode V2 analysis policy before activation."""
import json
import pathlib
import unittest

CONFIG = pathlib.Path(".github/opencode-analysis.json")


class OpenCodePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = json.loads(CONFIG.read_text(encoding="utf-8"))

    def test_v2_permissions_schema(self):
        self.assertIsInstance(self.config.get("permissions"), list)
        self.assertNotIn("permission", self.config)
        self.assertTrue(all(
            set(rule) == {"action", "resource", "effect"}
            for rule in self.config["permissions"]
        ))

    def test_default_deny_first(self):
        self.assertEqual(
            self.config["permissions"][0],
            {"action": "*", "resource": "*", "effect": "deny"},
        )

    def test_no_write_or_shell_exceptions(self):
        allowed = {
            rule["action"] for rule in self.config["permissions"]
            if rule["effect"] == "allow"
        }
        self.assertEqual(allowed, {"read", "glob", "grep"})

    def test_secret_file_deny_last(self):
        rules = self.config["permissions"]
        self.assertTrue(any(
            rule["action"] == "read" and rule["resource"] == "*secret*"
            and rule["effect"] == "deny"
            for rule in rules[1:]
        ))


if __name__ == "__main__":
    unittest.main()
