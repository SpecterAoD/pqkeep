"""DE: Regeltests für scripts/check_actions_policy.py (#181), inkl. der echten Workflows.
EN: Rule tests for scripts/check_actions_policy.py (#181), incl. the real workflows."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_actions_policy import audit

PIN = "actions/checkout@" + "a" * 40
BASE = "name: Example\non: [push]\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + PIN + "\n"
PR_FORMS = ("on:\n  pull_request:", "on: [push, pull_request]", "on: pull_request", "on:\n  - pull_request")
PR = BASE.replace("on: [push]", PR_FORMS[0])
GUARD = "    if: github.event_name != 'pull_request'\n"
WRITE_JOB = "  publish:\n{1}    runs-on: ubuntu-latest\n    permissions:\n      {0}: write\n"

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
        # DE: Block, Liste und Einzeiler. EN: Block, list and inline form.
        for on in ("on:\n  pull_request_target:", "on: [push, pull_request_target]", "on: workflow_run",
                   "on:\n  - push\n  - workflow_run"):
            self.check(BASE.replace("on: [push]", on), "privileged trigger")

    def test_secret_dump(self):
        self.check(BASE + "      - run: echo ${{ toJSON(secrets) }}\n", "secret serialization")

    def test_pr_secret(self):
        for on in PR_FORMS:
            self.check(BASE.replace("on: [push]", on) + "env:\n  KEY: ${{ secrets.API_KEY }}\n", "repository secrets")

    def test_remote_shell(self):
        self.check(BASE + "      - run: curl https://example.invalid/a | bash\n", "remote shell")

    def test_codeql_scoped_upload_allowed(self):
        self.assertEqual([], audit(PR + WRITE_JOB.format("security-events", ""), "codeql.yml"))

    def test_codeql_contents_write_rejected(self):
        sample = PR + WRITE_JOB.format("security-events", "") + "      contents: write\n"
        self.check(sample, "write permission")

    def test_non_codeql_write_rejected(self):
        for on in PR_FORMS:
            sample = BASE.replace("on: [push]", on) + WRITE_JOB.format("security-events", "")
            self.check(sample, "write permission")

    def test_write_all_and_top_level_rejected(self):
        self.check(PR.replace("permissions:\n  contents: read", "permissions: write-all"), "top level")
        self.check(PR.replace("contents: read", "contents: write"), "top level")

    def test_guard_counts_per_job(self):
        # DE: Der Ausschluss eines Jobs entlastet keinen anderen. EN: One job's guard covers no other.
        guarded = PR + WRITE_JOB.format("contents", GUARD)
        self.assertEqual([], audit(guarded, "release.yml"))
        both = guarded + WRITE_JOB.format("contents", "").replace("publish:", "extra:")
        found = audit(both, "release.yml")
        self.assertEqual(1, len(found), found)
        self.assertIn("extra", found[0])

    def test_pr_secret_index_and_comment(self):
        pr = PR
        self.check(pr + "env:\n  KEY: ${{ secrets['API_KEY'] }}\n", "repository secrets")
        # DE: Das Wort in einem Kommentar ist kein Fund. EN: The word in a comment is no finding.
        self.assertEqual([], audit(pr.replace("permissions:", "# no secrets. here\npermissions:"), "t.yml"))

    def test_repository_workflows_pass(self):
        # DE: Alle Workflows des Repositorys erfüllen die Regeln. EN: All repository workflows pass.
        root = Path(__file__).resolve().parents[1] / ".github" / "workflows"
        files = sorted(root.glob("*.yml"))
        self.assertTrue(files)
        for path in files:
            self.assertEqual([], audit(path.read_text(encoding="utf-8"), path.name), path.name)

    def test_download_needs_checksum(self):
        # DE: Download ohne Prüfung wird gemeldet. EN: Unverified download is reported.
        get = "      - run: curl -sSfL -o tool.tgz https://example.invalid/tool.tgz\n"
        self.check(BASE + get, "download without checksum")
        self.check(BASE + get.replace("curl -sSfL -o", "wget -O"), "download without checksum")
        # DE: Umleitung und Pipe sind auch Downloads. EN: Redirection and pipes are downloads too.
        self.check(BASE + "      - run: curl -sSfL https://example.invalid/t > t.tgz\n", "download without checksum")
        self.check(BASE + "      - run: curl -sSfL https://example.invalid/t | tar -xz\n", "download without checksum")
        # DE: Prüfung im selben Schritt (auch mehrzeilig mit Fortsetzung). EN: Check in the same step.
        ok = BASE + ("      - run: |\n          curl -sSfL -o tool.tgz \\\n            https://example.invalid/tool.tgz\n"
                     "          echo \"$SUM  tool.tgz\" | sha256sum -c -\n")
        self.assertEqual([], audit(ok, "test.yml"))

    def test_checksum_must_be_in_the_same_step(self):
        # DE: Prüfung in einem anderen Schritt, Schein-Prüfung oder Kommentar zählt nicht.
        # EN: A check in another step, a fake check or a comment does not count.
        get = BASE + "      - run: curl -sSfL -o tool.tgz https://example.invalid/tool.tgz\n"
        self.check(get + "      - run: echo \"$SUM  tool.tgz\" | sha256sum -c -\n", "download without checksum")
        self.check(get + "      - run: sha256sum tool.tgz\n", "download without checksum")
        commented = BASE + ("      - run: |\n          # sha256sum -c is done elsewhere\n"
                            "          curl -sSfL -o t.tgz https://example.invalid/t\n")
        self.check(commented, "download without checksum")

    def test_local_action(self):
        self.assertEqual([], audit(BASE.replace(PIN, "./.github/actions/test"), "test.yml"))

if __name__ == "__main__":
    unittest.main()
