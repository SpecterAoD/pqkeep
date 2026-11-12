"""Run provenance checks reject unauthorized or replayed workflow runs."""
import unittest

from verify_opencode_run_provenance import verify_run


def run_record():
    return {
        "id": 12345, "event": "issue_comment",
        "status": "completed", "conclusion": "success",
        "path": ".github/workflows/opencode.yml",
        "head_sha": "a" * 40,
        "actor": {"id": 77644070},
        "triggering_actor": {"id": 77644070},
        "repository": {"full_name": "SpecterAoD/pqkeep"},
        "head_repository": {"full_name": "SpecterAoD/pqkeep"},
    }


class RunProvenanceTests(unittest.TestCase):
    def check(self, record):
        return verify_run(
            12345, "a" * 40, "read-token",
            lambda path, token: (200, record),
        )

    def test_valid(self):
        self.assertTrue(self.check(run_record()))

    def test_other_actor(self):
        record = run_record()
        record["actor"]["id"] = 1
        self.assertFalse(self.check(record))

    def test_other_triggering_actor(self):
        record = run_record()
        record["triggering_actor"]["id"] = 1
        self.assertFalse(self.check(record))

    def test_failed_run(self):
        record = run_record()
        record["conclusion"] = "failure"
        self.assertFalse(self.check(record))

    def test_other_workflow(self):
        record = run_record()
        record["path"] = ".github/workflows/ci.yml"
        self.assertFalse(self.check(record))

    def test_other_sha(self):
        record = run_record()
        record["head_sha"] = "b" * 40
        self.assertFalse(self.check(record))

    def test_other_repository(self):
        record = run_record()
        record["head_repository"]["full_name"] = "attacker/pqkeep"
        self.assertFalse(self.check(record))

    def test_other_run_id(self):
        record = run_record()
        record["id"] = 12346
        self.assertFalse(self.check(record))

    def test_missing_fields(self):
        self.assertFalse(self.check({}))

    def test_wrong_event(self):
        record = run_record()
        record["event"] = "workflow_dispatch"
        self.assertFalse(self.check(record))


if __name__ == "__main__":
    unittest.main()
