"""Negative tests for GitHub Actions artifact ownership binding."""
import unittest

from verify_opencode_artifact_origin import verify_artifact_listing


def response():
    return {
        "total_count": 1,
        "artifacts": [{
            "id": 456, "name": "opencode-issue-93-run-12345",
            "expired": False, "size_in_bytes": 1000,
            "workflow_run": {
                "id": 12345, "head_sha": "a" * 40,
                "repository_id": 77,
            },
        }],
    }


class ArtifactOriginTests(unittest.TestCase):
    def check(self, data):
        return verify_artifact_listing(
            93, 12345, "a" * 40, 456, "read-token",
            lambda path, token: (200, data),
        )

    def test_valid(self):
        self.assertTrue(self.check(response()))

    def test_other_run(self):
        data = response()
        data["artifacts"][0]["workflow_run"]["id"] = 5
        self.assertFalse(self.check(data))

    def test_other_sha(self):
        data = response()
        data["artifacts"][0]["workflow_run"]["head_sha"] = "b" * 40
        self.assertFalse(self.check(data))

    def test_wrong_artifact_id(self):
        data = response()
        data["artifacts"][0]["id"] = 457
        self.assertFalse(self.check(data))

    def test_wrong_name(self):
        data = response()
        data["artifacts"][0]["name"] = "opencode-issue-94-run-12345"
        self.assertFalse(self.check(data))

    def test_expired(self):
        data = response()
        data["artifacts"][0]["expired"] = True
        self.assertFalse(self.check(data))

    def test_duplicate_artifacts(self):
        data = response()
        data["total_count"] = 2
        data["artifacts"].append(dict(data["artifacts"][0]))
        self.assertFalse(self.check(data))

    def test_large_artifact(self):
        data = response()
        data["artifacts"][0]["size_in_bytes"] = 120_001
        self.assertFalse(self.check(data))

    def test_missing_artifacts(self):
        self.assertFalse(self.check({}))

    def test_boolean_artifact_id(self):
        data = response()
        data["artifacts"][0]["id"] = True
        self.assertFalse(self.check(data))


if __name__ == "__main__":
    unittest.main()
