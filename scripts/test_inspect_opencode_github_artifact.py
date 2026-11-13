"""End-to-end orchestration rejects untrusted run and artifact before fetch."""
import unittest
from unittest.mock import patch

from inspect_opencode_github_artifact import inspect


class EndToEndTests(unittest.TestCase):
    def test_missing_comment_never_fetches(self):
        def forbidden(*args):
            raise AssertionError("no network or download expected")
        with self.assertRaises(ValueError):
            inspect(None, None, {}, 93, 12345, "a" * 40,
                    456, "token", get=forbidden, fetch=forbidden)

    def test_untrusted_run_never_downloads(self):
        with patch("inspect_opencode_github_artifact.verify_run",
                   return_value=False):
            def forbidden(*args):
                raise AssertionError("download must not happen")
            with self.assertRaises(ValueError):
                inspect(None, None, {}, 93, 12345, "a" * 40,
                        456, "token", fetch=forbidden, expected_comment_id=42)

    def test_untrusted_artifact_never_downloads(self):
        with patch("inspect_opencode_github_artifact.verify_run",
                   return_value=True), patch(
                   "inspect_opencode_github_artifact.verify_artifact_listing",
                   return_value=False):
            def forbidden(*args):
                raise AssertionError("download must not happen")
            with self.assertRaises(ValueError):
                inspect(None, None, {}, 93, 12345, "a" * 40,
                        456, "token", fetch=forbidden)

    def test_verified_archive_reaches_combined_gate(self):
        import io
        import json
        import zipfile
        def fetch(artifact, token, destination):
            with zipfile.ZipFile(destination, "w") as outer:
                outer.writestr("manifest.json", json.dumps({"test": True}))
                outer.writestr("proposal.zip", b"inner zip")
        with patch("inspect_opencode_github_artifact.verify_run",
                   return_value=True), patch(
                   "inspect_opencode_github_artifact.verify_artifact_listing",
                   return_value=True), patch(
                   "inspect_opencode_github_artifact.check",
                   return_value=["docs/guide.md"]) as combined:
            paths = inspect(None, None, {}, 93, 12345, "a" * 40,
                            456, "token", fetch=fetch, expected_comment_id=42)
            self.assertEqual(paths, ["docs/guide.md"])
            combined.assert_called_once()
            self.assertEqual(combined.call_args.kwargs["expected_comment_id"], 42)


if __name__ == "__main__":
    unittest.main()
