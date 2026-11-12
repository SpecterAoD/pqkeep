"""Unit tests for the offline container smoke test preconditions."""
import os
import unittest
from unittest.mock import patch

from smoke_opencode_sandbox import IMAGE_RE, main


class SmokeTests(unittest.TestCase):
    def test_digest_required(self):
        for image in ("", "ubuntu:24.04", "alpine:latest", "x@sha256:abc"):
            with self.subTest(image=image):
                with patch.dict(os.environ, {"OPENCODE_TEST_IMAGE": image}):
                    self.assertEqual(main(), 1)

    def test_valid_digest_format(self):
        self.assertIsNotNone(IMAGE_RE.fullmatch(
            "alpine@sha256:" + "a" * 64
        ))

    def test_no_docker_call_without_digest(self):
        with patch.dict(os.environ, {"OPENCODE_TEST_IMAGE": ""}):
            with patch("smoke_opencode_sandbox.docker") as docker:
                self.assertEqual(main(), 1)
                docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
