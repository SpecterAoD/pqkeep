"""Unit tests for the offline container smoke test preconditions."""
import os
import unittest
from unittest.mock import patch

from smoke_opencode_sandbox import IMAGE_RE, docker, main
from test_verify_opencode_sandbox import safe
import json


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

    def test_docker_does_not_inherit_remote_daemon(self):
        from types import SimpleNamespace
        with patch.dict(os.environ, {
            "DOCKER_HOST": "tcp://attacker.example:2375",
            "DOCKER_CONTEXT": "remote",
            "DOCKER_CONFIG": "/tmp/attacker",
            "HTTP_PROXY": "http://attacker.example",
        }):
            with patch("smoke_opencode_sandbox.subprocess.run",
                       return_value=SimpleNamespace(stdout="ok")) as run:
                self.assertEqual(docker("version"), "ok")
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["DOCKER_CONFIG"], "/nonexistent")
        self.assertNotIn("DOCKER_HOST", environment)
        self.assertNotIn("DOCKER_CONTEXT", environment)
        self.assertNotIn("HTTP_PROXY", environment)

    def test_reject_changed_configuration_before_start(self):
        digest = "alpine@sha256:" + "a" * 64
        calls = []
        def fake_docker(*args, **kwargs):
            calls.append(args)
            if args[0] == "create":
                return "test-container-id"
            if args[0] == "inspect":
                config = safe()
                config["Id"] = "test-container-id"
                if sum(call[0] == "inspect" for call in calls) == 2:
                    config["HostConfig"]["Privileged"] = True
                return json.dumps([config])
            if args[0] == "rm":
                return ""
            if args[0] == "start":
                self.fail("unsafe container was started")
            raise AssertionError(args)
        with patch.dict(os.environ, {"OPENCODE_TEST_IMAGE": digest}):
            with patch("smoke_opencode_sandbox.docker",
                       side_effect=fake_docker):
                self.assertEqual(main(), 1)
        self.assertEqual(sum(call[0] == "inspect" for call in calls), 2)
        self.assertFalse(any(call[0] == "start" for call in calls))
        self.assertTrue(any(call[0] == "rm" for call in calls))

    def test_create_never_pulls_image(self):
        digest = "alpine@sha256:" + "a" * 64
        calls = []
        def fake_docker(*args, **kwargs):
            calls.append(args)
            if args[0] == "create":
                raise OSError("test stop before any container starts")
            return ""
        with patch.dict(os.environ, {"OPENCODE_TEST_IMAGE": digest}):
            with patch("smoke_opencode_sandbox.docker",
                       side_effect=fake_docker):
                self.assertEqual(main(), 1)
        self.assertEqual(calls[0][:3], ("create", "--pull", "never"))
        self.assertIn("--network", calls[0])
        self.assertIn("none", calls[0])

    def test_no_docker_call_without_digest(self):
        with patch.dict(os.environ, {"OPENCODE_TEST_IMAGE": ""}):
            with patch("smoke_opencode_sandbox.docker") as docker:
                self.assertEqual(main(), 1)
                docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
