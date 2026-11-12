#!/usr/bin/env python3
"""Offline container smoke test; deliberately has no Gemini integration.

Requires an independently reviewed immutable local image digest supplied by
the operator. This script never pulls an image or injects credentials.
"""
import json
import os
import re
import subprocess
import sys

from verify_opencode_sandbox import compliant

IMAGE_RE = re.compile(r"[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}\Z")


def docker(*args: str, timeout: int = 25) -> str:
    """Run only predetermined Docker commands, without a shell."""
    result = subprocess.run(
        ["docker", *args], check=True, capture_output=True,
        text=True, timeout=timeout,
    )
    return result.stdout.strip()


def main() -> int:
    """Run a no-network, no-secret, non-root container and inspect it."""
    image = os.environ.get("OPENCODE_TEST_IMAGE", "")
    if not IMAGE_RE.fullmatch(image):
        print("DENIED: reviewed image digest required", file=sys.stderr)
        return 1
    container_id = ""
    try:
        # This is a smoke test, not an OpenCode execution.
        container_id = docker(
            "create", "--network", "none", "--read-only",
            "--user", "10001:10001", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--memory", "256m", "--pids-limit", "32", "--cpus", "1",
            "--ipc", "private", image, "/bin/true",
        )
        inspected = json.loads(docker("inspect", container_id))
        if not isinstance(inspected, list) or len(inspected) != 1:
            raise ValueError("unexpected Docker inspection")
        if not compliant(inspected[0]):
            raise ValueError("sandbox configuration rejected")
        docker("start", "-a", container_id)
        print("PASS: offline sandbox started and exited successfully")
        return 0
    except (
        subprocess.CalledProcessError, subprocess.TimeoutExpired,
        ValueError, OSError, json.JSONDecodeError,
    ):
        print("DENIED: sandbox smoke test failed", file=sys.stderr)
        return 1
    finally:
        if container_id:
            try:
                docker("rm", "-f", container_id)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                print("WARNING: sandbox cleanup failed", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
