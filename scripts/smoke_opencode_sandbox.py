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
    # Do not inherit DOCKER_HOST, Docker contexts or CLI plugin overrides.
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "DOCKER_CONFIG": "/nonexistent",
    }
    result = subprocess.run(
        ["docker", *args], check=True, capture_output=True,
        text=True, timeout=timeout, env=environment,
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
        # Confirm the local Docker image store knows the exact pinned digest.
        # A container Config.Image string alone is not sufficient evidence.
        image_data = json.loads(docker("image", "inspect", image))
        if not isinstance(image_data, list) or len(image_data) != 1:
            raise ValueError("unexpected Docker image inspection")
        repo_digests = image_data[0].get("RepoDigests")
        if (not isinstance(repo_digests, list)
                or image not in repo_digests):
            raise ValueError("pinned image digest missing from local store")
        image_id = image_data[0].get("Id")
        if (not isinstance(image_id, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)):
            raise ValueError("invalid local Docker image ID")
        # This is a smoke test, not an OpenCode execution.
        container_id = docker(
            "create", "--pull", "never", "--network", "none", "--read-only",
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
        if inspected[0].get("Image") != image_id:
            raise ValueError("container uses a different image ID")
        if inspected[0].get("Config", {}).get("Image") != image:
            raise ValueError("unexpected sandbox image")
        if inspected[0].get("State", {}).get("Running") is not False:
            raise ValueError("container already running")
        # Inspect again immediately before starting: refuse altered containers.
        second = json.loads(docker("inspect", container_id))
        if not isinstance(second, list) or len(second) != 1:
            raise ValueError("unexpected pre-start inspection")
        if not compliant(second[0]):
            raise ValueError("sandbox configuration changed before start")
        if second[0].get("Image") != image_id:
            raise ValueError("container image ID changed before start")
        if second[0].get("Config", {}).get("Image") != image:
            raise ValueError("sandbox image changed before start")
        if second[0].get("State", {}).get("Running") is not False:
            raise ValueError("container started before validation")
        if (not isinstance(inspected[0].get("Id"), str)
                or inspected[0]["Id"] != container_id
                or second[0].get("Id") != container_id):
            raise ValueError("container identity changed before start")
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
