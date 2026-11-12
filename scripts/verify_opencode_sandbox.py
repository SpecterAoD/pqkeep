#!/usr/bin/env python3
"""Fail-closed policy for a proposed Docker sandbox configuration.

This validates inspect metadata only. It does NOT prove network isolation.
Do not use this as permission to inject a Gemini secret.
"""
import json
import sys
from pathlib import Path


def compliant(config: dict) -> bool:
    """Check a strict subset of container hardening invariants."""
    if not isinstance(config, dict):
        return False
    host = config.get("HostConfig")
    settings = config.get("Config")
    if not isinstance(host, dict) or not isinstance(settings, dict):
        return False
    user = settings.get("User")
    if not isinstance(user, str) or not user:
        return False
    # Require explicit positive numeric UID and GID; names and UID 0 fail.
    parts = user.split(":")
    if (
        len(parts) != 2
        or any(not part.isascii() or not part.isdecimal() for part in parts)
        or any(int(part) <= 0 for part in parts)
    ):
        return False
    if not host.get("ReadonlyRootfs", False):
        return False
    if host.get("Privileged") is not False:
        return False
    if host.get("NetworkMode") != "none":
        return False
    if host.get("CapDrop") != ["ALL"]:
        return False
    if "no-new-privileges:true" not in (host.get("SecurityOpt") or []):
        return False
    if host.get("PidMode") not in ("", None):
        return False
    if host.get("IpcMode") == "host":
        return False
    if host.get("CgroupnsMode") == "host":
        return False
    if (
        not isinstance(host.get("Memory"), int)
        or isinstance(host["Memory"], bool)
        or not 128 * 1024 * 1024 <= host["Memory"] <= 1024 * 1024 * 1024
    ):
        return False
    if not isinstance(host.get("PidsLimit"), int) or isinstance(host["PidsLimit"], bool) or not (
        1 <= host["PidsLimit"] <= 128
    ):
        return False
    if not isinstance(host.get("NanoCpus"), int) or isinstance(host["NanoCpus"], bool) or not (
        1 <= host["NanoCpus"] <= 2_000_000_000
    ):
        return False
    if host.get("Binds"):
        return False
    if host.get("Devices"):
        return False
    if host.get("PortBindings"):
        return False
    if host.get("ExtraHosts"):
        return False
    if host.get("Dns"):
        return False
    if host.get("Mounts"):
        return False
    if host.get("ReadonlyPaths") and not isinstance(host["ReadonlyPaths"], list):
        return False
    if settings.get("Entrypoint") is None:
        return False
    env = settings.get("Env") or []
    if not isinstance(env, list):
        return False
    if any(
        isinstance(item, str)
        and any(key in item.upper() for key in (
            "GEMINI_API_KEY=", "GOOGLE_GENERATIVE_AI_API_KEY=",
            "GITHUB_TOKEN=", "GH_TOKEN=", "OPENROUTER_API_KEY=",
        ))
        for item in env
    ):
        return False
    return all(isinstance(item, str) for item in env)


def main() -> int:
    """Validate a local docker-inspect JSON file, never start containers."""
    if len(sys.argv) != 2:
        return 1
    try:
        path = Path(sys.argv[1])
        if path.stat().st_size > 100_000:
            return 1
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not compliant(data):
            return 1
    except (OSError, UnicodeError, ValueError, TypeError):
        return 1
    print("PASS: offline, secret-free sandbox metadata only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
