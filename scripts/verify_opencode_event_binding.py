#!/usr/bin/env python3
"""Offline, fail-closed event-binding verifier; NOT connected to a workflow.

Both expected identity and key must come from independent trusted inputs.
This module does not establish key custody or provenance by itself.
"""
import json
import os
from pathlib import Path
import sys

from attest_opencode_event import verify

MAX_JSON = 4096
MAX_KEY = 4096


def load_json(path: Path) -> dict:
    """Read a small JSON object without following symlinks."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("invalid input")
    if not 0 < path.stat().st_size <= MAX_JSON:
        raise ValueError("invalid input size")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def verify_files(envelope_path: Path, expected_path: Path,
                 key_path: Path) -> bool:
    """Never derive expected fields or key from the untrusted envelope."""
    if key_path.is_symlink() or not key_path.is_file():
        return False
    try:
        if not 32 <= key_path.stat().st_size <= MAX_KEY:
            return False
        if os.name == "posix" and key_path.stat().st_mode & 0o077:
            return False
        key = key_path.read_bytes()
        return verify(load_json(envelope_path), key,
                      load_json(expected_path))
    except (OSError, ValueError, TypeError, UnicodeError,
            json.JSONDecodeError):
        return False


def main() -> int:
    """CLI expects three trusted path arguments; never logs key material."""
    if len(sys.argv) != 4:
        return 1
    try:
        valid = verify_files(Path(sys.argv[1]), Path(sys.argv[2]),
                             Path(sys.argv[3]))
    except (OSError, ValueError):
        valid = False
    print("PASS: event binding verified" if valid else
          "DENIED: event binding invalid")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
