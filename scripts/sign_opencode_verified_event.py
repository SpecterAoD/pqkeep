#!/usr/bin/env python3
"""Trusted offline signer entrypoint; never called from the untrusted agent.

Inputs must be independently obtained by a trusted preflight. A file on its
own is not proof of origin. This command performs no GitHub writes.
"""
import json
import os
from pathlib import Path
import sys

from attest_opencode_event import sign
from build_opencode_event_binding import build_binding
from verify_opencode_event_binding import load_json


def sign_verified(event_path: Path, comment_path: Path, issue_path: Path,
                  key_path: Path, run_id: int, base_sha: str) -> dict:
    """Sign only a freshly revalidated event identity with a private key."""
    if key_path.is_symlink() or not key_path.is_file():
        raise ValueError("invalid signer key")
    mode = key_path.stat().st_mode
    if os.name == "posix" and mode & 0o077:
        raise ValueError("signer key permissions too broad")
    if not 32 <= key_path.stat().st_size <= 4096:
        raise ValueError("invalid signer key size")
    binding = build_binding(
        load_json(event_path), load_json(comment_path),
        load_json(issue_path), run_id, base_sha,
    )
    return sign(binding, key_path.read_bytes())


def main() -> int:
    """CLI: event live-comment live-issue key run-id base-sha output."""
    if len(sys.argv) != 8:
        return 1
    try:
        run = sys.argv[5]
        if not run.isascii() or not run.isdecimal() or int(run) <= 0:
            raise ValueError("invalid run")
        result = sign_verified(
            Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]),
            Path(sys.argv[4]), int(run), sys.argv[6],
        )
        output = Path(sys.argv[7])
        if output.is_symlink() or output.exists():
            raise ValueError("output must be new and not a symlink")
        with output.open("x", encoding="utf-8") as handle:
            os.chmod(output, 0o600)
            json.dump(result, handle, sort_keys=True)
            handle.write("\n")
    except (OSError, ValueError, TypeError, UnicodeError, KeyError):
        print("DENIED: trusted event signing failed", file=sys.stderr)
        return 1
    print("PASS: event binding signed (no publication)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
