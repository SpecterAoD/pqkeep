#!/usr/bin/env python3
"""Apply an untrusted patch in a disposable Git worktree, then validate.

Run ONLY on a trusted checkout with no GitHub write credentials.
This tool never pushes, opens PRs, or executes project build scripts.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from validate_opencode_patch import validate

SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_PATCH_BYTES = 100_000


def git(directory: Path, *args: str, input_bytes: bytes = None) -> bytes:
    """Run git with fixed arguments and no interactive prompts or hooks."""
    # Do not inherit Git configuration injection from the caller.
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    })
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c",
         "core.fsmonitor=false", "-C", str(directory), *args],
        input=input_bytes, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30, env=env,
    ).stdout


def review_patch(repository: Path, patch_file: Path, base: str) -> list[str]:
    """Return allowed paths only after patch application and full validation."""
    if not isinstance(base, str) or not SHA.fullmatch(base):
        raise ValueError("invalid trusted base")
    if patch_file.is_symlink() or not patch_file.is_file():
        raise ValueError("invalid patch file")
    if not 0 < patch_file.stat().st_size <= MAX_PATCH_BYTES:
        raise ValueError("patch exceeds size policy")
    patch = patch_file.read_bytes()
    if b"\0" in patch:
        raise ValueError("NUL in patch")
    git(repository, "cat-file", "-e", base + "^{commit}")
    with tempfile.TemporaryDirectory(prefix="opencode-patch-review-") as tmp:
        # Worktree must not exist before git worktree add.
        checkout = Path(tmp) / "checkout"
        added = False
        try:
            git(repository, "worktree", "add", "--detach", str(checkout), base)
            added = True
            # git apply --index enforces that index and worktree agree.
            git(checkout, "apply", "--check", "--index", "--whitespace=error",
                "-", input_bytes=patch)
            git(checkout, "apply", "--index", "--whitespace=error",
                "-", input_bytes=patch)
            # Commit exactly one proposal; hooks disabled by git wrapper.
            git(checkout, "-c", "user.name=OpenCode Review",
                "-c", "user.email=opencode@invalid.example",
                "commit", "-m", "review: untrusted documentation proposal")
            old = Path.cwd()
            try:
                os.chdir(checkout)
                return validate(base)
            finally:
                os.chdir(old)
        finally:
            if added:
                git(repository, "worktree", "remove", "--force", str(checkout))


def main() -> int:
    """CLI: trusted repo, inert patch path, independently trusted base SHA."""
    if len(sys.argv) != 4:
        return 1
    try:
        paths = review_patch(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
    except (OSError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, UnicodeError):
        print("DENIED: patch application or validation failed", file=sys.stderr)
        return 1
    print(f"PASS: validated {len(paths)} documentation paths (no push)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
