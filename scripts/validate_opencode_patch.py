#!/usr/bin/env python3
"""Strict first-stage allowlist for AI-generated git changes.

Run only in a trusted publisher job, never as an agent security boundary.
"""
import os
import subprocess
import sys

MAX_FILES = 10
MAX_PATCH_BYTES = 100_000
MAX_FILE_BYTES = 40_000
ALLOWED_PREFIX = "docs/"
PROTECTED_NAMES = {
    "docs/SPEC.md", "docs/THREAT_MODEL.md", "docs/SANDBOX.md",
    "docs/CRYPTO.md", "docs/FORMAT.md", "docs/FILE_FORMAT.md",
    "docs/KEY_MANAGEMENT.md", "docs/SECURITY_REVIEW.md",
    "docs/OPENCODE_AGENT_SECURITY_PLAN.md",
}


def allowed_path(path: str) -> bool:
    """Allow only non-security Markdown documentation without path tricks."""
    if not isinstance(path, str) or not path.startswith(ALLOWED_PREFIX):
        return False
    if path in PROTECTED_NAMES or not path.endswith(".md"):
        return False
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in path):
        return False
    if any(ch in path for ch in ("\\", ":", "~")):
        return False
    return True


def parse_changes(data: bytes) -> list[str]:
    """Parse git diff --name-status -z; reject all but plain M/A entries."""
    if not data or not data.endswith(b"\0"):
        raise ValueError("empty or malformed change list")
    fields = data[:-1].split(b"\0")
    if len(fields) % 2:
        raise ValueError("malformed status list")
    paths = []
    for idx in range(0, len(fields), 2):
        status = fields[idx].decode("ascii", "strict")
        path = fields[idx + 1].decode("utf-8", "strict")
        if status not in ("M", "A") or not allowed_path(path):
            raise ValueError("forbidden change")
        if path in paths or path.casefold() in [p.casefold() for p in paths]:
            raise ValueError("duplicate or case-conflicting path")
        paths.append(path)
    if len(paths) > MAX_FILES:
        raise ValueError("too many changed files")
    return paths


def git(*args: str) -> bytes:
    """Execute a fixed git command; never interpolate untrusted shell text."""
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)


def validate(base: str) -> list[str]:
    """Validate committed changes, file modes and final blob sizes."""
    if not base or any(ch not in "0123456789abcdef" for ch in base) or len(base) != 40:
        raise ValueError("base must be a full commit SHA")
    git("cat-file", "-e", base + "^{commit}")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("working tree not clean")
    if git("rev-list", "--count", base + "..HEAD").strip() != b"1":
        raise ValueError("expected exactly one proposed commit")
    if git("merge-base", base, "HEAD").strip().decode("ascii") != base:
        raise ValueError("base is not an ancestor of proposed commit")
    paths = parse_changes(git("diff", "--name-status", "-z", "--no-renames", base, "HEAD"))
    for path in paths:
        previous = git("ls-tree", base, "--", path)
        if previous and not previous.startswith(b"100644 blob "):
            raise ValueError("base file has forbidden mode")
    patch = git("diff", "--binary", "--no-ext-diff", base, "HEAD")
    if b"GIT binary patch" in patch or b"Binary files " in patch:
        raise ValueError("binary patch not allowed")
    if len(patch) > MAX_PATCH_BYTES:
        raise ValueError("patch too large")
    for path in paths:
        record = git("ls-tree", "HEAD", "--", path)
        if not record.startswith(b"100644 blob "):
            raise ValueError("non-regular file or executable mode")
        size = len(git("show", "HEAD:" + path))
        if size > MAX_FILE_BYTES:
            raise ValueError("file too large")
    return paths


def main() -> int:
    """Reject on any failure, including git errors."""
    try:
        paths = validate(os.environ.get("OPENCODE_BASE_SHA", ""))
    except (ValueError, UnicodeError, subprocess.CalledProcessError) as exc:
        print(f"DENIED: patch validation failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(f"ALLOWED: {len(paths)} documentation files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
