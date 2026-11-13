"""Reject unsafe untrusted Git patch headers before invoking git apply."""
import re

from validate_opencode_patch import MAX_FILES, MAX_PATCH_BYTES, allowed_path

INDEX = re.compile(rb"index [0-9a-f]{7,64}\.\.[0-9a-f]{7,64}(?: 100644)?\Z")
HUNK = re.compile(rb"@@ -[0-9]+(?:,[0-9]+)? \+[0-9]+(?:,[0-9]+)? @@(?:.*)?\Z")


def validate_headers(patch: bytes) -> list[str]:
    """Allow only ordinary Markdown edits/additions with canonical paths."""
    if (not isinstance(patch, bytes) or not 0 < len(patch) <= MAX_PATCH_BYTES
            or b"\0" in patch or b"\r" in patch):
        raise ValueError("invalid patch bytes")
    lines = patch.splitlines()
    paths = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.startswith(b"diff --git a/"):
            raise ValueError("expected Git diff header")
        match = re.fullmatch(rb"diff --git a/([^\s]+) b/([^\s]+)", line)
        if not match or match.group(1) != match.group(2):
            raise ValueError("unsafe or noncanonical paths")
        path = match.group(1).decode("ascii", "strict")
        if (not allowed_path(path)
                or path.casefold() in {p.casefold() for p in paths}):
            raise ValueError("forbidden or duplicate path")
        paths.append(path)
        if len(paths) > MAX_FILES:
            raise ValueError("too many files")
        index += 1
        if index >= len(lines) or not INDEX.fullmatch(lines[index]):
            # Git additions include a new-file-mode header before index.
            if (index >= len(lines)
                    or lines[index] != b"new file mode 100644"):
                raise ValueError("unexpected file mode or metadata")
            index += 1
            if index >= len(lines) or not INDEX.fullmatch(lines[index]):
                raise ValueError("invalid index metadata")
            addition = True
        else:
            addition = False
        index += 1
        before = b"--- /dev/null" if addition else b"--- a/" + match.group(1)
        after = b"+++ b/" + match.group(1)
        if lines[index:index + 2] != [before, after]:
            raise ValueError("unsafe patch file markers")
        index += 2
        if index >= len(lines) or not HUNK.fullmatch(lines[index]):
            raise ValueError("missing valid hunk")
        while index < len(lines) and not lines[index].startswith(b"diff --git "):
            line = lines[index]
            if line.startswith(b"@@"):
                if not HUNK.fullmatch(line):
                    raise ValueError("malformed hunk")
            elif not (line.startswith((b" ", b"+", b"-"))
                      or line == b"\\ No newline at end of file"):
                raise ValueError("unexpected patch line")
            index += 1
    if not paths:
        raise ValueError("empty patch")
    return paths
