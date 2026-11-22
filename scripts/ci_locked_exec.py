#!/usr/bin/env python3
"""DE: Freigegebenes CI-Memlock-Budget. EN: Approved ephemeral CI memlock budget."""
import os
import subprocess
import sys

BUDGET = 2 * 1024**3


def main():
    """DE/EN: Nur eigenes Linux-CI-Prozesslimit / only own Linux CI process limit."""
    if len(sys.argv) < 2:
        raise SystemExit("Usage: ci_locked_exec.py COMMAND [ARG ...]")
    if sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true":
        import resource

        original_uid = os.geteuid()
        subprocess.run([
            "sudo", "-n", "prlimit", "--pid", str(os.getpid()),
            f"--memlock={BUDGET}:{BUDGET}",
        ], check=True)
        if os.geteuid() != original_uid or original_uid == 0:
            raise SystemExit("CI tests must run as the original unprivileged user")
        if resource.getrlimit(resource.RLIMIT_MEMLOCK) != (BUDGET, BUDGET):
            raise SystemExit("CI memlock budget was not applied")
    # DE: Keine Shell, keine Tests mit sudo. EN: No shell, no tests under sudo.
    if sys.platform == "win32":
        # DE: Windows-exec wartet nicht zuverlässig auf Kindprozesse.
        # EN: Explicitly wait on Windows and propagate the real test exit status.
        raise SystemExit(subprocess.run(sys.argv[1:], check=False).returncode)
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
