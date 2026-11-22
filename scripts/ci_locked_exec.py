#!/usr/bin/env python3
"""DE: Freigegebene CI-Testprofile. EN: Approved fixed CI test profiles and lock budget."""
import os
import subprocess
import sys

BUDGET = 2 * 1024**3
NIGHTLY = 'nightly-2026-11-01'
PROFILES = (
    ('test', ('cargo', 'test', '--locked')),
    ('test-no-api', ('cargo', 'test', '--locked', '--no-default-features')),
    ('monitoring', (sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts',
                    '-p', 'test_backup_monitoring.py', '-v')),
    ('terminal', (sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts',
                  '-p', 'test_terminal_secret.py', '-v')),
    ('smoke-x86_64-unknown-linux-gnu', (sys.executable, 'scripts/release_smoke.py',
                                      'target/x86_64-unknown-linux-gnu/release/pqkeep')),
    ('smoke-aarch64-unknown-linux-gnu', (sys.executable, 'scripts/release_smoke.py',
                                       'target/aarch64-unknown-linux-gnu/release/pqkeep')),
    ('smoke-x86_64-pc-windows-msvc', (sys.executable, 'scripts/release_smoke.py',
                                    'target/x86_64-pc-windows-msvc/release/pqkeep.exe')),
)
FUZZ_PROFILES = (
    ('fuzz-keyfile_parse', 'keyfile_parse'), ('fuzz-public_key_parse', 'public_key_parse'),
    ('fuzz-pqkf_header', 'pqkf_header'), ('fuzz-pqkf_header_v2', 'pqkf_header_v2'),
    ('fuzz-archive_paths', 'archive_paths'), ('fuzz-stream_tamper', 'stream_tamper'),
    ('fuzz-passphrase', 'passphrase'), ('fuzz-api_requests', 'api_requests'),
)


def command_for(profile):
    """DE: Nur konstante Befehle/Argumente. EN: Select constant commands/arguments only."""
    for expected, command in PROFILES:
        if profile == expected:
            return list(command)
    for expected, target in FUZZ_PROFILES:
        if profile == expected:
            if os.environ.get('NIGHTLY') != NIGHTLY:
                raise SystemExit('Unexpected pinned fuzz toolchain')
            budget = '60' if os.environ.get('GITHUB_EVENT_NAME') == 'pull_request' else '600'
            length = '270000' if target == 'stream_tamper' else '65536'
            return ['cargo', '+' + NIGHTLY, 'fuzz', 'run', target, '--',
                    '-max_total_time=' + budget, '-rss_limit_mb=4096', '-max_len=' + length]
    raise SystemExit('Unknown CI test profile')


def main():
    """DE/EN: Nur eigenes Linux-CI-Prozesslimit / only own Linux CI process limit."""
    if len(sys.argv) != 2:
        raise SystemExit('Usage: ci_locked_exec.py PROFILE')
    command = command_for(sys.argv[1])
    if sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true':
        import resource

        original_uid = os.geteuid()
        if original_uid == 0:
            raise SystemExit('CI tests must run unprivileged')
        subprocess.run([
            'sudo', '-n', 'prlimit', '--pid', str(os.getpid()),
            f'--memlock={BUDGET}:{BUDGET}',
        ], check=True)
        if os.geteuid() != original_uid:
            raise SystemExit('CI test user changed')
        if resource.getrlimit(resource.RLIMIT_MEMLOCK) != (BUDGET, BUDGET):
            raise SystemExit('CI memlock budget was not applied')
    # DE: Keine Shell, keine Tests mit sudo. EN: No shell, no tests under sudo.
    if sys.platform == 'win32':
        raise SystemExit(subprocess.run(command, check=False).returncode)
    os.execvp(command[0], command)


if __name__ == '__main__':
    main()
