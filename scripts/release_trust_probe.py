#!/usr/bin/env python3
"""DE: Reale Gegenproben an einem signierten Bündel; nur temporäre Kopien verändern.
EN: Real verification probes against a signed bundle; modify temporary copies only."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

import release_manifest as manifest
from release_trust import verify


def expect_failure(label, operation):
    """DE/EN: Unerwartete Annahme ist ein Testfehler / unexpected acceptance fails the test."""
    try:
        operation()
    except (OSError, ValueError, subprocess.SubprocessError):
        print(f'Abgewiesen / rejected: {label}', flush=True)
        return
    raise AssertionError(f'Accepted invalid case: {label}')


def run(dist, version, repo, ref, commit):
    verify(dist, version, repo, ref, commit)
    print('Valid signed main bundle accepted', flush=True)
    for label, field, bad in [('repository', 'repo', 'example/foreign'),
                              ('ref', 'ref', 'refs/tags/v0.0.0-wrong'),
                              ('commit', 'commit', '0' * 40)]:
        values = dict(dist=dist, version=version, repo=repo, ref=ref, commit=commit)
        values[field] = bad
        expect_failure(label, lambda: verify(**values))
    with tempfile.TemporaryDirectory(prefix='pqkeep-trust-') as tmp:
        copy = Path(tmp) / 'dist'
        shutil.copytree(dist, copy)
        first = sorted(manifest.names(version, ('archive', 'deb')))[0]
        (copy / first).write_bytes((copy / first).read_bytes() + b'tampered')
        expect_failure('tampered artifact', lambda: verify(copy, version, repo, ref, commit))
        shutil.copyfile(dist / first, copy / first)
        bundle = copy / (first + '.sigstore.json')
        bundle.write_text('{}')
        expect_failure('invalid signature', lambda: verify(copy, version, repo, ref, commit))
    print('Live trust probes passed; no publication or original artifact changes', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('dist', 'version', 'repo', 'ref', 'commit'):
        parser.add_argument(name, type=Path if name == 'dist' else str)
    run(**vars(parser.parse_args()))
