#!/usr/bin/env python3
"""DE: Vollständige Release-Verifikation ohne Schreibrechte oder OIDC.
EN: Complete release verification without write permissions or OIDC."""
import argparse
from pathlib import Path
import re
import subprocess

import release_manifest as manifest


def validate(repo, ref, commit, workflow, version):
    """DE: Erwartungen kommen vom Aufrufer, nie aus Artefakten. EN: Independent expectations."""
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', repo):
        raise ValueError('Invalid expected repository')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Invalid expected commit')
    if workflow not in ('release', 'preview'):
        raise ValueError('Invalid expected workflow')
    if ref != 'refs/heads/main' and not re.fullmatch(r'refs/tags/v[0-9][A-Za-z0-9.+-]*', ref):
        raise ValueError('Untrusted expected ref')
    if not re.fullmatch(r'[0-9][A-Za-z0-9.+-]*', version):
        raise ValueError('Invalid expected version')


def execute(args, cwd):
    """DE: Keine Shell, Fehler/Timeout abbrechen. EN: No shell; fail on error/timeout."""
    subprocess.run(args, cwd=cwd, check=True, timeout=180)


def verify(dist, version, repo, ref, commit, workflow='release'):
    """DE: Inventar, Hashes, Signaturen und Herkunft prüfen. EN: Verify complete trust chain."""
    validate(repo, ref, commit, workflow, version)
    manifest.verify(dist, version)
    workflow_path = f'{repo}/.github/workflows/{workflow}.yml'
    identity = f'https://github.com/{workflow_path}@{ref}'
    artifacts = sorted(manifest.names(version, ('archive', 'deb')))
    for name in artifacts + [manifest.SUMS]:
        execute(['cosign', 'verify-blob', '--bundle', name + '.sigstore.json',
                 '--certificate-identity', identity, '--certificate-oidc-issuer',
                 'https://token.actions.githubusercontent.com', name], dist)
    # DE: Auch SBOM-Attestationen müssen zu exakt diesem Commit/Ref/Workflow gehören.
    # EN: SBOM attestations must also bind the exact commit/ref/workflow.
    flags = ['--repo', repo, '--source-ref', ref, '--source-digest', commit, '--signer-digest', commit,
             '--cert-identity', identity, '--cert-oidc-issuer',
             'https://token.actions.githubusercontent.com', '--deny-self-hosted-runners']
    for name in artifacts:
        execute(['gh', 'attestation', 'verify', name, *flags], dist)
        execute(['gh', 'attestation', 'verify', name, *flags,
                 '--bundle', manifest.provenance(version)], dist)
        execute(['gh', 'attestation', 'verify', name, *flags,
                 '--predicate-type', 'https://cyclonedx.org/bom'], dist)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dist', type=Path)
    parser.add_argument('version')
    parser.add_argument('repo')
    parser.add_argument('ref')
    parser.add_argument('commit')
    parser.add_argument('--workflow', choices=('release', 'preview'), default='release')
    args = parser.parse_args()
    try:
        verify(args.dist, args.version, args.repo, args.ref, args.commit, args.workflow)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Verifikation fehlgeschlagen / verification failed: {error}\n')


if __name__ == '__main__':
    main()
