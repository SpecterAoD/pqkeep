#!/usr/bin/env python3
"""DE: Release-Ref, Commit und Tag gegen geschützten main-Vertrauensanker prüfen.
EN: Validate release ref, commit and signed tag against protected main trust anchors."""
import os
from pathlib import Path
import re
import subprocess
import tempfile


def git(*args):
    """DE/EN: Keine Shell / no shell."""
    return subprocess.check_output(['git', *args], text=True, timeout=30).strip()


def metadata(event, ref, commit, version):
    """DE: Keine Artefakt-/Tag-eigenen Trust Roots. EN: No artifact/tag-controlled trust roots."""
    if not re.fullmatch(r'[0-9a-f]{40}', commit) or git('rev-parse', 'HEAD') != commit:
        raise ValueError('Unexpected checked-out commit')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?', version):
        raise ValueError('Invalid package version')
    epoch = git('log', '-1', '--format=%ct')
    if not epoch.isdigit():
        raise ValueError('Invalid source timestamp')
    if event == 'pull_request' and re.fullmatch(r'refs/pull/[0-9]+/merge', ref):
        return values(version + '-dev.' + commit[:7], epoch, False)
    if event == 'workflow_dispatch' and ref == 'refs/heads/main':
        return values(version + '-dev.' + commit[:7], epoch, False)
    if event != 'push' or ref != 'refs/tags/v' + version:
        raise ValueError('Untrusted release event/ref')
    tag = ref.removeprefix('refs/tags/')
    if git('rev-parse', ref + '^{commit}') != commit:
        raise ValueError('Tag no longer points to expected source commit')
    # DE: Ein Tag darf nicht seinen eigenen Signaturschlüssel legitimieren.
    # EN: A tag must not authorize its own signing key.
    signers = git('show', 'refs/remotes/origin/main:.github/allowed_signers')
    with tempfile.TemporaryDirectory(prefix='pqkeep-tag-') as tmp:
        trust = Path(tmp) / 'allowed_signers'
        trust.write_text(signers + '\n')
        git('-c', 'gpg.format=ssh', '-c', f'gpg.ssh.allowedSignersFile={trust}', 'verify-tag', tag)
    if not Path('docs/releases', tag + '.md').is_file():
        raise ValueError('Missing bilingual release notes')
    return values(version, epoch, True)


def values(version, epoch, is_tag):
    """DE/EN: Nur validierte skalare Job-Ausgaben / validated scalar job outputs only."""
    return dict(version=version, epoch=epoch, is_tag=str(is_tag).lower(),
                prerelease=str('-' in version).lower())


if __name__ == '__main__':
    package = Path('Cargo.toml').read_text().split('[package]', 1)[1].split('\n[', 1)[0]
    version = re.search(r'^version = "([^"]+)"$', package, re.MULTILINE).group(1)
    result = metadata(os.environ['GITHUB_EVENT_NAME'], os.environ['GITHUB_REF'],
                      os.environ['GITHUB_SHA'], version)
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        for key, value in result.items():
            output.write(f'{key}={value}\n')
