"""DE: Echte temporäre Git-/SSH-Tag-Gegenproben. EN: Real temporary signed-tag tests."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from release_ref import metadata


class RefTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pqkeep-ref-')
        self.previous = Path.cwd()
        os.chdir(self.tmp.name)
        self.addCleanup(self.restore)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Release test')
        self.git('config', 'user.email', 'test@example.invalid')
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', 'key'], check=True)
        Path('.github').mkdir()
        Path('.github/allowed_signers').write_text('test@example.invalid ' + Path('key.pub').read_text())
        Path('docs/releases').mkdir(parents=True)
        Path('docs/releases/v1.2.3.md').write_text('DE: Test. EN: Test.')
        self.git('add', '.github', 'docs')
        self.git('commit', '-qm', 'Public test baseline')
        self.commit = self.git('rev-parse', 'HEAD')
        self.git('update-ref', 'refs/remotes/origin/main', self.commit)
        self.git('config', 'gpg.format', 'ssh')
        self.git('config', 'user.signingkey', str(Path('key').resolve()))

    def restore(self):
        os.chdir(self.previous)
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', *args], text=True, stderr=subprocess.PIPE).strip()

    def tag(self, name='v1.2.3'):
        self.git('tag', '-s', name, '-m', 'Test release')

    def test_signed_expected_tag_is_accepted(self):
        self.tag()
        self.assertEqual('true', metadata('push', 'refs/tags/v1.2.3', self.commit, '1.2.3')['is_tag'])

    def test_lightweight_and_unsigned_tags_are_rejected(self):
        self.git('tag', 'v1.2.3')
        with self.assertRaises(subprocess.CalledProcessError):
            metadata('push', 'refs/tags/v1.2.3', self.commit, '1.2.3')

    def test_unsigned_annotated_tag_is_rejected(self):
        self.git('tag', '-a', 'v1.2.3', '-m', 'Unsigned')
        with self.assertRaises(subprocess.CalledProcessError):
            metadata('push', 'refs/tags/v1.2.3', self.commit, '1.2.3')

    def test_tag_pointing_to_other_commit_is_rejected(self):
        self.tag()
        Path('public.txt').write_text('public new commit')
        self.git('add', 'public.txt')
        self.git('commit', '-qm', 'New source')
        with self.assertRaises(ValueError):
            metadata('push', 'refs/tags/v1.2.3', self.git('rev-parse', 'HEAD'), '1.2.3')

    def test_tag_cannot_supply_its_own_trusted_signer(self):
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', 'foreign'], check=True)
        Path('.github/allowed_signers').write_text('test@example.invalid ' + Path('foreign.pub').read_text())
        self.git('add', '.github/allowed_signers')
        self.git('commit', '-qm', 'Untrusted signers in tag source')
        commit = self.git('rev-parse', 'HEAD')
        self.git('config', 'user.signingkey', str(Path('foreign').resolve()))
        self.tag()
        with self.assertRaises(subprocess.CalledProcessError):
            metadata('push', 'refs/tags/v1.2.3', commit, '1.2.3')

    def test_wrong_event_ref_version_commit_and_missing_notes_are_rejected(self):
        for event, ref, commit in [('workflow_dispatch', 'refs/heads/feature', self.commit),
                                    ('push', 'refs/tags/v9.9.9', self.commit),
                                    ('push', 'refs/tags/v1.2.3', '0' * 40),
                                    ('pull_request_target', 'refs/heads/main', self.commit)]:
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                metadata(event, ref, commit, '1.2.3')
        self.tag()
        Path('docs/releases/v1.2.3.md').unlink()
        with self.assertRaises(ValueError):
            metadata('push', 'refs/tags/v1.2.3', self.commit, '1.2.3')

    def test_main_dry_run_and_pr_never_become_releases(self):
        for event, ref in [('workflow_dispatch', 'refs/heads/main'), ('pull_request', 'refs/pull/1/merge')]:
            result = metadata(event, ref, self.commit, '1.2.3')
            self.assertEqual('false', result['is_tag'])
            self.assertTrue(result['version'].endswith(self.commit[:7]))


if __name__ == '__main__':
    unittest.main()
