"""DE: Fehlergrenzen des Release-Verifikationsstarters. EN: Release verification contracts."""
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import release_trust as trust

COMMIT = 'a' * 40
ARGS = (Path('dist'), '1.2.3', 'owner/repo', 'refs/heads/main', COMMIT)


class TrustTests(unittest.TestCase):
    def test_all_signatures_and_attestations_bind_independent_expectations(self):
        with patch.object(trust.manifest, 'verify') as inventory, patch.object(trust, 'execute') as execute:
            trust.verify(*ARGS)
        inventory.assert_called_once_with(ARGS[0], ARGS[1])
        calls = [x.args[0] for x in execute.call_args_list]
        self.assertEqual(21, len(calls))
        self.assertEqual(6, sum(x[0] == 'cosign' for x in calls))
        for command in calls:
            self.assertIn('https://github.com/owner/repo/.github/workflows/release.yml@refs/heads/main', command)
            if command[0] == 'gh':
                for flag, expected in [('--repo', 'owner/repo'), ('--source-digest', COMMIT),
                                       ('--signer-digest', COMMIT), ('--source-ref', 'refs/heads/main')]:
                    self.assertEqual(expected, command[command.index(flag) + 1])
                self.assertIn('--deny-self-hosted-runners', command)
                self.assertNotIn('--signer-repo', command)
                self.assertNotIn('--signer-workflow', command)

    def test_invalid_expectations_never_reach_tools(self):
        for field, invalid in [(2, '--help'), (3, 'refs/heads/feature'),
                               (3, 'refs/pull/1/merge'), (4, 'bad'), (1, '../../file')]:
            args = list(ARGS)
            args[field] = invalid
            with self.subTest(field=field), patch.object(trust, 'execute') as execute:
                with self.assertRaises(ValueError):
                    trust.verify(*args)
                execute.assert_not_called()

    def test_missing_or_tampered_inventory_stops_before_crypto(self):
        with patch.object(trust.manifest, 'verify', side_effect=ValueError('invalid inventory')), \
                patch.object(trust, 'execute') as execute:
            with self.assertRaises(ValueError):
                trust.verify(*ARGS)
            execute.assert_not_called()

    def test_every_external_failure_stops_verification(self):
        for stage in range(21):
            with self.subTest(stage=stage), patch.object(trust.manifest, 'verify'), \
                    patch.object(trust, 'execute') as execute:
                execute.side_effect = [None] * stage + [subprocess.CalledProcessError(1, 'verifier')]
                with self.assertRaises(subprocess.CalledProcessError):
                    trust.verify(*ARGS)
                self.assertEqual(stage + 1, execute.call_count)

    def test_cli_arguments_are_rejected_before_context_or_tools(self):
        with patch.object(trust.sys, 'argv', ['runner', '--anything']), \
                patch.object(trust, 'execute') as execute:
            with self.assertRaises(ValueError):
                trust.main()
            execute.assert_not_called()

    def test_processes_have_timeout_and_no_shell(self):
        with patch.object(trust.subprocess, 'run') as run:
            trust.execute(['cosign', 'verify-blob'], Path('dist'))
        run.assert_called_once_with(['cosign', 'verify-blob'], cwd=Path('dist'), check=True, timeout=180)


if __name__ == '__main__':
    unittest.main()
