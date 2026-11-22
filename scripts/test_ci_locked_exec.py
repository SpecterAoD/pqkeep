"""DE: Keine lokale Rechteerhöhung, begrenzter CI-Aufruf. EN: Scoped CI elevation tests."""
import os
import unittest
from unittest.mock import patch

import ci_locked_exec as runner


class LockedRunnerTests(unittest.TestCase):
    def test_local_never_invokes_sudo(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(runner.sys, 'platform', 'linux'), \
                patch.object(runner.sys, 'argv', ['runner', 'cargo', 'test']), \
                patch.object(runner.subprocess, 'run') as privileged, \
                patch.object(runner.os, 'execvp') as execute:
            runner.main()
            privileged.assert_not_called()
            execute.assert_called_once_with('cargo', ['cargo', 'test'])

    def test_linux_ci_changes_only_own_limit(self):
        import resource
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}, clear=True), \
                patch.object(runner.sys, 'platform', 'linux'), \
                patch.object(runner.sys, 'argv', ['runner', 'cargo', 'test']), \
                patch.object(runner.os, 'geteuid', return_value=1000), \
                patch.object(runner.os, 'getpid', return_value=123), \
                patch.object(resource, 'getrlimit', return_value=(runner.BUDGET, runner.BUDGET)), \
                patch.object(runner.subprocess, 'run') as privileged, \
                patch.object(runner.os, 'execvp') as execute:
            runner.main()
            privileged.assert_called_once_with([
                'sudo', '-n', 'prlimit', '--pid', '123',
                '--memlock=2147483648:2147483648',
            ], check=True)
            execute.assert_called_once_with('cargo', ['cargo', 'test'])

    def test_windows_waits_and_propagates_failure_without_sudo(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}, clear=True), \
                patch.object(runner.sys, 'platform', 'win32'), \
                patch.object(runner.sys, 'argv', ['runner', 'cargo', 'test']), \
                patch.object(runner.subprocess, 'run') as execute, \
                patch.object(runner.os, 'execvp') as replace:
            execute.return_value.returncode = 7
            with self.assertRaises(SystemExit) as raised:
                runner.main()
            self.assertEqual(raised.exception.code, 7)
            execute.assert_called_once_with(['cargo', 'test'], check=False)
            replace.assert_not_called()


if __name__ == '__main__':
    unittest.main()
