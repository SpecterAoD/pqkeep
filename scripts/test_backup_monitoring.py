"""DE: Echte Backup-Prüfung plus fehlerhafte Antworten, Bash/Linux und PowerShell/Windows.
EN: Real backup checks plus invalid responses, Bash/Linux and PowerShell/Windows.
Run: python3 -m unittest discover -s scripts -p 'test_backup_monitoring.py' -v
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import backup_monitoring_fixtures as fixture


@unittest.skipUnless(fixture.available_shell(), 'Native Shell fehlt / native shell unavailable')
class MonitoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shell = fixture.available_shell()
        if cls.shell == 'bash' and not shutil.which('jq'):
            raise unittest.SkipTest('jq fehlt / unavailable')
        if not shutil.which('rustc'):
            raise unittest.SkipTest('rustc fehlt / unavailable')
        cls.temp = tempfile.TemporaryDirectory(prefix='pqkeep-monitor-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.binary = fixture.make_fake(cls.directory)
        cls.sources = ['a [ü] & space.pqkf', '-second.pqkf']

    def check(self, value, process_code=0, expected=1, sources=None):
        fixture.set_fake(self.directory, value, process_code)
        result = fixture.monitor(self.shell, self.binary, 'key file', 'pass file',
                                 self.sources if sources is None else sources, self.directory)
        self.assertEqual(result.returncode, expected)
        self.assertNotIn('RAW_DIAGNOSTIC_MUST_NOT_APPEAR', result.stdout + result.stderr)
        return result.stdout + result.stderr

    def test_success_and_unknown_fields(self):
        for sources in [self.sources[:1], self.sources]:
            value = fixture.report(sources, [0] * len(sources))
            value['future'] = {'allowed': True}
            self.assertIn(f'total={len(sources)}', self.check(value, expected=0, sources=sources))

    def test_all_exit_codes_and_first_error(self):
        for codes in [[0, code] for code in range(1, 8)] + [[3, 1], [1, 3]]:
            with self.subTest(codes=codes):
                value = fixture.report(self.sources, codes)
                code = value['exit_code']
                output = self.check(value, code, code)
                for kind in {fixture.KINDS[c] for c in codes if c}:
                    self.assertIn(kind, output)
        value = fixture.report(self.sources, [3, 1])
        value['exit_code'] = 1
        self.assertIn('JSON', self.check(value, 1, 1))

    def test_command_errors(self):
        for code in range(1, 8):
            value = {'schema': 'pqkeep-json/1', 'command': 'check', 'ok': False,
                     'exit_code': code, 'error': fixture.error(code)}
            self.assertIn('command failed', self.check(value, code, code))
        value['results'] = []
        self.assertIn('JSON', self.check(value, 7, 7))

    def test_invalid_json_and_process_failure(self):
        good = fixture.report(self.sources, [0, 0])
        for raw in ['', 'not JSON', '{"ok":', 'null', 'true', '[]', json.dumps([good]),
                    json.dumps(good)[:-1] + ',}', '/* comment */' + json.dumps(good),
                    json.dumps(good).replace('true', 'tr\0ue'), json.dumps(good) + '\0',
                    json.dumps(good) + '\n' + json.dumps(good)]:
            for code in [0, 2, 3, 127]:
                with self.subTest(raw=repr(raw), code=code):
                    output = self.check(raw, code, code or 1)
                    self.assertIn('JSON', output)
        self.assertIn('JSON', self.check(good, 3, 3))
        self.assertIn('JSON', self.check(fixture.report(self.sources, [3, 0]), 0, 1))

    def test_missing_wrong_and_inconsistent_fields(self):
        good = fixture.report(self.sources, [0, 0])
        for field in good:
            value = copy.deepcopy(good)
            del value[field]
            self.assertIn('JSON', self.check(value))
        replacements = {'schema': ['pqkeep-json/2', ['pqkeep-json/1']],
                        'command': ['inspect', ['check']], 'ok': ['true', 1, None],
                        'exit_code': ['0', False, -1, 0.5, 8],
                        'results': [None, {}, [], good['results'][:1]],
                        'summary': [None, {}, [], {'total': 0, 'ok': 0, 'failed': 0}]}
        for field, alternatives in replacements.items():
            for alternative in alternatives:
                with self.subTest(field=field, alternative=alternative):
                    value = copy.deepcopy(good)
                    value[field] = alternative
                    self.assertIn('JSON', self.check(value))
        for field in ['total', 'ok', 'failed']:
            for bad in [None, '0', False, -1, 0.5, 99]:
                value = copy.deepcopy(good)
                value['summary'][field] = bad
                self.assertIn('JSON', self.check(value))
        for field, bad in [('source', 'different.pqkf'), ('ok', 'true'), ('error', {})]:
            value = copy.deepcopy(good)
            value['results'][0][field] = bad
            self.assertIn('JSON', self.check(value))
        for field, bad in [('kind', 'RAW_DIAGNOSTIC_MUST_NOT_APPEAR'), ('code', 0), ('code', '3')]:
            value = fixture.report(self.sources, [3, 0])
            value['results'][0]['error'][field] = bad
            self.assertIn('JSON', self.check(value, 3, 3))

    def test_paths_and_log_escaping(self):
        sources = ['quote"\n\x1b[31m.pqkf', self.sources[0], self.sources[1]]
        value = fixture.report(sources, [1, 0, 0])
        output = self.check(value, 1, 1, sources)
        self.assertNotIn('\x1b', output)
        self.assertEqual(len(output.splitlines()), 2)
        arguments = (self.directory / 'arguments').read_text(encoding='utf-8').split('\0')
        self.assertEqual(arguments, ['--batch', 'check', '--json', '--key', 'key file',
                                    '--passphrase-file', 'pass file', '--', *sources])

    def test_empty_selection_and_source_limit(self):
        for sources in [[], ['file.pqkf'] * 1001]:
            self.assertIn('required', self.check('', expected=2, sources=sources))
        if self.shell == 'bash':
            result = fixture.run(['bash', '-c', 'shopt -s nullglob; files=(./*.pqkf); '
                                  'bash "$1" "$2" key pass "${files[@]}"', 'test',
                                  fixture.ROOT / 'scripts/check_backups.sh', self.binary], self.directory)
            self.assertEqual(result.returncode, 2)

    def test_missing_program(self):
        result = fixture.monitor(self.shell, self.directory / 'missing', 'key', 'pass',
                                 self.sources, self.directory)
        self.assertEqual(result.returncode, 1)

    @unittest.skipUnless(os.name != 'nt', 'jq nur für Bash / jq only for Bash')
    def test_missing_jq(self):
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, PATH=directory)
            result = fixture.run([shutil.which('bash'), fixture.ROOT / 'scripts/check_backups.sh',
                                  self.binary, 'key', 'pass', *self.sources], self.directory, env)
            self.assertEqual(result.returncode, 1)
            self.assertIn('jq', result.stderr)

    @unittest.skipUnless(os.name != 'nt', 'Temporäre JSON-Datei nur unter Bash / Bash only')
    def test_temporary_json_cleanup(self):
        for value, code in [(fixture.report(self.sources, [0, 0]), 0), ('invalid', 3)]:
            with tempfile.TemporaryDirectory() as directory:
                fixture.set_fake(self.directory, value, code)
                result = fixture.monitor(self.shell, self.binary, 'key', 'pass', self.sources,
                                         self.directory, dict(os.environ, TMPDIR=directory))
                self.assertEqual(result.returncode, code)
                self.assertEqual(list(Path(directory).iterdir()), [])


@unittest.skipUnless(fixture.available_shell(), 'Native Shell fehlt / native shell unavailable')
@unittest.skipUnless(fixture.BINARY.is_file(), 'Zuerst cargo build --locked / build binary first')
class RealBackupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shell = fixture.available_shell()
        if cls.shell == 'bash' and not shutil.which('jq'):
            raise unittest.SkipTest('jq fehlt / unavailable')
        cls.temp = tempfile.TemporaryDirectory(prefix='pqkeep-real-monitor-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.key, cls.password, cls.secret, cls.paths, cls.tampered, cls.truncated = fixture.real_files(cls.directory)

    def check(self, sources, code, key=None, password=None):
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.directory.iterdir()}
        result = fixture.monitor(self.shell, fixture.BINARY, key or self.key, password or self.password,
                                 sources, self.directory)
        self.assertEqual(result.returncode, code)
        self.assertFalse(self.secret in result.stdout + result.stderr, 'Geheimnis ausgegeben / secret printed')
        after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.directory.iterdir()}
        self.assertEqual(before, after)
        return result.stdout + result.stderr

    def test_success(self):
        self.assertIn('total=1', self.check(self.paths[:1], 0))
        self.assertIn('total=2', self.check(self.paths, 0))

    def test_mixed_tampered_truncated_and_missing(self):
        missing = str(self.directory / 'missing.pqkf')
        for sources, code in [([*self.paths, self.tampered], 3), ([self.truncated], 3),
                              ([missing], 1), ([missing, *self.paths], 1),
                              ([self.tampered, missing], 3), ([missing, self.tampered], 1)]:
            with self.subTest(code=code, count=len(sources)):
                output = self.check(sources, code)
                self.assertIn('FEHLER / ERROR', output)
                self.assertIn('decrypt_failed' if code == 3 else 'error', output)

    def test_missing_key_password_and_wrong_password(self):
        missing = self.directory / 'missing'
        self.assertIn('command failed', self.check(self.paths, 1, key=missing))
        self.assertIn('command failed', self.check(self.paths, 1, password=missing))
        wrong = fixture.require_success(fixture.run([fixture.BINARY, 'passphrase'], self.directory)).strip()
        password = self.directory / 'wrong.txt'
        with open(os.open(password, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='utf-8') as file:
            file.write(wrong + '\n')
        output = self.check(self.paths, 3, password=password)
        self.assertFalse(wrong in output, 'Geheimnis ausgegeben / secret printed')
        self.assertIn('decrypt_failed', output)


if __name__ == '__main__':
    unittest.main()
