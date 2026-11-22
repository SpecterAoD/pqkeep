"""DE: Echte verdeckte PTY-Eingabe und Bestätigung. EN: Real hidden PTY input/confirmation."""
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time
import unittest


@unittest.skipUnless(os.name == 'posix', 'Linux PTY test')
class TerminalSecretTests(unittest.TestCase):
    def test_confirmation_retry_backspace_and_no_echo(self):
        import pty
        binary = str(Path(os.environ.get('PQKEEP_BINARY', 'target/debug/pqkeep')).resolve())
        secret = subprocess.check_output([binary, '--lang', 'en', 'passphrase'], timeout=30).strip()
        with tempfile.TemporaryDirectory(prefix='pqkeep-terminal-') as tmp:
            master, slave = pty.openpty()
            self.addCleanup(os.close, master)
            child = subprocess.Popen([binary, '--lang', 'en', 'generate', '--algorithm',
                                      'aes-256', '--name', 'PTY test', '--out', 'key.json'],
                                     stdin=slave, stderr=slave, stdout=subprocess.PIPE, cwd=tmp)
            os.close(slave)
            self.addCleanup(lambda: child.kill() if child.poll() is None else None)
            transcript = bytearray()

            def expect(prompt):
                start = len(transcript)
                deadline = time.monotonic() + 90
                while prompt not in transcript[start:]:
                    self.assertLess(time.monotonic(), deadline, 'terminal prompt timed out')
                    ready, _, _ = select.select([master], [], [], 1)
                    if ready:
                        try:
                            data = os.read(master, 4096)
                        except OSError:
                            self.fail('terminal closed before expected prompt')
                        self.assertTrue(data, 'terminal closed')
                        transcript.extend(data)

            expect(b'Passphrase: ')
            os.write(master, secret + b'\r')
            expect(b'Repeat passphrase: ')
            os.write(master, secret + b'x\r')
            expect(b'Passphrase: ')
            # DE/EN: UTF-8-Zeichen vollständig zurücknehmen / remove whole UTF-8 character.
            os.write(master, secret + 'ü'.encode() + b'\x7f\r')
            expect(b'Repeat passphrase: ')
            os.write(master, secret + b'\r')
            child.communicate(timeout=180)
            self.assertEqual(child.returncode, 0, 'interactive generation failed')
            self.assertTrue((Path(tmp) / 'key.json').is_file())
            self.assertNotIn(secret, transcript, 'terminal echoed the secret')
            checked = subprocess.run([binary, '--lang', 'en', 'inspect', 'key.json'],
                                     cwd=tmp, capture_output=True, timeout=30)
            self.assertEqual(checked.returncode, 0, 'generated key cannot be inspected')


if __name__ == '__main__':
    unittest.main()
