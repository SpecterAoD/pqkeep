"""DE: Echte verdeckte PTY-Eingabe und Bestätigung. EN: Real hidden PTY input/confirmation."""
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(os.name == 'posix', 'Linux PTY test')
class TerminalSecretTests(unittest.TestCase):
    def test_confirmation_retry_backspace_and_no_echo(self):
        import pty
        import termios
        binary = str(Path(os.environ.get('PQKEEP_BINARY', 'target/debug/pqkeep')).resolve())
        secret = subprocess.check_output([binary, '--lang', 'en', 'passphrase'], timeout=30).strip()
        with tempfile.TemporaryDirectory(prefix='pqkeep-terminal-') as tmp:
            master, slave = pty.openpty()
            self.addCleanup(os.close, master)
            self.addCleanup(os.close, slave)
            original_mode = termios.tcgetattr(slave)
            child = subprocess.Popen([binary, '--lang', 'en', 'generate', '--algorithm',
                                      'aes-256', '--name', 'PTY test', '--out', 'key.json'],
                                     stdin=slave, stderr=slave, stdout=subprocess.PIPE, cwd=tmp)
            self.addCleanup(lambda: child.kill() if child.poll() is None else None)
            transcript = bytearray()

            def expect(prompt):
                print("PTY prompt: " + prompt.decode("ascii"), file=sys.stderr, flush=True)
                start = len(transcript)
                deadline = time.monotonic() + 90
                while prompt not in transcript[start:]:
                    self.assertLess(time.monotonic(), deadline, 'terminal prompt timed out: ' + prompt.decode('ascii'))
                    ready, _, _ = select.select([master], [], [], 1)
                    if ready:
                        try:
                            data = os.read(master, 4096)
                        except OSError:
                            self.fail('terminal closed before expected prompt')
                        self.assertTrue(data, 'terminal closed')
                        transcript.extend(data)

            expect(b'New passphrase: ')
            os.write(master, secret + b'\r')
            expect(b'Repeat passphrase: ')
            os.write(master, secret + b'x\r')
            expect(b'New passphrase: ')
            # DE/EN: UTF-8-Zeichen vollständig zurücknehmen / remove whole UTF-8 character.
            os.write(master, secret + 'ü'.encode() + b'\x7f\r')
            expect(b'Repeat passphrase: ')
            os.write(master, secret + b'\r')
            child.communicate(timeout=180)
            self.assertEqual(child.returncode, 0, 'interactive generation failed')
            self.assertEqual(termios.tcgetattr(slave), original_mode, 'terminal mode not restored')
            self.assertTrue((Path(tmp) / 'key.json').is_file())
            self.assertFalse(secret in transcript, 'terminal echoed the secret')
            checked = subprocess.run([binary, '--lang', 'en', 'inspect', 'key.json'],
                                     cwd=tmp, capture_output=True, timeout=30)
            self.assertEqual(checked.returncode, 0, 'generated key cannot be inspected')


    def test_ctrl_c_restores_terminal_and_creates_no_key(self):
        import pty
        import termios
        binary = str(Path(os.environ.get('PQKEEP_BINARY', 'target/debug/pqkeep')).resolve())
        with tempfile.TemporaryDirectory(prefix='pqkeep-terminal-cancel-') as tmp:
            master, slave = pty.openpty()
            self.addCleanup(os.close, master)
            self.addCleanup(os.close, slave)
            original = termios.tcgetattr(slave)
            child = subprocess.Popen([binary, '--lang', 'en', 'generate', '--algorithm',
                                      'aes-256', '--name', 'PTY cancel', '--out', 'key.json'],
                                     stdin=slave, stderr=slave, stdout=subprocess.PIPE, cwd=tmp)
            self.addCleanup(lambda: child.kill() if child.poll() is None else None)
            transcript = bytearray()
            deadline = time.monotonic() + 30
            while b'New passphrase: ' not in transcript:
                self.assertLess(time.monotonic(), deadline, 'cancel prompt timed out')
                ready, _, _ = select.select([master], [], [], 1)
                if ready:
                    transcript.extend(os.read(master, 4096))
            os.write(master, b'\x03')
            child.communicate(timeout=30)
            self.assertNotEqual(child.returncode, 0, 'cancel was accepted as success')
            self.assertEqual(termios.tcgetattr(slave), original, 'cancel did not restore mode')
            self.assertFalse((Path(tmp) / 'key.json').exists())

    def test_redirected_prompt_stream_fails_without_reading_input(self):
        import pty
        binary = str(Path(os.environ.get('PQKEEP_BINARY', 'target/debug/pqkeep')).resolve())
        with tempfile.TemporaryDirectory(prefix='pqkeep-terminal-redirect-') as tmp:
            master, slave = pty.openpty()
            self.addCleanup(os.close, master)
            self.addCleanup(os.close, slave)
            child = subprocess.Popen([binary, '--lang', 'en', 'generate', '--algorithm',
                                      'aes-256', '--name', 'PTY redirected', '--out', 'key.json'],
                                     stdin=slave, stderr=subprocess.PIPE,
                                     stdout=subprocess.PIPE, cwd=tmp)
            self.addCleanup(lambda: child.kill() if child.poll() is None else None)
            child.communicate(timeout=15)
            self.assertNotEqual(child.returncode, 0, 'redirected prompt accepted')
            self.assertFalse((Path(tmp) / 'key.json').exists())

if __name__ == '__main__':
    unittest.main()
