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
            os.write(master, secret)
            for byte in '🚀'.encode():
                os.write(master, bytes([byte]))
                time.sleep(0.02)
            os.write(master, b'\x7f\x1b[D\r')
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

    def _write_bounded(self, master, child, data):
        os.set_blocking(master, False)
        end = time.monotonic() + 10
        offset = 0
        while offset < len(data) and child.poll() is None:
            self.assertLess(time.monotonic(), end, 'input fixture write timed out')
            if select.select([], [master], [], 0.1)[1]:
                try:
                    offset += os.write(master, data[offset:offset + 512])
                except BlockingIOError:
                    pass

    def _reject(self, payload):
        import pty
        import termios
        binary = str(Path(os.environ.get('PQKEEP_BINARY', 'target/debug/pqkeep')).resolve())
        marker = os.urandom(12).hex().encode('ascii')
        with tempfile.TemporaryDirectory(prefix='pqkeep-terminal-invalid-') as tmp:
            master, slave = pty.openpty()
            self.addCleanup(os.close, master)
            self.addCleanup(os.close, slave)
            original = termios.tcgetattr(slave)
            child = subprocess.Popen([binary, '--lang', 'en', 'generate', '--algorithm',
                                      'aes-256', '--name', 'PTY input fixture', '--out', 'key.json'],
                                     stdin=slave, stderr=slave, stdout=subprocess.PIPE, cwd=tmp)
            self.addCleanup(lambda: child.kill() if child.poll() is None else None)
            transcript = bytearray()
            end = time.monotonic() + 30
            while b'New passphrase: ' not in transcript:
                self.assertLess(time.monotonic(), end, 'rejection prompt timed out')
                self.assertIsNone(child.poll(), 'child exited before protected input')
                if select.select([master], [], [], 0.1)[0]:
                    transcript.extend(os.read(master, 4096))
            self._write_bounded(master, child, marker + payload)
            child.communicate(timeout=15)
            while select.select([master], [], [], 0)[0]:
                transcript.extend(os.read(master, 4096))
            self.assertNotEqual(child.returncode, 0, 'invalid input was accepted')
            self.assertEqual(termios.tcgetattr(slave), original, 'error did not restore mode')
            self.assertFalse(marker in transcript, 'terminal echoed the runtime fixture')
            self.assertFalse((Path(tmp) / 'key.json').exists())
            return slave, transcript

    def test_escape_alone_restores_mode_without_echo(self):
        self._reject(b'\x1b')

    def test_invalid_and_truncated_utf8_restore_mode(self):
        # DE: Enter nach unvollständigem UTF8 ist ungültig, kein Ersatzzeichen.
        # EN: Enter after incomplete UTF8 is invalid, never a replacement character.
        for payload in [b'\x80', b'\xc0\xaf', b'\xe2\r', b'\xed\xa0\x80', b'\xf4\x90\x80\x80']:
            with self.subTest(case=payload.hex()):
                self._reject(payload)

    def test_input_and_escape_sequences_are_bounded(self):
        for payload in [b'x' * 32768, b'\x1b[' + b'0' * 33]:
            with self.subTest(length=len(payload)):
                self._reject(payload)

    def test_rejected_input_discards_already_queued_suffix(self):
        import tty
        import termios
        slave, _ = self._reject(b'\x80' + os.urandom(12).hex().encode() + b'\n')
        # DE: Nur eigene öffentliche Fixture beobachten; Modus war bereits geprüft.
        # EN: Inspect only the own public fixture after restoration was checked.
        tty.setraw(slave, termios.TCSANOW)
        self.assertFalse(select.select([slave], [], [], 0)[0], 'private suffix remained queued')

    def test_typeahead_confirmation_survives_until_cancel_then_discards_suffix(self):
        import tty
        import termios
        slave, transcript = self._reject(b'\r\x03' + os.urandom(12).hex().encode() + b'\n')
        self.assertTrue(b'Repeat passphrase: ' in transcript, 'typed-ahead confirmation lost')
        tty.setraw(slave, termios.TCSANOW)
        self.assertFalse(select.select([slave], [], [], 0)[0], 'cancel suffix remained queued')

if __name__ == '__main__':
    unittest.main()
