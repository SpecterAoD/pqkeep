//! DE: Rekey-Framing und gesperrte Leseziele. EN: Rekey framing and locked read targets.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::hardening::memlock;
use pqkeep::security::Lang;
use std::io::{self, Cursor, Read};

struct Observed {
    input: Cursor<Vec<u8>>,
    interrupted: bool,
}

impl Read for Observed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert!(memlock::is_locked(buf.as_ptr().addr()));
        assert_eq!(buf.len(), 1);
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.input.read(buf)
    }
}

#[test]
fn rekey_reads_only_locked_bytes_without_read_ahead() {
    let mut input = Observed {
        input: Cursor::new(b"old\r\nnew\nconfirm\n".to_vec()),
        interrupted: false,
    };
    for expected in [b"old".as_slice(), b"new", b"confirm"] {
        let line = super::line(&mut input, Lang::En).ok().unwrap();
        assert!(line.is_locked() && line.expose() == expected);
    }
    assert_eq!(input.input.position(), 17);
}

#[test]
fn newline_counts_toward_the_unchanged_rekey_limit() {
    for payload in [0, 1, 4094, 4095, 4096, 4097] {
        let mut input = vec![b'x'; payload];
        input.push(b'\n');
        let result = super::line(&mut Cursor::new(input), Lang::En);
        assert_eq!(result.is_ok(), payload < super::MAX_LINE);
        if let Ok(line) = result {
            assert_eq!(line.len(), payload);
        }
    }
}

#[test]
fn rekey_rejects_missing_newline_and_embedded_carriage_return() {
    for input in [b"".as_slice(), b"no-newline", b"a\rb\n", b"a\r\r\n"] {
        assert!(super::line(&mut Cursor::new(input), Lang::En).is_err());
    }
    let line = super::line(&mut Cursor::new(b"\r\n"), Lang::En)
        .ok()
        .unwrap();
    assert!(line.is_empty());
}

struct Failed;
impl Read for Failed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert!(memlock::is_locked(buf.as_ptr().addr()));
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

#[test]
fn read_failure_never_returns_a_rekey_secret() {
    assert!(super::line(&mut Failed, Lang::En).is_err());
}
