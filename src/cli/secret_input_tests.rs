//! DE: Grenzen, Mehrzeilen-Pipes und Lesefehler. EN: Bounds, multi-line pipes and read errors.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{self, Cursor, Read};

struct Failing(bool);
impl Read for Failing {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0 {
            return Err(io::ErrorKind::Other.into());
        }
        self.0 = true;
        buf[0] = b'x';
        Ok(1)
    }
}

#[test]
fn one_line_never_consumes_the_next_secret() {
    let mut reader = Cursor::new(b"first\r\nsecond\n".as_slice());
    let first = super::read_line(&mut reader, 16).unwrap();
    assert!(first.is_locked() && first.expose() == b"first");
    let second = super::read_line(&mut reader, 16).unwrap();
    assert!(second.is_locked() && second.expose() == b"second");
}

#[test]
fn oversized_or_failed_input_never_returns_a_secret() {
    let mut long = Cursor::new(vec![b'x'; 18]);
    assert!(super::read_line(&mut long, 16).is_err());
    assert!(super::read_line(&mut Failing(false), 16).is_err());
}

#[test]
fn limit_and_empty_lines_are_bounded() {
    let mut exact = Cursor::new(vec![b'x'; 16]);
    assert_eq!(super::read_line(&mut exact, 16).unwrap().len(), 16);
    assert!(
        super::read_line(&mut Cursor::new(b"\n"), 16)
            .unwrap()
            .is_empty()
    );
}
