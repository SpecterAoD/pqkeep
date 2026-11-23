//! DE: Echte Hash-Leseziele vor Verarbeitung gesperrt, kurze Reads und Fehler.
//! EN: Actual hash read targets locked before processing, short reads and failures.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::hardening::memlock;
use pqkeep::sign::digest_reader;
use sha3::{Digest, Sha3_512};
use std::io::{self, Read};

struct Input {
    remaining: usize,
    interrupted: bool,
    fail: bool,
}

impl Read for Input {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        assert!(memlock::is_locked(target.as_ptr().addr()));
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.fail {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let n = self.remaining.min(target.len()).min(4093);
        target[..n].fill(0x5a);
        self.remaining -= n;
        Ok(n)
    }
}

#[test]
fn hash_targets_stay_locked_across_short_reads_and_chunk_boundaries() {
    for size in [
        0, 1, 4095, 4096, 4097, 8191, 8192, 8193, 65535, 65536, 65537,
    ] {
        let input = Input {
            remaining: size,
            interrupted: false,
            fail: false,
        };
        let result = digest_reader(input).unwrap();
        let expected: [u8; 64] = Sha3_512::digest(vec![0x5a; size]).into();
        assert_eq!(result.size, size as u64);
        assert_eq!(result.sha3_512, expected);
    }
}

#[test]
fn failed_hash_read_never_returns_a_digest() {
    let input = Input {
        remaining: 32,
        interrupted: false,
        fail: true,
    };
    assert_eq!(
        digest_reader(input),
        Err(pqkeep::Error::Io(io::ErrorKind::PermissionDenied))
    );
}
