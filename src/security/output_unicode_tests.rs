//! DE: Gesperrtes Transcoding, kurze Writes und Löschen bei Fehlern direkt beobachten.
//! EN: Directly observe locked transcoding, short writes and wiping on errors.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{crypto::secret_buffer::SecretBuffer, hardening::memlock};

#[test]
fn locked_unicode_workspace_handles_boundaries_and_short_writes() {
    for capacity in [2, 3, 127, 128, 129, 1024] {
        let mut storage = SecretBuffer::new(vec![0u16; capacity]).unwrap();
        let fixture = format!("{}α中🙂{}", "x".repeat(1023), "y".repeat(1025));
        let mut actual = Vec::new();
        write_text(storage.expose_mut(), &fixture, |words| {
            assert!(memlock::is_locked(words.as_ptr().addr()));
            assert!(memlock::is_locked(
                words.as_ptr().addr() + size_of_val(words) - 1
            ));
            actual.push(words[0]);
            Ok(1)
        })
        .unwrap();
        assert_eq!(actual, fixture.encode_utf16().collect::<Vec<_>>());
        assert!(storage.expose().iter().all(|word| *word == 0));
    }
}

#[test]
fn unicode_workspace_is_wiped_on_backend_error_and_zero_or_invalid_progress() {
    for result in [Err(io::ErrorKind::BrokenPipe), Ok(0), Ok(1025)] {
        let mut storage = SecretBuffer::new(vec![0u16; 1024]).unwrap();
        let error = write_text(storage.expose_mut(), "α中🙂", |words| {
            assert!(memlock::is_locked(words.as_ptr().addr()));
            result.map_err(io::Error::from)
        });
        assert!(error.is_err());
        assert!(storage.expose().iter().all(|word| *word == 0));
    }
}
