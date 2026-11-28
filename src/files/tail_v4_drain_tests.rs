//! DE: Rückhalt, echte Sperren und Fehlerbereinigung über den AEAD-Strom prüfen.
//! EN: Check holdback, actual locks and failure cleanup through the AEAD stream.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::crypto::{
    rng,
    stream::{EncryptWriter, PREFIX_LEN},
};
use crate::locked_owner_test_support::locked;

fn key() -> SecretBytes {
    let mut key = SecretBytes::zeroed(32).unwrap();
    rng::fill(key.expose_mut()).unwrap();
    key
}

fn seal(key: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut enc = EncryptWriter::new(key, [0; PREFIX_LEN], b"public fixture", Vec::new()).unwrap();
    enc.push(plain).unwrap();
    enc.finish().unwrap().0
}

#[test]
fn streamed_holdback_matches_public_fixture_and_retains_locked_state() {
    let key = key();
    for len in [
        0,
        1,
        CHUNK_SIZE - TRAILER_LEN,
        CHUNK_SIZE,
        2 * CHUNK_SIZE + 3,
    ] {
        let mut plain = vec![19; len];
        plain.extend_from_slice(&[0; 37]);
        plain.extend_from_slice(&[71; TRAILER_LEN]);
        let encrypted = seal(key.expose(), &plain);
        let mut dec = DecryptReader::new(
            key.expose(),
            [0; PREFIX_LEN],
            b"public fixture",
            encrypted.as_slice(),
        )
        .unwrap();
        let mut output = Vec::new();
        let mut drained = drain(&mut dec, &mut output, TRAILER_LEN, None).unwrap();
        dec.finish().unwrap();
        let equal = output == plain[..plain.len() - TRAILER_LEN];
        assert!(equal);
        let equal = drained.bytes().unwrap() == [71; TRAILER_LEN];
        assert!(equal);
        assert_eq!(drained.written(), (len + 37) as u64);
        assert_eq!(drained.zeros(), 37);
        locked(drained.0.get());
        let buffer = drained.0.get().buffer.as_ref().unwrap();
        buffer.assert_metadata_locked();
        locked(buffer.expose());
        drained.0.get_mut().zeroize();
        assert!(drained.0.get().buffer.is_none());
        assert_eq!(
            (drained.written(), drained.zeros(), drained.0.get().held),
            (0, 0, 0)
        );
    }
}

#[test]
fn rejects_short_holdback_and_short_authenticated_stream() {
    assert!(matches!(
        Drained::prepare(TRAILER_LEN - 1),
        Err(Error::Crypto)
    ));
    assert!(Drained::prepare(usize::MAX).is_err());
    let key = key();
    let encrypted = seal(key.expose(), b"public short fixture");
    let mut dec = DecryptReader::new(
        key.expose(),
        [0; PREFIX_LEN],
        b"public fixture",
        encrypted.as_slice(),
    )
    .unwrap();
    assert!(matches!(
        drain(&mut dec, &mut std::io::sink(), TRAILER_LEN, None),
        Err(Error::InvalidInput { field: "trailer" })
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn drain_failure_cleanup_and_denial_preserve_parent_limit() {
    use rustix::process::{Resource, getrlimit};
    let before = getrlimit(Resource::Memlock);
    crate::locked_owner_test_support::isolated_test(
        "files::tail_v4_drain::tests::drain_failure_child",
        "PQKEEP_DRAIN_FAILURE_CHILD",
    );
    assert_eq!(getrlimit(Resource::Memlock), before);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded owned child only"]
fn drain_failure_child() {
    use crate::hardening::memlock;
    use rustix::process::{Resource, getrlimit, setrlimit};
    assert_eq!(std::env::var("PQKEEP_DRAIN_FAILURE_CHILD").unwrap(), "1");
    let key = key();
    let encrypted = seal(key.expose(), &vec![1; CHUNK_SIZE + TRAILER_LEN]);
    let baseline = memlock::stats().locked_pages;
    for panic in [false, true] {
        let result = std::panic::catch_unwind(|| {
            let mut dec = DecryptReader::new(
                key.expose(),
                [0; PREFIX_LEN],
                b"public fixture",
                encrypted.as_slice(),
            )
            .unwrap();
            let mut writer = FailingWriter { panic };
            assert!(drain(&mut dec, &mut writer, TRAILER_LEN, None).is_err());
        });
        assert_eq!(result.is_err(), panic);
        assert_eq!(memlock::stats().locked_pages, baseline);
    }
    let mut limit = getrlimit(Resource::Memlock);
    limit.current = Some(0);
    setrlimit(Resource::Memlock, limit).unwrap();
    assert_eq!(getrlimit(Resource::Memlock).current, Some(0));
    let failures = memlock::stats().failed_attempts;
    assert!(matches!(
        Drained::prepare(TRAILER_LEN),
        Err(Error::MemoryLock)
    ));
    assert!(memlock::stats().failed_attempts > failures);
    assert_eq!(memlock::stats().locked_pages, baseline);
}

#[cfg(target_os = "linux")]
struct FailingWriter {
    panic: bool,
}

#[cfg(target_os = "linux")]
impl Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        if self.panic {
            std::panic::resume_unwind(Box::new(()));
        }
        Err(std::io::Error::other("public test failure"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
