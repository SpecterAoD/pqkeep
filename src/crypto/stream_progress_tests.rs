//! DE: Laufende private Zähler am echten Strom und bei Verweigerung prüfen.
//! EN: Check live private counters on the real stream and under denial.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::locked_owner_test_support::locked;

#[test]
fn stream_counters_stay_locked_across_partial_chunks_and_moves() {
    let mut key = SecretBytes::zeroed(32).unwrap();
    crate::crypto::rng::fill(key.expose_mut()).unwrap();
    let plain = vec![23; CHUNK_SIZE + 17];
    let mut enc =
        EncryptWriter::new(key.expose(), [0; PREFIX_LEN], b"public fixture", Vec::new()).unwrap();
    let base = std::ptr::from_ref(enc.progress.get()).addr();
    for part in plain.chunks(153) {
        enc.push(part).unwrap();
        locked(enc.progress.get());
        let stable = std::ptr::from_ref(enc.progress.get()).addr() == base;
        assert!(stable);
    }
    assert_eq!(enc.written(), plain.len() as u64);
    let (cipher, written) = enc.finish().unwrap();
    assert_eq!(written, plain.len() as u64);
    let mut dec = DecryptReader::new(
        key.expose(),
        [0; PREFIX_LEN],
        b"public fixture",
        cipher.as_slice(),
    )
    .unwrap();
    let base = std::ptr::from_ref(dec.progress.get()).addr();
    let mut buffer = SecretBytes::zeroed(131).unwrap();
    while dec.read(buffer.expose_mut()).unwrap() != 0 {
        locked(dec.progress.get());
        let stable = std::ptr::from_ref(dec.progress.get()).addr() == base;
        assert!(stable);
    }
    assert_eq!(dec.position(), plain.len() as u64);
    dec.finish().unwrap();
}

#[test]
fn counter_overflow_fails_before_copy_hash_or_output() {
    let mut key = SecretBytes::zeroed(32).unwrap();
    crate::crypto::rng::fill(key.expose_mut()).unwrap();
    let mut enc = EncryptWriter::new(key.expose(), [0; PREFIX_LEN], b"", Vec::new()).unwrap();
    enc.progress.get_mut().total = u64::MAX;
    assert!(matches!(enc.push(b"public fixture"), Err(Error::Crypto)));
    assert_eq!(enc.progress.get().cursor, 0);
    assert!(enc.buf.expose().iter().all(|b| *b == 0));
    let no_output = enc.inner.is_empty();
    assert!(no_output);
    let mut state = Progress::prepare().unwrap();
    state.get_mut().cursor = usize::MAX;
    assert!(matches!(state.get_mut().advance(1), Err(Error::Crypto)));
    assert_eq!(state.get().total, 0);
    state.get_mut().zeroize();
    assert_eq!((state.get().cursor, state.get().total), (0, 0));
}

#[cfg(target_os = "linux")]
#[test]
fn progress_denial_runs_in_own_child() {
    use rustix::process::{Resource, getrlimit};
    let before = getrlimit(Resource::Memlock);
    crate::locked_owner_test_support::isolated_test(
        "crypto::stream_io::progress_tests::progress_denial_child",
        "PQKEEP_PROGRESS_DENIAL_CHILD",
    );
    assert_eq!(getrlimit(Resource::Memlock), before);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded owned child only"]
fn progress_denial_child() {
    use crate::hardening::memlock;
    use rustix::process::{Resource, getrlimit, setrlimit};
    assert_eq!(std::env::var("PQKEEP_PROGRESS_DENIAL_CHILD").unwrap(), "1");
    let baseline = memlock::stats().locked_pages;
    let unwind = std::panic::catch_unwind(|| {
        let mut progress = Progress::prepare().unwrap();
        progress.get_mut().advance(123).unwrap();
        locked(progress.get());
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(unwind.is_err());
    assert_eq!(memlock::stats().locked_pages, baseline);
    let mut limit = getrlimit(Resource::Memlock);
    limit.current = Some(0);
    setrlimit(Resource::Memlock, limit).unwrap();
    assert_eq!(getrlimit(Resource::Memlock).current, Some(0));
    let failures = memlock::stats().failed_attempts;
    assert!(matches!(Progress::prepare(), Err(Error::MemoryLock)));
    assert!(memlock::stats().failed_attempts > failures);
    assert_eq!(memlock::stats().locked_pages, baseline);
}
