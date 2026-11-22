//! DE: Ohne Speichersperre wird die Secret-Verarbeitung verweigert.
//! Eigene Testdatei, da die Grenze den ganzen Testprozess betrifft (nur Linux).
//! EN: Secret processing is refused when memory locking is unavailable.
//! Own test file because the limit affects the whole test process (Linux only).

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(target_os = "linux")]
#[test]
fn locking_failure_refuses_secret_processing() {
    use pqkeep::crypto::{SecretBytes, aead};
    use pqkeep::hardening::memlock;
    use rustix::process::{Resource, Rlimit, setrlimit};

    let zero = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    setrlimit(Resource::Memlock, zero).unwrap();

    let before = memlock::stats();
    assert!(matches!(
        SecretBytes::new(vec![1u8; 4096]),
        Err(pqkeep::Error::MemoryLock)
    ));
    assert!(memlock::stats().failed_attempts > before.failed_attempts);
    assert!(matches!(
        aead::generate_key(),
        Err(pqkeep::Error::MemoryLock)
    ));
}
