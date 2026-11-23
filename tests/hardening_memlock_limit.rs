//! DE: Ohne Speichersperre wird die Secret-Verarbeitung verweigert.
//! Eigene Testdatei, da die Grenze den ganzen Testprozess betrifft (nur Linux).
//! EN: Secret processing is refused when memory locking is unavailable.
//! Own test file because the limit affects the whole test process (Linux only).

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(target_os = "linux")]
struct Unread<'a>(&'a mut bool);
#[cfg(target_os = "linux")]
impl std::io::Read for Unread<'_> {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        *self.0 = true;
        Ok(0)
    }
}

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
    let mut called = false;
    assert!(matches!(
        pqkeep::sign::digest_reader(Unread(&mut called)),
        Err(pqkeep::Error::MemoryLock)
    ));
    assert!(!called);
    assert!(matches!(
        aead::seal(&[0; 32], b"synthetic", b""),
        Err(pqkeep::Error::MemoryLock)
    ));
    #[cfg(feature = "api")]
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        assert!(matches!(
            pqkeep::api::token::create(&path, pqkeep::envelope::Overwrite::No),
            Err(pqkeep::Error::MemoryLock)
        ));
        assert!(!path.exists());
    }
}
