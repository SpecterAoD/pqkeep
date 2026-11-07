//! DE: Best effort: Ist Sperren nicht erlaubt (Grenze `RLIMIT_MEMLOCK` = 0), läuft
//! alles weiter; das Geheimnis gilt als nicht gesperrt und der Fehlschlag wird gezählt.
//! Eigene Testdatei, da die Grenze den ganzen Testprozess betrifft (nur Linux).
//! EN: Best effort: if locking is not allowed (`RLIMIT_MEMLOCK` = 0), everything
//! continues; the secret counts as not locked and the failure is counted.
//! Own test file because the limit affects the whole test process (Linux only).

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(target_os = "linux")]
#[test]
fn locking_failure_is_tolerated_and_reported() {
    use pqkeep::crypto::{SecretBytes, aead};
    use pqkeep::hardening::memlock;
    use rustix::process::{Resource, Rlimit, getuid, setrlimit};

    if getuid().is_root() {
        // DE: root darf trotz Grenze sperren (CAP_IPC_LOCK) – Test nicht aussagekräftig.
        // EN: root may lock despite the limit (CAP_IPC_LOCK) – test not meaningful.
        return;
    }
    let zero = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    setrlimit(Resource::Memlock, zero).unwrap();

    let before = memlock::stats();
    let secret = SecretBytes::new(vec![1u8; 4096]);
    assert!(!secret.is_locked());
    assert!(memlock::stats().failed_attempts > before.failed_attempts);
    assert_eq!(secret.expose().len(), 4096);

    // DE: Kryptografie funktioniert weiter. EN: Cryptography keeps working.
    let key = aead::generate_key().unwrap();
    let sealed = aead::seal(key.expose(), b"data", b"").unwrap();
    let opened = aead::open(key.expose(), &sealed.nonce, &sealed.ciphertext, b"").unwrap();
    assert_eq!(opened.expose(), b"data");
}
