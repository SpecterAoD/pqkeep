//! DE: Budget nur im eigenen Testkind beschränken, Root-APIs müssen verweigern.
//! EN: Restrict only the own test child budget; Root APIs must refuse operation.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn public_gcm_operations_deny_unavailable_locks_in_bounded_child() {
    crate::locked_owner_test_support::isolated_test(
        "crypto::aead::workspace_tests::cleanup::denial::gcm_denial_child",
        "PQKEEP_GCM_DENIAL_CHILD",
    );
}

#[test]
#[ignore = "DE/EN: Nur im eigenen begrenzten Kind / bounded own child only."]
fn gcm_denial_child() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    assert_eq!(std::env::var("PQKEEP_GCM_DENIAL_CHILD").unwrap(), "1");
    // DE: Öffentliche zur Laufzeit erzeugte Fixture, kein privater Owner darf Seiten halten.
    // EN: Public runtime-generated fixture; no private owner may retain locked pages.
    let key: Vec<u8> = (0..32).map(|i| u8::try_from(i * 3 + 1).unwrap()).collect();
    let sealed = seal(&key, b"public fixture", b"public aad").unwrap();
    assert_eq!(memlock::stats().locked_pages, 0);
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
    assert!(matches!(cipher(&key), Err(Error::MemoryLock)));
    assert!(matches!(
        seal(&key, b"public fixture", b"public aad"),
        Err(Error::MemoryLock)
    ));
    assert!(matches!(
        open(&key, &sealed.nonce, &sealed.ciphertext, b"public aad"),
        Err(Error::MemoryLock)
    ));
    assert!(matches!(
        crate::crypto::stream::Stream::new(&key, [0; 7], b"public aad"),
        Err(Error::MemoryLock)
    ));
    assert_eq!(memlock::stats().locked_pages, 0);
}
