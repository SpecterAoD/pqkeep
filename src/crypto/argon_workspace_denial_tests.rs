//! DE: Nur eigener Testkindprozess; fehlende Sperren vor privatem Argon-Einstieg verweigern.
//! EN: Own test child only; refuse unavailable locks before private Argon processing.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn argon_entry_points_deny_unavailable_locks_in_bounded_child() {
    crate::locked_owner_test_support::isolated_test(
        "crypto::kdf::operation_workspace_tests::cleanup::denial::argon_denial_child",
        "PQKEEP_ARGON_DENIAL_CHILD",
    );
}

#[test]
#[ignore = "DE/EN: Nur im eigenen begrenzten Kind / bounded own child only."]
fn argon_denial_child() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    assert_eq!(std::env::var("PQKEEP_ARGON_DENIAL_CHILD").unwrap(), "1");
    // DE/EN: Öffentliche generierte Fixture, kein privater Owner bleibt gesperrt.
    // Public generated fixture, no retained locked private owner.
    let password: Vec<u8> = (0..32).map(|i| u8::try_from(i * 7 + 1).unwrap()).collect();
    let salt: Vec<u8> = (0..16).map(|i| u8::try_from(i * 11 + 3).unwrap()).collect();
    let params = KdfParams {
        memory_kib: MIN_MEMORY_KIB,
        iterations: 3,
        parallelism: 4,
    };
    let _ = derive(&password, &salt, &params).unwrap();
    assert_eq!(memlock::stats().locked_pages, 0);
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
    assert!(matches!(
        derive(&password, &salt, &params),
        Err(Error::MemoryLock)
    ));
    let mut out = [0xa5; 32];
    assert!(matches!(
        argon2id(&password, &salt, &params, &[], &[], &mut out),
        Err(Error::MemoryLock)
    ));
    assert!(out.iter().all(|byte| *byte == 0xa5));
    assert_eq!(memlock::stats().locked_pages, 0);
}
