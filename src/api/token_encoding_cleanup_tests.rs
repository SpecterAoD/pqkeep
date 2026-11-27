//! DE: Restblock-Wipe unter Sperre bei Fehler/Unwind; kein Ressourcen-Fallback.
//! EN: Remainder wipe under lock on error/unwind; no resource fallback.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;

struct Observed<'a> {
    work: Workspace,
    witness: &'a std::cell::Cell<bool>,
}

impl Drop for Observed<'_> {
    fn drop(&mut self) {
        self.work.wipe();
        locked(self.work.0.expose());
        assert!(self.work.0.expose().iter().all(|b| *b == 0));
        self.witness.set(true);
    }
}

#[test]
fn populated_remainder_is_wiped_under_lock_on_error_and_unwind() {
    crate::locked_owner_test_support::isolated_test(
        "api::token_encoding::tests::cleanup::base64_cleanup_child",
        "PQKEEP_BASE64_CLEANUP_CHILD",
    );
}

#[test]
#[ignore = "DE/EN: Exakte Zähler nur im eigenen Kind / exact counters only in own child."]
fn base64_cleanup_child() {
    assert_eq!(std::env::var("PQKEEP_BASE64_CLEANUP_CHILD").unwrap(), "1");
    let raw = crate::crypto::rng::secret(32).unwrap();
    let mut out = SecretBytes::zeroed(43).unwrap();
    let baseline = memlock::stats().locked_pages;
    for unwind in [false, true] {
        let witness = std::cell::Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut owner = Observed {
                work: Workspace::new().unwrap(),
                witness: &witness,
            };
            owner
                .work
                .encode::<Base64UrlUnpadded>(raw.expose(), out.expose_mut())
                .unwrap();
            assert!(owner.work.0.expose().iter().any(|b| *b != 0));
            if unwind {
                std::panic::resume_unwind(Box::new(()));
            }
            Err::<(), _>(Error::Crypto)
        }));
        assert_eq!(result.is_err(), unwind);
        assert!(witness.get());
        assert_eq!(memlock::stats().locked_pages, baseline);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn token_encoding_and_creation_deny_unavailable_locks_in_bounded_child() {
    crate::locked_owner_test_support::isolated_test(
        "api::token_encoding::tests::cleanup::base64_denial_child",
        "PQKEEP_BASE64_DENIAL_CHILD",
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "DE/EN: Budget nur im eigenen Kind senken / lower budget in own child only."]
fn base64_denial_child() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    assert_eq!(std::env::var("PQKEEP_BASE64_DENIAL_CHILD").unwrap(), "1");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token-hash");
    let mut output = [0xa5; 43];
    // DE/EN: Nur öffentliche Fixture; alle Warmup-Owner vor Budgetsenkung freigeben.
    // Public fixture only; release every warmup owner before lowering the budget.
    encode(&[1; 32], &mut output).unwrap();
    output.fill(0xa5);
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
        encode(&[1; 32], &mut output),
        Err(Error::MemoryLock)
    ));
    assert!(output.iter().all(|b| *b == 0xa5));
    assert!(matches!(
        crate::api::token::create(&path, crate::envelope::Overwrite::No),
        Err(Error::MemoryLock)
    ));
    assert!(!path.exists());
    assert_eq!(memlock::stats().locked_pages, 0);
}
