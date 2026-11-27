//! DE: Verborgene Signaturpfade mit echtem Unwind und Sperrverweigerung.
//! EN: Hidden signature paths under actual unwind and memory-lock denial.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{crypto::SecretBytes, hardening::memlock};
use rustix::process::{Resource, getrlimit, setrlimit};

#[test]
fn confidential_workspace_denial_and_unwind_run_in_an_owned_child() {
    let before = getrlimit(Resource::Memlock);
    crate::locked_owner_test_support::isolated_test(
        "crypto::dsa::confidential_verify::denial_tests::confidential_workspace_child",
        "PQKEEP_CONFIDENTIAL_DSA_CHILD",
    );
    assert_eq!(getrlimit(Resource::Memlock), before);
}

#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded owned child only"]
fn confidential_workspace_child() {
    assert_eq!(std::env::var("PQKEEP_CONFIDENTIAL_DSA_CHILD").unwrap(), "1");
    let algorithm = DsaAlgorithm::MlDsa44;
    let key = super::super::generate(algorithm).unwrap();
    let public = SecretBytes::from_slice(&key.public_key).unwrap();
    let signature =
        super::super::sign_confidential(algorithm, key.seed().expose(), b"message", b"ctx")
            .unwrap();
    let baseline = memlock::stats().locked_pages;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut state = State::<MlDsa44>::new().unwrap();
        let pk: &EncodedVerifyingKey<MlDsa44> = public.expose().try_into().unwrap();
        let sig: &EncodedSignature<MlDsa44> = signature.expose().try_into().unwrap();
        assert!(
            state
                .work
                .get_mut()
                .verify_encoded(pk, b"message", b"ctx", sig)
        );
        assert!(state.work.get().visit_private_storage(|addr, len| {
            memlock::is_locked(addr) && memlock::is_locked(addr + len - 1)
        }));
        std::panic::resume_unwind(Box::new(()));
    }));
    assert!(result.is_err());
    assert_eq!(memlock::stats().locked_pages, baseline);
    let mut limit = getrlimit(Resource::Memlock);
    limit.current = Some(0);
    setrlimit(Resource::Memlock, limit).unwrap();
    assert_eq!(getrlimit(Resource::Memlock).current, Some(0));
    let failure_count = memlock::stats().failed_attempts;
    assert!(matches!(
        verify(
            algorithm,
            public.expose(),
            b"message",
            b"ctx",
            signature.expose()
        ),
        Err(Error::MemoryLock)
    ));
    assert!(matches!(
        super::super::sign_confidential(algorithm, key.seed().expose(), b"message", b"ctx"),
        Err(Error::MemoryLock)
    ));
    assert!(memlock::stats().failed_attempts >= failure_count + 2);
    assert_eq!(memlock::stats().locked_pages, baseline);
}
