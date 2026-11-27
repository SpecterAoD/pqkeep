//! DE: Vollständige KEM-Operationsflächen unter echter Ownersperre vergleichen.
//! EN: Compare complete KEM operation workspaces under actual owner locks.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::locked_owner_test_support::locked;
use ml_kem::kem::Decapsulate;

#[cfg(target_os = "linux")]
#[path = "kem_operation_denial_tests.rs"]
mod denial;

macro_rules! operation_variant {
    ($parameter:ty, $algorithm:expr) => {{
        let seed = rng::secret(64).unwrap();
        let mut encryption =
            SecretState::new(ml_kem::EncryptionWorkspace::<$parameter>::default()).unwrap();
        let mut decryption =
            SecretState::new(ml_kem::DecapsulationWorkspace::<$parameter>::default()).unwrap();
        let key = key_state::KeyState::<ml_kem::DecapsulationKey<$parameter>>::new(
            seed_state::view(&seed).unwrap(),
        )
        .unwrap();
        let encryption_address = std::ptr::from_ref(encryption.get()).addr();
        let decryption_address = std::ptr::from_ref(decryption.get()).addr();
        let encapsulated = encapsulation::run(|entropy, output, hash| {
            locked(encryption.get());
            let ciphertext = key
                .get()
                .encapsulation_key()
                .encapsulate_with_workspace(entropy, output, hash, encryption.get_mut())
                .map_err(|_| Error::Crypto)?;
            locked(encryption.get());
            Ok(ciphertext.to_vec())
        })
        .unwrap();
        for position in [
            None,
            Some(0),
            Some(encapsulated.ciphertext.len() / 2),
            Some(encapsulated.ciphertext.len() - 1),
        ] {
            let mut ciphertext = encapsulated.ciphertext.clone();
            if let Some(position) = position {
                ciphertext[position] ^= 0x80;
            }
            let mut expected = key.get().decapsulate_slice(&ciphertext).unwrap();
            let mut actual = SecretBytes::zeroed(38).unwrap();
            actual.expose_mut().fill(0xa5);
            locked(decryption.get());
            key.get()
                .decapsulate_with_workspace(
                    ciphertext.as_slice().try_into().unwrap(),
                    decryption.get_mut(),
                    (&mut actual.expose_mut()[3..35]).try_into().unwrap(),
                )
                .unwrap();
            assert!(actual.expose()[3..35].eq(expected.as_slice()));
            assert!(actual.expose()[..3].iter().all(|byte| *byte == 0xa5));
            assert!(actual.expose()[35..].iter().all(|byte| *byte == 0xa5));
            let root = decapsulate($algorithm, seed.expose(), &ciphertext).unwrap();
            assert!(root.expose().eq(expected.as_slice()));
            expected.zeroize();
            locked(decryption.get());
            decryption.get_mut().zeroize();
        }
        let stable = std::ptr::from_ref(encryption.get()).addr() == encryption_address
            && std::ptr::from_ref(decryption.get()).addr() == decryption_address;
        assert!(stable);
        let redacted = format!("{:?}", encryption.get()) == "EncryptionWorkspace { .. }"
            && format!("{:?}", decryption.get()) == "DecapsulationWorkspace { .. }";
        assert!(redacted);
        encryption.get_mut().zeroize();
        locked(encryption.get());
        locked(decryption.get());
    }};
}

#[test]
fn kem512_operation_workspaces_cover_valid_and_rejected_candidates() {
    operation_variant!(MlKem512, KemAlgorithm::MlKem512);
}

#[test]
fn kem768_operation_workspaces_cover_valid_and_rejected_candidates() {
    operation_variant!(MlKem768, KemAlgorithm::MlKem768);
}

#[test]
fn kem1024_operation_workspaces_cover_valid_and_rejected_candidates() {
    operation_variant!(MlKem1024, KemAlgorithm::MlKem1024);
}

struct ObservedWorkspace<'a> {
    inner: ml_kem::DecapsulationWorkspace<MlKem512>,
    cleaned_locked: &'a std::cell::Cell<bool>,
}

impl zeroize::ZeroizeOnDrop for ObservedWorkspace<'_> {}

impl Drop for ObservedWorkspace<'_> {
    fn drop(&mut self) {
        self.inner.zeroize();
        locked(&self.inner);
        self.cleaned_locked.set(true);
    }
}

fn fail_after_private_operation(
    key: &ml_kem::DecapsulationKey<MlKem512>,
    ciphertext: &[u8],
    unwind: bool,
    cleaned_locked: &std::cell::Cell<bool>,
) -> Result<()> {
    let mut workspace = SecretState::new(ObservedWorkspace {
        inner: ml_kem::DecapsulationWorkspace::default(),
        cleaned_locked,
    })?;
    let mut out = SecretBytes::zeroed(32)?;
    key.decapsulate_with_workspace(
        ciphertext.try_into().map_err(|_| Error::Crypto)?,
        &mut workspace.get_mut().inner,
        out.expose_mut().try_into().map_err(|_| Error::Crypto)?,
    )
    .map_err(|_| Error::Crypto)?;
    locked(workspace.get());
    if unwind {
        std::panic::resume_unwind(Box::new(()));
    }
    Err(Error::Crypto)
}

#[test]
fn populated_private_operation_workspace_is_wiped_under_lock_on_error_and_unwind() {
    crate::locked_owner_test_support::isolated_test(
        "crypto::kem::operation_workspace_tests::operation_cleanup_child",
        "PQKEEP_KEM_CLEANUP_CHILD",
    );
}

#[test]
#[ignore = "DE/EN: Exakte Zähler nur im eigenen Kind / exact counters only in own child."]
fn operation_cleanup_child() {
    assert_eq!(std::env::var("PQKEEP_KEM_CLEANUP_CHILD").unwrap(), "1");
    let seed = rng::secret(64).unwrap();
    let key = key_state::KeyState::<ml_kem::DecapsulationKey<MlKem512>>::new(
        seed_state::view(&seed).unwrap(),
    )
    .unwrap();
    let public = key.get().encapsulation_key().to_bytes();
    let ciphertext = encapsulate(KemAlgorithm::MlKem512, &public)
        .unwrap()
        .ciphertext;
    for unwind in [false, true] {
        let before = crate::hardening::memlock::stats().locked_pages;
        let cleaned = std::cell::Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fail_after_private_operation(key.get(), &ciphertext, unwind, &cleaned)
        }));
        assert_eq!(result.is_err(), unwind);
        if !unwind {
            assert!(matches!(result, Ok(Err(Error::Crypto))));
        }
        assert!(cleaned.get());
        assert_eq!(crate::hardening::memlock::stats().locked_pages, before);
    }
}
