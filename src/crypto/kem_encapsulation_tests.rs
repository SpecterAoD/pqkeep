//! DE: Tatsächliche Caller-Flächen und unabhängige alte Kapselungs-API vergleichen.
//! EN: Compare actual caller storage with the unchanged legacy encapsulation API.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::locked_owner_test_support::locked;
use ml_kem::{
    EncapsulateWithWorkspace,
    kem::{Decapsulate, FromSeed, KeyExport},
};
use sha3::{Digest, Sha3_256, Sha3_512};
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
#[path = "kem_encapsulation_denial_tests.rs"]
mod denial;

fn check_full_g(entropy: &B32, actual: &EncapsulationWorkspace, public_key: &[u8]) {
    let public_hash = Sha3_256::digest(public_key);
    let mut hash = Sha3_512::new();
    hash.update(entropy);
    hash.update(public_hash);
    let mut expected = hash.finalize();
    assert!(actual.as_slice().eq(expected.as_slice()));
    expected.zeroize();
}

macro_rules! compare_variant {
    ($parameter:ty) => {{
        let seed = rng::secret(64).unwrap();
        let (dk, ek) = <$parameter>::from_seed(seed_state::view(&seed).unwrap());
        let visited = std::cell::Cell::new(0);
        let mut pke =
            SecretState::new(ml_kem::EncryptionWorkspace::<$parameter>::default()).unwrap();
        let result = run(|entropy, workspace, hash| {
            locked(entropy);
            locked(workspace);
            locked(hash);
            let base = workspace.as_ptr();
            let (expected_ct, mut expected_key) = ek.encapsulate_deterministic(entropy);
            // DE: Öffentliche Altlast muss vor privatem Absorb verworfen werden.
            // EN: Public stale state must be reset before private absorption.
            hash.update(b"public stale hash state");
            locked(pke.get());
            let ciphertext = ek
                .encapsulate_with_workspace(entropy, workspace, hash, pke.get_mut())
                .map_err(|_| Error::Crypto)?;
            locked(pke.get());
            visited.set(visited.get() + 1);
            assert!(base == workspace.as_ptr());
            assert!(ciphertext == expected_ct);
            assert!(workspace[..32] == expected_key[..]);
            check_full_g(entropy, workspace, &ek.to_bytes());
            let mut reset_output = SecretBytes::zeroed(64).unwrap();
            sha3::digest::FixedOutputReset::finalize_into_reset(
                hash,
                reset_output.expose_mut().try_into().unwrap(),
            );
            assert!(reset_output.expose() == Sha3_512::digest([]).as_slice());
            let mut opened = dk.decapsulate(&ciphertext);
            assert!(opened == expected_key);
            opened.zeroize();
            expected_key.zeroize();
            locked(entropy);
            locked(workspace);
            locked(hash);
            Ok(ciphertext.to_vec())
        })
        .unwrap();
        assert_eq!(visited.get(), 1);
        locked::<B32>(result.shared_secret.expose().try_into().unwrap());
        let mut opened = dk.decapsulate_slice(&result.ciphertext).unwrap();
        assert!(opened.as_slice() == result.shared_secret.expose());
        opened.zeroize();
    }};
}

#[test]
fn protected_kem512_matches_legacy_hash_and_roundtrip_in_actual_locked_storage() {
    compare_variant!(ml_kem::MlKem512);
}

#[test]
fn protected_kem768_matches_legacy_hash_and_roundtrip_in_actual_locked_storage() {
    compare_variant!(ml_kem::MlKem768);
}

#[test]
fn protected_kem1024_matches_legacy_hash_and_roundtrip_in_actual_locked_storage() {
    compare_variant!(ml_kem::MlKem1024);
}

struct UnwindProbe<'a> {
    entropy: &'a B32,
    workspace: &'a EncapsulationWorkspace,
    hash: &'a Sha3_512,
    observed: &'a std::cell::Cell<bool>,
}

impl Drop for UnwindProbe<'_> {
    fn drop(&mut self) {
        locked(self.entropy);
        locked(self.workspace);
        locked(self.hash);
        self.observed.set(true);
    }
}

#[test]
fn private_encapsulation_inputs_remain_locked_during_actual_unwind() {
    let observed = std::cell::Cell::new(false);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = run(|entropy, workspace, hash| {
            hash.update(entropy);
            let _probe = UnwindProbe {
                entropy,
                workspace,
                hash,
                observed: &observed,
            };
            std::panic::resume_unwind(Box::new(()));
        });
    }));
    assert!(result.is_err() && observed.get());
}

#[test]
fn invalid_public_encapsulation_keys_remain_errors_for_all_parameter_sets() {
    for algorithm in [
        super::super::KemAlgorithm::MlKem512,
        super::super::KemAlgorithm::MlKem768,
        super::super::KemAlgorithm::MlKem1024,
    ] {
        assert!(matches!(
            super::super::encapsulate(algorithm, &[]),
            Err(Error::InvalidInput {
                field: "public_key"
            })
        ));
    }
}
