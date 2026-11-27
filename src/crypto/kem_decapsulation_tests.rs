//! DE: Geliehene Entkapselungsausgabe, implizite Ablehnung und alte API vergleichen.
//! EN: Compare borrowed decapsulation output, implicit rejection and the legacy API.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::locked_owner_test_support::locked;
use ml_kem::DecapsulateInto;
use ml_kem::{B32, kem::Decapsulate};

macro_rules! compare_variant {
    ($parameter:ty, $algorithm:expr) => {{
        let seed = rng::secret(SEED_LEN).unwrap();
        let (dk, ek) = <$parameter>::from_seed(seed_state::view(&seed).unwrap());
        let entropy = rng::secret(32).unwrap();
        let (mut ciphertext, mut expected) =
            ek.encapsulate_deterministic(seed_state::view(&entropy).unwrap());
        let mut storage = rng::secret(38).unwrap();
        let before = SecretBytes::from_slice(storage.expose()).unwrap();
        {
            let out: &mut B32 = (&mut storage.expose_mut()[3..35]).try_into().unwrap();
            locked(out);
            let address = out.as_ptr();
            dk.decapsulate_into(&ciphertext, out);
            assert!(address == out.as_ptr());
            assert!(out.as_slice() == expected.as_slice());
            locked(out);
        }
        assert!(storage.expose()[..3] == before.expose()[..3]);
        assert!(storage.expose()[35..] == before.expose()[35..]);
        let actual = decapsulate($algorithm, seed.expose(), &ciphertext).unwrap();
        locked::<B32>(actual.expose().try_into().unwrap());
        assert!(actual.expose() == expected.as_slice());
        for index in [0, ciphertext.len() / 2, ciphertext.len() - 1] {
            ciphertext[index] ^= 1;
            let mut legacy = dk.decapsulate(&ciphertext);
            let out: &mut B32 = (&mut storage.expose_mut()[3..35]).try_into().unwrap();
            dk.decapsulate_slice_into(&ciphertext, out).unwrap();
            assert!(out.as_slice() == legacy.as_slice());
            let actual = decapsulate($algorithm, seed.expose(), &ciphertext).unwrap();
            assert!(actual.expose() == legacy.as_slice());
            assert!(actual.expose() != expected.as_slice());
            legacy.zeroize();
            ciphertext[index] ^= 1;
        }
        expected.zeroize();
    }};
}

#[test]
fn borrowed_decapsulation_512_matches_roundtrip_and_implicit_rejection() {
    compare_variant!(MlKem512, KemAlgorithm::MlKem512);
}

#[test]
fn borrowed_decapsulation_768_matches_roundtrip_and_implicit_rejection() {
    compare_variant!(MlKem768, KemAlgorithm::MlKem768);
}

#[test]
fn borrowed_decapsulation_1024_matches_roundtrip_and_implicit_rejection() {
    compare_variant!(MlKem1024, KemAlgorithm::MlKem1024);
}

macro_rules! check_lengths {
    ($parameter:ty) => {{
        let seed = rng::secret(SEED_LEN).unwrap();
        let (dk, _) = <$parameter>::from_seed(seed_state::view(&seed).unwrap());
        let correct = size_of::<ml_kem::kem::Ciphertext<$parameter>>();
        let mut bytes = rng::secret(32).unwrap();
        let before = SecretBytes::from_slice(bytes.expose()).unwrap();
        for len in [0, 1, correct - 1, correct + 1] {
            let public_ciphertext = vec![0; len];
            let out: &mut B32 = bytes.expose_mut().try_into().unwrap();
            assert!(dk.decapsulate_slice_into(&public_ciphertext, out).is_err());
            assert!(out.as_slice() == before.expose());
            locked(out);
        }
    }};
}

#[test]
fn rejected_ciphertext_lengths_leave_borrowed_output_unchanged_in_all_parameter_sets() {
    check_lengths!(MlKem512);
    check_lengths!(MlKem768);
    check_lengths!(MlKem1024);
}
