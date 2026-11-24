//! DE: Tatsächliche feste Seedtypen vor Befüllung, nach Bewegungen und beim Löschen.
//! EN: Actual fixed seed types before population, after moves and during wiping.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{crypto::rng, locked_owner_test_support::locked};
use ml_kem::{MlKem512, MlKem768, MlKem1024};
use zeroize::Zeroize;

fn prepared<N: ArraySize>(public: &Array<u8, N>) {
    let width = public.len();
    assert_eq!(size_of::<Array<u8, N>>(), width);
    let state = SecretBytes::zeroed(width).unwrap();
    state.assert_metadata_locked();
    let typed = view::<N>(&state).unwrap();
    locked(typed);
    let bytes = typed.as_slice();
    assert!(std::ptr::eq(bytes.as_ptr(), state.expose().as_ptr()));
    assert!(bytes.iter().all(|byte| *byte == 0));
}

#[test]
fn concrete_seed_arrays_are_locked_before_private_copy() {
    prepared(&ml_dsa::Seed::default());
    prepared(&ml_kem::kem::Seed::<MlKem512>::default());
    prepared(&ml_kem::kem::Seed::<MlKem768>::default());
    prepared(&ml_kem::kem::Seed::<MlKem1024>::default());
}

fn moved_and_wiped<N: ArraySize>(public: &Array<u8, N>) {
    let fixture = rng::secret(public.len()).unwrap();
    let state = parse(fixture.expose(), public.len()).unwrap();
    let address = state.expose().as_ptr();
    let mut moved = Box::new(state);
    moved.assert_metadata_locked();
    let typed = view::<N>(&moved).unwrap();
    locked(typed);
    let bytes = typed.as_slice();
    assert!(std::ptr::eq(bytes.as_ptr(), address));
    assert!(bytes.iter().eq(fixture.expose().iter()));
    moved.zeroize();
    assert!(moved.is_empty());
    assert!(std::ptr::eq(moved.expose().as_ptr(), address));
    assert!(matches!(
        view::<N>(&moved),
        Err(Error::InvalidInput { field: "seed" })
    ));
    moved.assert_metadata_locked();
}

#[test]
fn concrete_seed_state_stays_stable_and_locked_through_moves_and_wiping() {
    moved_and_wiped(&ml_dsa::Seed::default());
    moved_and_wiped(&ml_kem::kem::Seed::<MlKem512>::default());
    moved_and_wiped(&ml_kem::kem::Seed::<MlKem768>::default());
    moved_and_wiped(&ml_kem::kem::Seed::<MlKem1024>::default());
}

fn invalid_lengths<N: ArraySize>(public: &Array<u8, N>) {
    let width = public.len();
    let fixture = rng::secret(width + 1).unwrap();
    for len in [0, width - 1, width + 1] {
        assert!(matches!(
            parse(&fixture.expose()[..len], width),
            Err(Error::InvalidInput { field: "seed" })
        ));
    }
    assert!(parse(&fixture.expose()[..width], width).is_ok());
    assert!(matches!(
        view::<N>(&fixture),
        Err(Error::InvalidInput { field: "seed" })
    ));
}

#[test]
fn all_concrete_seed_lengths_preserve_strict_input_validation() {
    invalid_lengths(&ml_dsa::Seed::default());
    invalid_lengths(&ml_kem::kem::Seed::<MlKem512>::default());
    invalid_lengths(&ml_kem::kem::Seed::<MlKem768>::default());
    invalid_lengths(&ml_kem::kem::Seed::<MlKem1024>::default());
}

#[cfg(target_os = "linux")]
#[path = "seed_state_denial_tests.rs"]
mod denial;
