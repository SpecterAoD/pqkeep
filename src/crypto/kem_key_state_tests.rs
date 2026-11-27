//! DE: Echte KEM-Payloads und Wipe/Unlock/Free-Reihenfolge an lebenden Ownern prüfen.
//! EN: Check actual KEM payloads and wipe/unlock/free order while owners remain live.
#![allow(clippy::unwrap_used, deprecated)]

use super::*;
use crate::crypto::{rng, seed_state};
use crate::hardening::memlock;
use crate::locked_owner_test_support::locked;
use ml_kem::{
    ExpandedKeyEncoding,
    kem::{FromSeed, KeyExport},
};

fn ranges<T: SeedKeyInPlace>(key: &T) -> [(usize, usize); 3] {
    let mut result = [(0, 0); 3];
    let mut count = 0;
    assert!(key.visit_private_storage(|addr, len| {
        result[count] = (addr, len);
        count += 1;
        assert!(memlock::is_locked(addr));
        assert!(memlock::is_locked(addr + len - 1));
        #[cfg(target_os = "linux")]
        {
            assert!(crate::locked_owner_test_support::own_mapping_locked(addr));
            assert!(crate::locked_owner_test_support::own_mapping_locked(
                addr + len - 1
            ));
        }
        true
    }));
    assert_eq!(count, 3);
    result
}

macro_rules! check_variant {
    ($parameter:ty, $private_len:expr) => {{
        let seed = rng::secret(64).unwrap();
        let (_, legacy) = <$parameter>::from_seed(seed_state::view(&seed).unwrap());
        let mut state =
            KeyState::<<$parameter as ml_kem::kem::Kem>::DecapsulationKey>::prepare().unwrap();
        locked(state.get());
        let before = ranges(state.get());
        let mut workspace =
            SecretState::new(ml_kem::KeyGenerationWorkspace::<$parameter>::default()).unwrap();
        locked(workspace.get());
        state
            .key
            .get_mut()
            .initialize_seed_with_workspace(seed_state::view(&seed).unwrap(), workspace.get_mut())
            .unwrap();
        locked(workspace.get());
        let debug_is_redacted = format!("{:?}", workspace.get()) == "KeyGenerationWorkspace { .. }";
        assert!(debug_is_redacted);
        assert!(ranges(state.get()) == before);
        assert!(state.get().encapsulation_key().to_bytes() == legacy.to_bytes());
        let mut exported = state.get().to_bytes();
        assert!(exported.as_slice() == seed.expose());
        exported.zeroize();
        state.key.get_mut().zeroize();
        assert!(ranges(state.get()) == before);
        let cleared = state.get().to_expanded_bytes();
        assert!(cleared[..$private_len].iter().all(|byte| *byte == 0));
        assert!(cleared[cleared.len() - 32..].iter().all(|byte| *byte == 0));
    }};
}

#[test]
fn actual_kem_private_heaps_remain_locked_and_stable_until_explicit_wipe() {
    check_variant!(ml_kem::MlKem512, 768);
    check_variant!(ml_kem::MlKem768, 1152);
    check_variant!(ml_kem::MlKem1024, 1536);
}

#[path = "kem_key_state_order_tests.rs"]
mod order;
