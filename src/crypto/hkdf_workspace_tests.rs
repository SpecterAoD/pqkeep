//! DE: Tatsächliche HKDF-Descriptoren vor Rekey und nach privaten Owner-Moves.
//! EN: Actual HKDF descriptors before rekey and after private owner moves.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::crypto::rng;

#[test]
fn hmac_nested_descriptors_and_payloads_stay_locked_through_private_moves() {
    for len in [0, 32, 135, 136, 137] {
        let key = rng::secret(len).unwrap();
        let mut mac = LockedHmac::new().unwrap();
        let state = mac.state.assert_metadata_locked();
        let scratch = mac.scratch.assert_metadata_locked();
        let state_payload = mac.state.expose().as_ptr();
        let scratch_payload = mac.scratch.expose().as_ptr();
        mac.rekey(key.expose());
        assert!(mac.scratch.expose()[0].iter().all(|b| *b == 0));
        mac.update(key.expose());
        let mut moved = Box::new(mac);
        assert_eq!(moved.state.assert_metadata_locked(), state);
        assert_eq!(moved.scratch.assert_metadata_locked(), scratch);
        assert!(std::ptr::eq(moved.state.expose().as_ptr(), state_payload));
        assert!(std::ptr::eq(
            moved.scratch.expose().as_ptr(),
            scratch_payload
        ));
        let mut out = SecretBytes::zeroed(32).unwrap();
        moved.finalize_into(output_view::<Sha3_256>(&mut out).unwrap());
        assert!(out.is_locked());
        assert!(moved.scratch.expose()[0].iter().all(|b| *b == 0));
        moved.state.zeroize();
        moved.scratch.zeroize();
        assert!(moved.state.expose().is_empty() && moved.scratch.expose().is_empty());
        assert_eq!(moved.state.assert_metadata_locked(), state);
        assert_eq!(moved.scratch.assert_metadata_locked(), scratch);
    }
}

#[cfg(target_os = "linux")]
#[path = "fixed_workspace_denial_tests.rs"]
mod denial;
