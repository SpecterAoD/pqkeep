//! DE: Geteilter gesperrter Slot, einmalige Entnahme und Ersetzung.
//! EN: Shared locked slot, one-time take and replacement.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::files::locked_owner_tests::locked;

#[test]
fn shared_slot_stays_locked_before_and_after_identity_population() {
    let result = HiddenResult::new().unwrap();
    let other = result.clone();
    let address = std::ptr::from_ref(result.0.get());
    locked(result.0.get());
    assert!(result.take().is_none());
    result.store(SignedBy::from_public_key(b"public first identity").unwrap());
    locked(other.0.get());
    assert!(std::ptr::eq(std::ptr::from_ref(other.0.get()), address));
    other.store(SignedBy::from_public_key(b"public replacement identity").unwrap());
    drop(result);
    let signed = other.take().unwrap();
    assert_eq!(
        signed,
        SignedBy::from_public_key(b"public replacement identity").unwrap()
    );
    assert!(other.take().is_none());
    locked(other.0.get());
}
