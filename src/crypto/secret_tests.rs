//! DE: Lebende Byteowner vor Befüllung und nach Bewegungen prüfen.
//! EN: Check live byte owners before filling and after moves.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::Error;
use crate::locked_owner_test_support::locked;

impl SecretBytes {
    pub(crate) fn assert_metadata_locked(&self) {
        locked(self.inner.get());
        for byte in self
            .expose()
            .first()
            .into_iter()
            .chain(self.expose().last())
        {
            locked(byte);
        }
    }
}

#[test]
fn descriptor_is_locked_before_filling_and_stable_through_moves() {
    let mut value = SecretBytes::prepare().unwrap();
    value.assert_metadata_locked();
    let descriptor = std::ptr::from_ref(value.inner.get());
    value.inner.get_mut().initialize_zeroed(32).unwrap();
    value.expose_mut().fill(17);
    let moved = Box::new(value);
    assert!(std::ptr::eq(
        std::ptr::from_ref(moved.inner.get()),
        descriptor
    ));
    assert_eq!(moved.expose(), &[17; 32]);
    moved.assert_metadata_locked();
}

#[test]
fn caller_allocation_is_adopted_without_payload_copy() {
    let mut source = Vec::with_capacity(128);
    source.extend_from_slice(&[17; 32]);
    let pointer = source.as_ptr();
    let value = SecretBytes::new(source).unwrap();
    assert!(std::ptr::eq(value.expose().as_ptr(), pointer));
    assert_eq!(value.expose(), &[17; 32]);
    value.assert_metadata_locked();
}

#[test]
fn empty_and_zeroized_values_keep_valid_locked_descriptors() {
    for mut value in [
        SecretBytes::zeroed(0).unwrap(),
        SecretBytes::from_slice(&[]).unwrap(),
        SecretBytes::new(Vec::new()).unwrap(),
        SecretBytes::from_slice(&[17; 32]).unwrap(),
    ] {
        value.assert_metadata_locked();
        let descriptor = std::ptr::from_ref(value.inner.get());
        value.zeroize();
        assert!(value.is_empty());
        assert_eq!(value.expose_mut(), b"");
        assert!(std::ptr::eq(
            std::ptr::from_ref(value.inner.get()),
            descriptor
        ));
        value.assert_metadata_locked();
    }
}

#[test]
fn allocation_overflow_and_private_growth_are_refused_without_mutation() {
    let mut value = SecretBytes::prepare().unwrap();
    let descriptor = std::ptr::from_ref(value.inner.get());
    assert_eq!(
        value.inner.get_mut().initialize_zeroed(usize::MAX),
        Err(Error::MemoryLock)
    );
    assert!(value.is_empty());
    value.inner.get_mut().initialize_zeroed(4).unwrap();
    value.expose_mut().fill(17);
    let payload = value.expose().as_ptr();
    assert_eq!(
        value.inner.get_mut().initialize_zeroed(8),
        Err(Error::MemoryLock)
    );
    assert_eq!(
        value.inner.get_mut().adopt_locked(vec![23; 8]),
        Err(Error::MemoryLock)
    );
    assert_eq!(value.expose(), &[17; 4]);
    assert!(std::ptr::eq(value.expose().as_ptr(), payload));
    assert!(std::ptr::eq(
        std::ptr::from_ref(value.inner.get()),
        descriptor
    ));
    value.assert_metadata_locked();
}

#[cfg(target_os = "linux")]
#[path = "secret_denial_tests.rs"]
mod denial;
