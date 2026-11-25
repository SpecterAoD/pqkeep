//! DE: Tatsächliche typisierte Descriptoren vor Befüllung und nach Bewegungen.
//! EN: Actual typed descriptors before population and after owner moves.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{Error, locked_owner_test_support::locked};

impl<T: Zeroize> SecretWorkspace<T>
where
    SecretBuffer<T>: ZeroizeOnDrop,
{
    pub(crate) fn assert_metadata_locked(&self) -> usize {
        locked(self.inner.get());
        for item in self
            .expose()
            .first()
            .into_iter()
            .chain(self.expose().last())
        {
            locked(item);
        }
        std::ptr::from_ref(self.inner.get()).addr()
    }
}

fn primitive<T: Zeroize + Default + Copy + PartialEq>(value: T)
where
    SecretBuffer<T>: ZeroizeOnDrop,
{
    let mut workspace = SecretWorkspace::<T>::prepare().unwrap();
    workspace.assert_metadata_locked();
    let descriptor = std::ptr::from_ref(workspace.inner.get());
    workspace.inner.get_mut().initialize_defaults(4).unwrap();
    assert!(workspace.expose().iter().all(|x| *x == T::default()));
    workspace.expose_mut().fill(value);
    let payload = workspace.expose().as_ptr();
    let mut moved = Box::new(workspace);
    assert!(std::ptr::eq(
        std::ptr::from_ref(moved.inner.get()),
        descriptor
    ));
    assert!(std::ptr::eq(moved.expose().as_ptr(), payload));
    assert!(moved.expose().iter().all(|x| *x == value));
    moved.assert_metadata_locked();
    moved.truncate(1);
    assert!(moved.expose() == [value]);
    moved.zeroize();
    assert!(moved.expose().is_empty());
    moved.assert_metadata_locked();
}

#[test]
fn concrete_primitive_descriptors_are_locked_and_stable() {
    primitive('🦀');
    primitive(17usize);
    primitive(true);
    primitive(0xd834u16);
}

#[test]
fn empty_primitive_workspaces_retain_locked_descriptors() {
    SecretWorkspace::<char>::zeroed(0)
        .unwrap()
        .assert_metadata_locked();
    SecretWorkspace::<usize>::zeroed(0)
        .unwrap()
        .assert_metadata_locked();
    SecretWorkspace::<bool>::zeroed(0)
        .unwrap()
        .assert_metadata_locked();
    SecretWorkspace::<u16>::zeroed(0)
        .unwrap()
        .assert_metadata_locked();
}

#[test]
fn caller_transfer_preserves_payload_and_empty_growth_is_bounded() {
    let mut source = Vec::with_capacity(64);
    source.extend(['a', '🦀']);
    let pointer = source.as_ptr();
    let value = SecretWorkspace::new(source).unwrap();
    assert!(std::ptr::eq(value.expose().as_ptr(), pointer));
    assert_eq!(value.expose(), ['a', '🦀']);
    value.assert_metadata_locked();
    let source = Vec::<usize>::with_capacity(4);
    let capacity = source.capacity();
    let mut pending = SecretWorkspace::new(source).unwrap();
    pending.assert_metadata_locked();
    for n in 0..capacity {
        pending.push_preallocated(n).unwrap();
    }
    assert_eq!(pending.push_preallocated(17), Err(Error::MemoryLock));
    assert!(pending.expose().iter().copied().eq(0..capacity));
    pending.assert_metadata_locked();
}

#[test]
fn overflow_and_reinitialization_refuse_mutation() {
    let mut value = SecretWorkspace::<usize>::prepare().unwrap();
    assert_eq!(
        value.inner.get_mut().reserve_empty(usize::MAX),
        Err(Error::MemoryLock)
    );
    assert_eq!(value.expose(), &[] as &[usize]);
    value.inner.get_mut().initialize_defaults(4).unwrap();
    value.expose_mut().fill(17);
    assert_eq!(
        value.inner.get_mut().reserve_empty(8),
        Err(Error::MemoryLock)
    );
    assert_eq!(
        value.inner.get_mut().adopt_locked(vec![23; 8]),
        Err(Error::MemoryLock)
    );
    assert_eq!(value.expose(), &[17; 4]);
    value.assert_metadata_locked();
}

#[cfg(target_os = "linux")]
#[path = "secret_workspace_denial_tests.rs"]
mod denial;
