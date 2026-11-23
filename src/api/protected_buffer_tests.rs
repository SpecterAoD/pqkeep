//! DE: Gesperrte Ziele und lebende Owner beobachten. EN: Observe locked targets and live owners.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::hardening::memlock;

#[test]
fn split_and_cloned_bytes_retain_their_own_live_lock() {
    let mut input = ProtectedBuffer::new(8192).unwrap();
    assert!(memlock::is_locked(input.spare_mut().as_ptr().addr()));
    input.spare_mut()[..4097].fill(0x5a);
    input.commit(4097);
    let piece = input.split(4096).unwrap().freeze();
    let clone = piece.clone();
    drop(piece);
    drop(input);
    assert_eq!(clone.len(), 4096);
    assert!(memlock::is_locked(clone.as_ptr().addr()));
    assert!(clone.iter().all(|b| *b == 0x5a));
}

#[test]
fn growth_locks_destination_before_preserving_private_bytes() {
    let mut input = ProtectedBuffer::new(32).unwrap();
    input.spare_mut()[..32].fill(0x5a);
    input.commit(32);
    input.reserve(4096).unwrap();
    assert!(memlock::is_locked(input.bytes().as_ptr().addr()));
    assert!(input.bytes().iter().all(|b| *b == 0x5a));
    assert!(input.reserve(MAX_CAPACITY).is_err());
    assert_eq!(input.bytes().len(), 32);
    assert!(input.split(33).is_err());
}

#[test]
fn discard_wipes_live_removed_tail_and_siblings_are_protected() {
    let mut input = ProtectedBuffer::new(4096).unwrap();
    input.spare_mut()[..128].fill(0x5a);
    input.commit(128);
    input.discard(127);
    assert_eq!(input.bytes().len(), 1);
    assert!(input.storage.expose()[1..128].iter().all(|b| *b == 0));
    let mut sibling = input.sibling(64).unwrap();
    assert!(memlock::is_locked(sibling.spare_mut().as_ptr().addr()));
    assert!(input.sibling(MAX_CAPACITY + 1).is_err());
}
