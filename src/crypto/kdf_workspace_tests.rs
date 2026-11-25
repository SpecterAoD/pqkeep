//! DE: Konkrete Argon2-Owner vor privatem Schreiben und nach Bewegungen prüfen.
//! EN: Check concrete Argon2 owners before private writes and after moves.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;
use argon2::Block;

#[test]
fn argon_block_descriptor_and_payload_stay_locked_through_moves() {
    assert_eq!(size_of::<Block>(), 1024);
    assert_eq!(align_of::<Block>(), 64);
    let mut blocks = SecretWorkspace::<Block>::prepare().unwrap();
    blocks.assert_metadata_locked();
    let descriptor = std::ptr::from_ref(blocks.inner.get());
    blocks.inner.get_mut().initialize_defaults(9).unwrap();
    blocks.assert_metadata_locked();
    assert!(
        blocks
            .expose()
            .iter()
            .all(|b| b.as_ref().iter().all(|x| *x == 0))
    );
    let payload = blocks.expose().as_ptr();
    assert_eq!(payload.addr() % align_of::<Block>(), 0);
    for block in blocks.expose_mut() {
        block.as_mut().fill(17);
    }
    let mut moved = Box::new(blocks);
    assert!(std::ptr::eq(
        std::ptr::from_ref(moved.inner.get()),
        descriptor
    ));
    assert!(std::ptr::eq(moved.expose().as_ptr(), payload));
    moved.assert_metadata_locked();
    assert!(
        moved
            .expose()
            .iter()
            .all(|b| b.as_ref().iter().all(|x| *x == 17))
    );
    // DE: Nur lebende Blockwerte prüfen; nach Freigabe keinen Speicher lesen.
    // EN: Inspect only live Block values; never read storage after release.
    moved.expose_mut().iter_mut().for_each(Zeroize::zeroize);
    assert!(
        moved
            .expose()
            .iter()
            .all(|b| b.as_ref().iter().all(|x| *x == 0))
    );
    moved.zeroize();
    assert!(moved.expose().is_empty());
    assert!(std::ptr::eq(moved.expose().as_ptr(), payload));
    assert!(memlock::is_locked(payload.addr()));
    moved.assert_metadata_locked();
}

#[test]
fn argon_empty_and_overflow_workspaces_preserve_locked_metadata() {
    let mut blocks = SecretWorkspace::<Block>::zeroed(0).unwrap();
    blocks.assert_metadata_locked();
    assert!(blocks.expose().is_empty());
    assert_eq!(
        blocks.inner.get_mut().initialize_defaults(usize::MAX),
        Err(Error::MemoryLock)
    );
    assert!(blocks.expose().is_empty());
    blocks.assert_metadata_locked();
}
