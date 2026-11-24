//! DE: Direkte gesperrte Slots und Fehlertransaktionen.
//! EN: Direct locked slots and failure transactions.
#![allow(clippy::unwrap_used)]

use super::*;
#[cfg(target_os = "linux")]
use crate::crypto::SecretBytes;

#[test]
fn prepared_arena_descriptor_is_locked_before_population_and_after_moves() {
    let mut entries = ConfidentialEntries::default();
    entries.prepare().unwrap();
    entries.0.as_ref().unwrap().assert_metadata_locked();
    assert!(entries.is_empty());
    let pointer = entries.as_ptr();
    let mut moved = Box::new(entries);
    moved
        .push(&Entry::fixture(ConfidentialText::from_text("name").unwrap(), Some(17)).unwrap())
        .unwrap();
    assert!(std::ptr::eq(moved.as_ptr(), pointer));
    moved.0.as_ref().unwrap().assert_metadata_locked();
    assert_eq!(moved[0].path.expose().unwrap(), "name");
    assert_eq!(moved[0].bytes, Some(17));
}

#[test]
fn caller_listing_transfer_keeps_payload_and_guards_descriptor() {
    let source = vec![ListEntry {
        path: ConfidentialText::from_text("name").unwrap(),
        kind: EntryKind::File,
        bytes: Some(17),
    }];
    let pointer = source.as_ptr();
    let entries = ConfidentialEntries::try_from(source).unwrap();
    assert!(std::ptr::eq(entries.as_ptr(), pointer));
    entries.0.as_ref().unwrap().assert_metadata_locked();
    assert_eq!(entries[0].bytes, Some(17));
    entries[0].path.assert_owner_locked();
}

#[test]
fn unprepared_arena_refuses_collection_without_mutation() {
    let mut entries = ConfidentialEntries::default();
    let entry = Entry::fixture(ConfidentialText::from_text("name").unwrap(), Some(17)).unwrap();
    assert_eq!(entries.push(&entry), Err(Error::MemoryLock));
    assert!(entries.is_empty());
}

#[test]
fn full_arena_refuses_growth_and_preserves_existing_records() {
    let mut arena = Vec::new();
    arena.try_reserve_exact(1).unwrap();
    let capacity = arena.capacity();
    let mut entries = ConfidentialEntries(Some(SecretWorkspace::new(arena).unwrap()));
    entries.0.as_ref().unwrap().assert_metadata_locked();
    let entry = Entry::fixture(
        ConfidentialText::from_text("Ä/name").unwrap(),
        Some(u64::MAX),
    )
    .unwrap();
    for _ in 0..capacity {
        entries.push(&entry).unwrap();
    }
    let pointer = entries.as_ptr();
    assert_eq!(entries.push(&entry), Err(Error::MemoryLock));
    assert_eq!(entries.len(), capacity);
    assert!(std::ptr::eq(entries.as_ptr(), pointer));
    entries.0.as_ref().unwrap().assert_metadata_locked();
    for record in &entries {
        record.path.assert_owner_locked();
        assert_eq!(record.path.expose().unwrap(), "Ä/name");
        assert_eq!(record.bytes, Some(u64::MAX));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn denied_locks_preserve_existing_slots_in_an_isolated_process() {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "files::confidential_entries::tests::lock_denial_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PQKEEP_METADATA_OWNER_DENIAL_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "DE: Nur isoliert ausführen. EN: Execute only in an isolated child."]
fn lock_denial_child() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    assert_eq!(
        std::env::var("PQKEEP_METADATA_OWNER_DENIAL_CHILD").unwrap(),
        "1"
    );
    let mut entries = ConfidentialEntries::default();
    entries.prepare().unwrap();
    let original = Entry::fixture(ConfidentialText::from_text("kept").unwrap(), Some(17)).unwrap();
    entries.push(&original).unwrap();
    let large = SecretBytes::zeroed(1024 * 1024).unwrap();
    let source = Entry::fixture(
        ConfidentialText::from_locked(large).unwrap(),
        Some(u64::MAX),
    )
    .unwrap();
    let pointer = entries.as_ptr();
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
    assert_eq!(entries.push(&source), Err(Error::MemoryLock));
    assert_eq!(entries.len(), 1);
    assert!(std::ptr::eq(entries.as_ptr(), pointer));
    entries.0.as_ref().unwrap().assert_metadata_locked();
    assert_eq!(entries[0].path.expose().unwrap(), "kept");
    assert_eq!(entries[0].bytes, Some(17));
    entries[0].path.assert_owner_locked();
}
