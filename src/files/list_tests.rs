//! DE: Exakte List-Budgets vor Sammlung/PathSet. EN: Exact budgets before collection/PathSet.

#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn entry_cap_accepts_exactly_then_rejects_without_mutation() {
    let mut pending = Pending::default();
    for _ in 0..MAX_LIST_ENTRIES {
        pending
            .push(&Entry::Dir(ConfidentialText::from_text("d").unwrap()))
            .unwrap();
    }
    assert_eq!(pending.entries.len(), MAX_LIST_ENTRIES);
    let before = pending.path_bytes;
    assert_eq!(
        pending.push(&Entry::Dir(ConfidentialText::from_text("x").unwrap())),
        Err(limit())
    );
    assert_eq!(pending.entries.len(), MAX_LIST_ENTRIES);
    assert_eq!(pending.path_bytes, before);
}

#[test]
fn utf8_byte_budget_accepts_exactly_and_rejects_one_byte_more() {
    let mut pending = Pending {
        path_bytes: MAX_LIST_PATH_BYTES - 2,
        ..Pending::default()
    };
    pending
        .push(&Entry::Dir(ConfidentialText::from_text("ä").unwrap()))
        .unwrap();
    assert_eq!(pending.path_bytes, MAX_LIST_PATH_BYTES);
    assert_eq!(
        pending.push(&Entry::Dir(ConfidentialText::from_text("a").unwrap())),
        Err(limit())
    );
    assert_eq!(pending.entries.len(), 1);
    assert_eq!(pending.path_bytes, MAX_LIST_PATH_BYTES);
}

#[test]
fn overflow_fails_without_collecting_metadata() {
    let mut pending = Pending {
        path_bytes: usize::MAX,
        ..Pending::default()
    };
    assert_eq!(
        pending.push(&Entry::File(
            ConfidentialText::from_text("a").unwrap(),
            u64::MAX
        )),
        Err(limit())
    );
    assert!(pending.entries.is_empty());
    assert_eq!(pending.path_bytes, usize::MAX);
}

/// DE: Typ/Größe und Owner bleiben im vollständig gesperrten festen Bereich.
/// EN: Kind/size and owners stay within the fully locked fixed arena.
#[test]
fn listing_record_arena_is_locked_before_private_collection_and_never_moves() {
    use crate::hardening::memlock;
    let mut pending = Pending::default();
    pending.entries.prepare().unwrap();
    let base = pending.entries.as_ptr().addr();
    let end = base + MAX_LIST_ENTRIES * size_of::<ListEntry>() - 1;
    assert!(memlock::is_locked(base));
    assert!(memlock::is_locked(end));
    for size in [0, 17, u64::MAX] {
        pending
            .push(&Entry::File(
                ConfidentialText::from_text("name").unwrap(),
                size,
            ))
            .unwrap();
        assert_eq!(pending.entries.as_ptr().addr(), base);
        assert!(memlock::is_locked(end));
        assert_eq!(pending.entries.last().unwrap().bytes, Some(size));
    }
    assert_eq!(
        format!("{:?}", pending.entries),
        "ConfidentialEntries([REDACTED])"
    );
}

#[test]
fn listing_entry_zeroize_clears_owned_name_and_scalar_metadata() {
    let mut entry = ListEntry {
        path: ConfidentialText::from_text("name").unwrap(),
        kind: EntryKind::File,
        bytes: Some(u64::MAX),
    };
    entry.zeroize();
    assert_eq!(entry.path.expose().unwrap(), "");
    assert_eq!(entry.bytes, None);
    assert_eq!(entry.kind, EntryKind::Directory);
}
