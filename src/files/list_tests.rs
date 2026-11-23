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
    assert_eq!(pending.entries, []);
    assert_eq!(pending.path_bytes, usize::MAX);
}
