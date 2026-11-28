//! DE: Echte Quelldatensätze, stabile Sperren und fallible Präfixübernahme.
//! EN: Actual source records, stable locks and fallible prefix adoption.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::crypto::SecretBytes;
use std::io::Read;

fn locked<T: ?Sized>(value: &T) {
    crate::locked_owner_test_support::locked(value);
    #[cfg(windows)]
    if size_of_val(value) > 0 {
        let mut query =
            SecretState::new(pqkeep_platform::memory_fixture::MemoryLockQuery::empty()).unwrap();
        let address = std::ptr::from_ref(value).addr();
        assert!(query.get_mut().is_locked(address).unwrap());
        assert!(
            query
                .get_mut()
                .is_locked(address + size_of_val(value) - 1)
                .unwrap()
        );
    }
}

fn owners(entries: &SourceEntries) {
    let state = entries.0.get();
    locked(state);
    locked(state.records.expose());
    locked(state.order.expose());
    for entry in &state.records.expose()[..state.used] {
        locked(entry);
        locked(entry.rel.as_ref().unwrap().bytes());
        if let Some(path) = &entry.abs {
            locked(path.encoded().unwrap());
        }
    }
}

#[test]
fn actual_collected_source_records_stay_locked_through_moves_and_sorting() {
    let root = tempfile::tempdir().unwrap();
    for name in ["z.txt", "ä.txt", "a.txt"] {
        std::fs::write(root.path().join(name), b"public source fixture").unwrap();
    }
    let (entries, skipped) = super::super::walk::collect_dir(root.path()).unwrap();
    let no_skipped_entries = skipped.is_empty();
    assert!(no_skipped_entries);
    assert_eq!(entries.len(), 3);
    owners(&entries);
    for (entry, expected) in entries.try_iter().unwrap().zip(["a.txt", "z.txt", "ä.txt"]) {
        let entry = entry.unwrap();
        let equal = entry.path().unwrap() == expected;
        assert!(equal);
        assert!(!entry.is_directory());
        assert_eq!(entry.size(), b"public source fixture".len() as u64);
        let mut contents = SecretBytes::zeroed(usize::try_from(entry.size()).unwrap()).unwrap();
        entry
            .open()
            .unwrap()
            .read_exact(contents.expose_mut())
            .unwrap();
        let equal = contents.expose() == b"public source fixture";
        assert!(equal);
    }
}

#[test]
fn prelocked_empty_record_and_prefixed_records_preserve_original_on_validation_error() {
    let empty = SourceEntries::prepare().unwrap();
    owners(&empty);
    let mut entry = SourceEntries::prepare().unwrap();
    entry
        .push("child.txt", Path::new("public fixture"), false, 9)
        .unwrap();
    entry.prepend_all("root").unwrap();
    let equal = entry.get(0).unwrap().path().unwrap() == "root/child.txt";
    assert!(equal);
    owners(&entry);
    assert!(entry.prepend_all("../invalid").is_err());
    let unchanged = entry.get(0).unwrap().path().unwrap() == "root/child.txt";
    assert!(unchanged);
    assert_eq!(entry.get(0).unwrap().size(), 9);
}

#[cfg(target_os = "linux")]
fn kernel_locked_bytes() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmLck:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse::<usize>()
        .unwrap()
        .checked_mul(1024)
        .unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn real_source_record_denial_and_unwind_run_in_owned_child() {
    use rustix::process::{Resource, getrlimit};
    let before = getrlimit(Resource::Memlock);
    crate::locked_owner_test_support::isolated_test(
        "files::source_entries::tests::source_record_denial_child",
        "PQKEEP_SOURCE_RECORD_CHILD",
    );
    crate::locked_owner_test_support::isolated_test(
        "files::source_entries::tests::partial_growth_denial_child",
        "PQKEEP_SOURCE_RECORD_CHILD",
    );
    assert_eq!(getrlimit(Resource::Memlock), before);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded owned child only"]
fn source_record_denial_child() {
    use crate::hardening::memlock;
    use rustix::process::{Resource, getrlimit, setrlimit};
    assert_eq!(std::env::var("PQKEEP_SOURCE_RECORD_CHILD").unwrap(), "1");
    let baseline = memlock::stats().locked_pages;
    let unwind = std::panic::catch_unwind(|| {
        let mut entry = SourceEntries::prepare().unwrap();
        entry
            .push("public.txt", Path::new("public fixture"), false, 9)
            .unwrap();
        owners(&entry);
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(unwind.is_err());
    assert_eq!(memlock::stats().locked_pages, baseline);
    let mut entry = SourceEntries::prepare().unwrap();
    for index in 0..128 {
        entry
            .push(
                &format!("entry-{index:03}"),
                Path::new("public fixture"),
                false,
                9,
            )
            .unwrap();
    }
    let prefix = "x".repeat(2 * region::page::size());
    let baseline = memlock::stats().locked_pages;
    let mut limit = getrlimit(Resource::Memlock);
    limit.current = Some(0);
    setrlimit(Resource::Memlock, limit).unwrap();
    assert_eq!(getrlimit(Resource::Memlock).current, Some(0));
    assert!(matches!(
        entry.push("new", Path::new("fixture"), false, 1),
        Err(Error::MemoryLock)
    ));
    assert_eq!(entry.len(), 128);
    assert!(matches!(entry.prepend_all(&prefix), Err(Error::MemoryLock)));
    assert_eq!(memlock::stats().locked_pages, baseline);
    let unchanged = entry.get(0).unwrap().path().unwrap() == "entry-000";
    assert!(unchanged);
    assert_eq!(entry.get(0).unwrap().size(), 9);
}

#[test]
fn protected_index_sort_preserves_fields_across_growth_boundaries() {
    for length in [0, 1, 2, 3, 16, 17, 31, 32, 65] {
        let mut entries = SourceEntries::prepare().unwrap();
        for index in (0..length).rev() {
            entries
                .push(
                    &format!("entry-{index:03}"),
                    Path::new("public fixture"),
                    index % 2 == 0,
                    u64::try_from(index).unwrap(),
                )
                .unwrap();
        }
        entries.sort().unwrap();
        owners(&entries);
        for (entry, index) in entries.try_iter().unwrap().zip(0..length) {
            let entry = entry.unwrap();
            let equal = entry.path().unwrap() == format!("entry-{index:03}");
            assert!(equal);
            assert_eq!(entry.size(), u64::try_from(index).unwrap());
            assert_eq!(entry.is_directory(), index % 2 == 0);
        }
    }
}

#[test]
fn iterator_source_and_cursor_remain_protected_while_advancing() {
    let mut entries = SourceEntries::prepare().unwrap();
    entries
        .push("a", Path::new("public fixture"), false, 1)
        .unwrap();
    entries
        .push("b", Path::new("public fixture"), true, 0)
        .unwrap();
    let mut iterator = entries.try_iter().unwrap();
    locked(iterator.0.get());
    let equal = iterator.next().unwrap().unwrap().path().unwrap() == "a";
    assert!(equal);
    locked(iterator.0.get());
    let equal = iterator.next().unwrap().unwrap().path().unwrap() == "b";
    assert!(equal);
    locked(iterator.0.get());
    assert!(iterator.next().is_none());
}

#[test]
fn equal_path_order_matches_the_previous_stable_reference_sort() {
    let mut entries = SourceEntries::prepare().unwrap();
    let mut reference = Vec::new();
    for index in (0..65u64).rev() {
        let path = format!("public-{}", index % 5);
        entries
            .push(&path, Path::new("public fixture"), false, index)
            .unwrap();
        reference.push((path, index));
    }
    reference.sort_by(|a, b| a.0.cmp(&b.0));
    entries.sort().unwrap();
    for (entry, (path, size)) in entries.try_iter().unwrap().zip(reference) {
        let entry = entry.unwrap();
        let equal = entry.path().unwrap() == path;
        assert!(equal);
        assert_eq!(entry.size(), size);
    }
}

#[test]
fn partial_native_path_failure_cleans_slot_and_preserves_previous_entries() {
    let mut entries = SourceEntries::prepare().unwrap();
    entries
        .push("old", Path::new("public fixture"), false, 9)
        .unwrap();
    assert!(matches!(
        entries.push("new", Path::new("public\0fixture"), true, 0),
        Err(Error::InvalidInput { field: "path" })
    ));
    assert_eq!(entries.len(), 1);
    assert!(entries.0.get().records.expose()[1].rel.is_none());
    assert!(entries.0.get().records.expose()[1].abs.is_none());
    let unchanged = entries.get(0).unwrap().path().unwrap() == "old";
    assert!(unchanged);
    entries
        .push("new", Path::new("public fixture"), true, 0)
        .unwrap();
    assert_eq!(entries.len(), 2);
    owners(&entries);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded owned child only"]
fn partial_growth_denial_child() {
    use crate::hardening::memlock;
    use rustix::process::{Resource, getrlimit, setrlimit};
    assert_eq!(std::env::var("PQKEEP_SOURCE_RECORD_CHILD").unwrap(), "1");
    let baseline = memlock::stats().locked_pages;
    let kernel_baseline = kernel_locked_bytes();
    let mut entries = SourceEntries::prepare().unwrap();
    let page = region::page::size();
    let source = "x".repeat(2 * page);
    for index in 0..16 {
        entries
            .push(&format!("entry-{index:02}"), Path::new(&source), false, 9)
            .unwrap();
    }
    let budget = kernel_locked_bytes().checked_add(12 * page).unwrap();
    let mut limit = getrlimit(Resource::Memlock);
    let budget = u64::try_from(budget).unwrap();
    assert!(limit.current.is_none_or(|original| budget < original));
    limit.current = Some(budget);
    setrlimit(Resource::Memlock, limit).unwrap();
    assert_eq!(getrlimit(Resource::Memlock).current, Some(budget));
    let before = memlock::stats().locked_pages;
    assert!(matches!(
        entries.push("new", Path::new(&source), false, 1),
        Err(Error::MemoryLock)
    ));
    assert!(entries.0.get().scan > 0 && entries.0.get().scan < entries.len());
    assert_eq!(entries.len(), 16);
    assert_eq!(memlock::stats().locked_pages, before);
    owners(&entries);
    let unchanged = entries.get(0).unwrap().path().unwrap() == "entry-00";
    assert!(unchanged);
    drop(entries);
    assert_eq!(memlock::stats().locked_pages, baseline);
    assert_eq!(kernel_locked_bytes(), kernel_baseline);
}
