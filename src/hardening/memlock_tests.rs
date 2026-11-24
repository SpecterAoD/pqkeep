//! DE: Interne Tests des Seitenzählers: zwei Bereiche auf derselben Seite.
//! EN: Internal tests of the page counter: two ranges on the same page.

#![allow(clippy::unwrap_used)]

use super::{is_locked, lock_capacity, lock_range, page_span, registry};

#[test]
fn shared_page_stays_locked_until_last_release() {
    let buf = vec![0u8; 4 * region::page::size()];
    let base = interior_page(&buf);
    let a = lock_range(base, 16);
    let b = lock_range(base + 32, 16);
    assert!(a.complete(base, 16) && b.complete(base + 32, 16));
    assert!(is_locked(base));
    drop(a);
    assert!(
        is_locked(base + 32),
        "Seite muss gesperrt bleiben / page must stay locked"
    );
    drop(b);
    assert!(!is_locked(base));
}

#[test]
fn empty_range_locks_nothing() {
    let r = lock_range(0x1000, 0);
    assert!(r.pages.is_empty() && r.complete(usize::MAX, 0));
}

#[test]
fn range_over_page_boundary_locks_both_pages() {
    let size = region::page::size();
    let buf = vec![0u8; size * 3];
    let start = buf.as_ptr().addr();
    let addr = start - start % size + size + size - 8;
    let r = lock_range(addr, 16);
    assert!(r.complete(addr, 16));
    assert_eq!(r.pages.len(), 2 * size);
    assert!(is_locked(addr) && is_locked(addr + 15));
}

#[test]
fn span_rounding_checks_empty_edges_and_overflows() {
    let size = region::page::size();
    assert!(page_span(usize::MAX, 0).eq(&Some(0..0)));
    assert!(page_span(size + 1, size).eq(&Some(size..3 * size)));
    assert!(page_span(size, size).eq(&Some(size..2 * size)));
    assert!(page_span(2 * size - 1, 1).eq(&Some(size..2 * size)));
    assert!(page_span(2 * size - 1, 2).eq(&Some(size..3 * size)));
    assert!(page_span(usize::MAX, 1).is_none());
    assert!(page_span(usize::MAX - 1, 1).is_none());
    assert!(page_span(size, usize::MAX).is_none());
}

#[test]
fn invalid_spans_cannot_report_success_or_acquire_pages() {
    let locked = lock_range(usize::MAX, 1);
    assert!(locked.pages.is_empty());
    assert!(!locked.complete(usize::MAX, 1));
    assert!(!locked.complete(1, usize::MAX));
}

#[test]
fn capacity_uses_full_pages_and_refuses_arithmetic_overflow() {
    let size = region::page::size();
    let span = page_span(size + 1, size).unwrap();
    assert_eq!(lock_capacity(0, &span), Some(2 * size));
    assert_eq!(lock_capacity(3, &span), Some(5 * size));
    assert!(lock_capacity(usize::MAX, &span).is_none());
    assert!(lock_capacity(1, &(0..usize::MAX)).is_none());
}

fn interior_page(buffer: &[u8]) -> usize {
    let size = region::page::size();
    let start = buffer.as_ptr().addr();
    start - start % size + size
}

#[test]
fn completion_requires_the_same_pages_and_release_wipes_live_record() {
    let size = region::page::size();
    let buffer = vec![0u8; 4 * size];
    let first = interior_page(&buffer);
    let mut locked = lock_range(first + 1, size - 1);
    assert!(locked.complete(first, size));
    assert!(!locked.complete(first + size, size));
    assert!(!locked.complete(first, size + 1));
    assert_eq!(size_of_val(&locked), 2 * size_of::<usize>());
    locked.release();
    assert_eq!(locked.pages.start, 0);
    assert_eq!(locked.pages.end, 0);
    assert!(!is_locked(first));
    // DE: Drop nach expliziter Freigabe bleibt leer. EN: Drop after release remains empty.
    drop(locked);
}

#[test]
fn saturated_reference_stops_at_prefix_without_losing_existing_owner() {
    let size = region::page::size();
    let buffer = vec![0u8; 4 * size];
    let first = interior_page(&buffer);
    let second = first + size;
    let existing = lock_range(second, size);
    assert!(existing.complete(second, size));
    registry().get_mut(&second).unwrap().0 = usize::MAX;
    let prefix = lock_range(first, 2 * size);
    let reference_preserved = {
        let mut reg = registry();
        let preserved = reg.get(&second).unwrap().0 == usize::MAX;
        reg.get_mut(&second).unwrap().0 = 1;
        preserved
    };
    assert!(reference_preserved);
    assert!(!prefix.complete(first, 2 * size));
    assert!(PartialEq::eq(&prefix.pages, &(first..second)));
    drop(prefix);
    assert!(!is_locked(first) && is_locked(second));
    drop(existing);
    assert!(!is_locked(second));
}

#[test]
fn overlapping_owners_release_only_their_pages() {
    let size = region::page::size();
    let buffer = vec![0u8; 5 * size];
    let first = interior_page(&buffer);
    let a = lock_range(first, 2 * size);
    let b = lock_range(first + size, 2 * size);
    assert!(a.complete(first, 2 * size) && b.complete(first + size, 2 * size));
    drop(a);
    assert!(!is_locked(first));
    assert!(is_locked(first + size) && is_locked(first + 2 * size));
    drop(b);
    assert!(!is_locked(first + size) && !is_locked(first + 2 * size));
}

#[test]
fn concurrent_shared_owner_keeps_page_locked() {
    use std::{sync::mpsc, time::Duration};
    let size = region::page::size();
    let buffer = vec![0u8; 4 * size];
    let first = interior_page(&buffer);
    let original = lock_range(first, size);
    assert!(original.complete(first, size));
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let second = lock_range(first, size);
        assert!(second.complete(first, size));
        ready_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(30)).unwrap();
        assert!(is_locked(first));
    });
    ready_rx.recv_timeout(Duration::from_secs(30)).unwrap();
    drop(original);
    assert!(is_locked(first));
    release_tx.send(()).unwrap();
    worker.join().unwrap();
    assert!(!is_locked(first));
}

#[test]
fn unwinding_releases_the_successful_range() {
    let size = region::page::size();
    let buffer = vec![0u8; 4 * size];
    let first = interior_page(&buffer);
    let result = std::panic::catch_unwind(|| {
        let locked = lock_range(first, size);
        assert!(locked.complete(first, size));
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(result.is_err());
    assert!(!is_locked(first));
}
