//! DE: Interne Tests des Seitenzählers: zwei Bereiche auf derselben Seite.
//! EN: Internal tests of the page counter: two ranges on the same page.

use super::{is_locked, lock_range};

#[test]
fn shared_page_stays_locked_until_last_release() {
    let buf = [0u8; 64];
    let base = buf.as_ptr().addr();
    let a = lock_range(base, 16);
    let b = lock_range(base + 32, 16);
    if !a.complete(base, 16) {
        // DE: Sperren auf diesem System nicht möglich – nichts zu prüfen.
        // EN: Locking not possible on this system – nothing to check.
        return;
    }
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
    assert_eq!(r.pages.len(), 0);
}

#[test]
fn range_over_page_boundary_locks_both_pages() {
    let size = region::page::size();
    let buf = vec![0u8; size * 3];
    let start = buf.as_ptr().addr();
    let addr = start - start % size + size + size - 8;
    let r = lock_range(addr, 16);
    if r.complete(addr, 16) {
        assert_eq!(r.pages.len(), 2);
        assert!(is_locked(addr) && is_locked(addr + 16));
    }
}
