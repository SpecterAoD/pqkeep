//! DE: Echte Arena-/Kernel-Sperren, Wachstum, Überlappung und Poison-Verweigerung.
//! EN: Actual arena/kernel locks, growth, overlap and refusal after poisoning.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock::{self, lock_range};

#[test]
fn registry_growth_and_poison_run_in_bounded_owned_children() {
    for name in [
        "registry_growth_child",
        "registry_release_error_child",
        "registry_poison_child",
        "guard_transfer_child",
    ] {
        crate::locked_owner_test_support::isolated_test(
            &format!("hardening::lock_registry::tests::{name}"),
            "PQKEEP_REGISTRY_CHILD",
        );
    }
}

#[cfg(target_os = "linux")]
fn kernel_locked_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmLck:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap()
        * 1024
}

fn fixture() -> (Vec<u8>, usize) {
    let page = region::page::size();
    let buffer = vec![0; 360 * page];
    let base = buffer.as_ptr().addr();
    let first = base - base % page + page;
    (buffer, first)
}

fn assert_metadata() {
    #[cfg(windows)]
    let mut query = crate::crypto::secret_state::SecretState::new(
        pqkeep_platform::memory_fixture::MemoryLockQuery::empty(),
    )
    .unwrap();
    let reg = registry();
    let mut observed = |base: usize, len: usize| {
        (base..base + len)
            .step_by(region::page::size())
            .all(|address| {
                #[cfg(target_os = "linux")]
                {
                    crate::locked_owner_test_support::own_mapping_locked(address)
                }
                #[cfg(windows)]
                {
                    query.get_mut().is_locked(address).unwrap()
                }
                #[cfg(not(any(target_os = "linux", windows)))]
                {
                    let _ = address;
                    false
                }
            })
    };
    assert!(reg.control.is_active());
    assert!(observed(
        std::ptr::from_ref(&CONTROL).addr(),
        size_of::<Control>()
    ));
    assert!(reg.storage.visit_storage(&mut observed));
}

#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded owned child only"]
fn registry_growth_child() {
    assert_eq!(std::env::var("PQKEEP_REGISTRY_CHILD").unwrap(), "1");
    #[cfg(target_os = "linux")]
    let before = kernel_locked_bytes();
    assert_eq!(memlock::stats().locked_pages, 0);
    #[cfg(target_os = "linux")]
    assert_eq!(kernel_locked_bytes(), before);
    let (_buffer, first) = fixture();
    let page = region::page::size();
    let left = lock_range(first, 300 * page);
    assert!(left.complete(first, 300 * page));
    let right = lock_range(first + 150 * page, 200 * page);
    assert!(right.complete(first + 150 * page, 200 * page));
    assert_eq!(memlock::stats().locked_pages, 350);
    assert_metadata();
    drop(left);
    assert_eq!(memlock::stats().locked_pages, 200);
    assert!(!memlock::is_locked(first));
    assert!(memlock::is_locked(first + 150 * page));
    let unwind = std::panic::catch_unwind(|| {
        let reused = lock_range(first, 20 * page);
        assert!(reused.complete(first, 20 * page));
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(unwind.is_err());
    assert_eq!(memlock::stats().locked_pages, 200);
    assert_metadata();
    drop(right);
    assert_eq!(memlock::stats().locked_pages, 0);
    assert!(!registry().control.is_active());
    #[cfg(target_os = "linux")]
    assert_eq!(kernel_locked_bytes(), before);
}

#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded owned child only"]
fn registry_poison_child() {
    assert_eq!(std::env::var("PQKEEP_REGISTRY_CHILD").unwrap(), "1");
    #[cfg(target_os = "linux")]
    let before = kernel_locked_bytes();
    let (_buffer, first) = fixture();
    let page = region::page::size();
    let owner = lock_range(first, page);
    assert!(owner.complete(first, page));
    let unwind = std::panic::catch_unwind(|| {
        let _reg = registry();
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(unwind.is_err());
    let refused = lock_range(first + page, page);
    assert!(!refused.complete(first + page, page));
    assert!(memlock::is_locked(first));
    drop(refused);
    drop(owner);
    assert_eq!(memlock::stats().locked_pages, 0);
    assert!(!registry().control.is_active());
    #[cfg(target_os = "linux")]
    assert_eq!(kernel_locked_bytes(), before);
}

fn native_locked(address: usize) -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::locked_owner_test_support::own_mapping_locked(address)
    }
    #[cfg(windows)]
    {
        let mut query = crate::crypto::secret_state::SecretState::new(
            pqkeep_platform::memory_fixture::MemoryLockQuery::empty(),
        )
        .unwrap();
        query.get_mut().is_locked(address).unwrap()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = address;
        false
    }
}

#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded owned child only"]
fn guard_transfer_child() {
    assert_eq!(std::env::var("PQKEEP_REGISTRY_CHILD").unwrap(), "1");
    let (_buffer, first) = fixture();
    let page = region::page::size();
    region::prepare_lock_capacity(4 * ALIGNMENT).unwrap();
    let mut a = LockGuard::empty();
    let mut b = LockGuard::empty();
    a.acquire(std::ptr::without_provenance::<u8>(first), page)
        .unwrap();
    assert!(
        a.acquire(std::ptr::without_provenance::<u8>(first + page), page)
            .is_err()
    );
    assert!(native_locked(first));
    assert!(!native_locked(first + page));
    a.swap(&mut b);
    assert!(!a.is_active() && b.is_active());
    a.release().unwrap();
    assert!(native_locked(first));
    b.release().unwrap();
    assert!(!native_locked(first));
    a.acquire(std::ptr::without_provenance::<u8>(first), page)
        .unwrap();
    b.acquire(std::ptr::without_provenance::<u8>(first + page), page)
        .unwrap();
    a.swap(&mut b);
    a.release().unwrap();
    assert!(native_locked(first) && !native_locked(first + page));
    b.release().unwrap();
    assert!(!native_locked(first));
}

#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded owned child only"]
fn registry_release_error_child() {
    assert_eq!(std::env::var("PQKEEP_REGISTRY_CHILD").unwrap(), "1");
    #[cfg(target_os = "linux")]
    let before = kernel_locked_bytes();
    let (_buffer, first) = fixture();
    let page = region::page::size();
    let keep = lock_range(first, page);
    assert!(keep.complete(first, page));
    #[cfg(windows)]
    let mut query = crate::crypto::secret_state::SecretState::new(
        pqkeep_platform::memory_fixture::MemoryLockQuery::empty(),
    )
    .unwrap();
    let baseline = memlock::stats().locked_pages;
    force_owned_unmap_before_release(page);
    assert_eq!(memlock::stats().locked_pages, baseline);
    assert!(memlock::is_locked(first));
    #[cfg(target_os = "linux")]
    assert!(native_locked(first));
    #[cfg(windows)]
    assert!(query.get_mut().is_locked(first).unwrap());
    let refused = lock_range(first + page, page);
    assert!(!refused.complete(first + page, page));
    drop(refused);
    drop(keep);
    #[cfg(windows)]
    drop(query);
    assert_eq!(memlock::stats().locked_pages, 0);
    assert!(!registry().control.is_active());
    #[cfg(target_os = "linux")]
    assert_eq!(kernel_locked_bytes(), before);
}

// DE: Absichtlich nur die eigene öffentliche Testabbildung vorzeitig freigeben.
// EN: Deliberately release only our own public test mapping before its guard.
fn force_owned_unmap_before_release(page: usize) {
    let mapping = region::alloc(page, region::Protection::READ_WRITE).unwrap();
    let address = mapping.as_ptr::<u8>().addr();
    let owner = lock_range(address, page);
    assert!(owner.complete(address, page));
    let failures = memlock::stats().failed_attempts;
    drop(mapping);
    drop(owner);
    assert!(memlock::stats().failed_attempts > failures);
}
