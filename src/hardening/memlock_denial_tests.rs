//! DE: Tatsächliche Linux-Teilsperre nur im eigenen kurzlebigen Kindprozess.
//! EN: Actual Linux partial lock only in our own short-lived child process.
#![allow(clippy::unwrap_used)]

use super::{is_locked, lock_range, registry};

#[test]
fn partial_os_denial_is_cleaned_up_in_isolated_child() {
    use rustix::process::{Resource, getrlimit};
    let before = getrlimit(Resource::Memlock);
    crate::locked_owner_test_support::isolated_test(
        "hardening::memlock::denial_tests::partial_os_denial_child",
        "PQKEEP_LOCK_RANGE_DENIAL_CHILD",
    );
    assert_eq!(getrlimit(Resource::Memlock), before);
}

#[test]
#[ignore = "DE: Nur isoliert ausführen. EN: Execute only in an isolated child."]
fn partial_os_denial_child() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    assert_eq!(
        std::env::var("PQKEEP_LOCK_RANGE_DENIAL_CHILD").unwrap(),
        "1"
    );
    assert!(registry().is_empty());
    let size = region::page::size();
    let buffer = vec![0u8; 4 * size];
    let base = buffer.as_ptr().addr();
    let first = base - base % size + size;
    let baseline = kernel_locked_bytes();
    let warm = lock_range(first, size);
    assert!(warm.complete(first, size));
    let warm_bytes = kernel_locked_bytes();
    let budget = warm_bytes
        .checked_add(u64::try_from(size).unwrap())
        .unwrap();
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(budget),
            maximum: Some(budget),
        },
    )
    .unwrap();
    assert_eq!(
        rustix::process::getrlimit(Resource::Memlock).current,
        Some(budget)
    );
    let target = first + size;
    let range = lock_range(target, 2 * size);
    assert!(!range.complete(target, 2 * size));
    assert!(PartialEq::eq(&range.pages, &(target..target + size)));
    assert!(is_locked(target) && !is_locked(target + size));
    drop(range);
    assert!(!is_locked(target));
    assert!(is_locked(first));
    assert_eq!(kernel_locked_bytes(), warm_bytes);
    drop(warm);
    assert_eq!(kernel_locked_bytes(), baseline);
    assert!(registry().is_empty());
}

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
