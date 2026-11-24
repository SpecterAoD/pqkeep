//! DE: Tatsächliche Linux-Teilsperre nur im eigenen kurzlebigen Kindprozess.
//! EN: Actual Linux partial lock only in our own short-lived child process.
#![allow(clippy::unwrap_used)]

use super::{is_locked, lock_range, registry};

#[test]
fn partial_os_denial_is_cleaned_up_in_isolated_child() {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "hardening::memlock::denial_tests::partial_os_denial_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PQKEEP_LOCK_RANGE_DENIAL_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
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
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(u64::try_from(size).unwrap()),
            maximum: Some(u64::try_from(size).unwrap()),
        },
    )
    .unwrap();
    let range = lock_range(first, 2 * size);
    assert!(!range.complete(first, 2 * size));
    assert!(PartialEq::eq(&range.pages, &(first..first + size)));
    assert!(is_locked(first) && !is_locked(first + size));
    drop(range);
    assert!(!is_locked(first));
    assert!(registry().is_empty());
}
