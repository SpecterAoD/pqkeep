//! DE: Sperrverweigerung ausschließlich in eigenen kurzlebigen Testkindern.
//! EN: Lock denial only in our own short-lived test children.
#![allow(clippy::unwrap_used)]

use super::*;

fn deny_further_locks() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
}

fn run_child(name: &str) {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--ignored", "--test-threads=1"])
        .env("PQKEEP_BYTE_OWNER_DENIAL_CHILD", "1")
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
fn metadata_denial_is_checked_in_an_isolated_process() {
    run_child("crypto::secret::tests::denial::metadata_denial_child");
}

#[test]
fn payload_denial_is_checked_after_metadata_preparation() {
    run_child("crypto::secret::tests::denial::payload_denial_child");
}

#[test]
#[ignore = "DE: Nur isoliert ausführen. EN: Execute only in an isolated child."]
fn metadata_denial_child() {
    assert_eq!(
        std::env::var("PQKEEP_BYTE_OWNER_DENIAL_CHILD").unwrap(),
        "1"
    );
    deny_further_locks();
    assert!(matches!(SecretBytes::zeroed(0), Err(Error::MemoryLock)));
    assert!(matches!(
        SecretBytes::from_slice(&[17]),
        Err(Error::MemoryLock)
    ));
    assert!(matches!(
        SecretBytes::new(vec![17; 32]),
        Err(Error::MemoryLock)
    ));
}

#[test]
#[ignore = "DE: Nur isoliert ausführen. EN: Execute only in an isolated child."]
fn payload_denial_child() {
    assert_eq!(
        std::env::var("PQKEEP_BYTE_OWNER_DENIAL_CHILD").unwrap(),
        "1"
    );
    let mut allocate = SecretBytes::prepare().unwrap();
    let mut adopt = SecretBytes::prepare().unwrap();
    let incoming = vec![17; 1024 * 1024];
    let first = std::ptr::from_ref(allocate.inner.get());
    let second = std::ptr::from_ref(adopt.inner.get());
    deny_further_locks();
    assert_eq!(
        allocate.inner.get_mut().initialize_zeroed(1024 * 1024),
        Err(Error::MemoryLock)
    );
    assert_eq!(
        adopt.inner.get_mut().adopt_locked(incoming),
        Err(Error::MemoryLock)
    );
    assert!(allocate.is_empty() && adopt.is_empty());
    assert!(std::ptr::eq(
        std::ptr::from_ref(allocate.inner.get()),
        first
    ));
    assert!(std::ptr::eq(std::ptr::from_ref(adopt.inner.get()), second));
    allocate.assert_metadata_locked();
    adopt.assert_metadata_locked();
}
