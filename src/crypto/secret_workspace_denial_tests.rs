//! DE: Nur eigene kurzlebige Kindprozesse mit reduziertem Memlock-Limit.
//! EN: Only our own short-lived children with a reduced memlock limit.
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

fn child(name: &str) {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--ignored", "--test-threads=1"])
        .env("PQKEEP_TYPED_OWNER_DENIAL_CHILD", "1")
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
fn metadata_denial_is_isolated() {
    child("crypto::secret_workspace::tests::denial::metadata_denial_child");
}

#[test]
fn payload_denial_follows_metadata_preparation() {
    child("crypto::secret_workspace::tests::denial::payload_denial_child");
}

#[test]
#[ignore = "DE: Nur isoliert ausführen. EN: Execute only in an isolated child."]
fn metadata_denial_child() {
    assert_eq!(
        std::env::var("PQKEEP_TYPED_OWNER_DENIAL_CHILD").unwrap(),
        "1"
    );
    deny_further_locks();
    assert!(matches!(
        SecretWorkspace::<argon2::Block>::zeroed(4),
        Err(Error::MemoryLock)
    ));
    assert!(matches!(
        SecretWorkspace::<char>::zeroed(0),
        Err(Error::MemoryLock)
    ));
    assert!(matches!(
        SecretWorkspace::<usize>::with_capacity(32),
        Err(Error::MemoryLock)
    ));
    assert!(matches!(
        SecretWorkspace::new(vec![true; 32]),
        Err(Error::MemoryLock)
    ));
    assert!(matches!(
        SecretWorkspace::new(vec![17u16; 32]),
        Err(Error::MemoryLock)
    ));
}

#[test]
#[ignore = "DE: Nur isoliert ausführen. EN: Execute only in an isolated child."]
fn payload_denial_child() {
    assert_eq!(
        std::env::var("PQKEEP_TYPED_OWNER_DENIAL_CHILD").unwrap(),
        "1"
    );
    let mut allocate = SecretWorkspace::<char>::prepare().unwrap();
    let mut adopt = SecretWorkspace::<usize>::prepare().unwrap();
    let mut blocks = SecretWorkspace::<argon2::Block>::prepare().unwrap();
    let incoming = vec![17usize; 1024 * 1024];
    deny_further_locks();
    assert_eq!(
        blocks.inner.get_mut().initialize_defaults(1024),
        Err(Error::MemoryLock)
    );
    assert!(blocks.expose().is_empty());
    blocks.assert_metadata_locked();
    assert_eq!(
        allocate.inner.get_mut().initialize_defaults(1024 * 1024),
        Err(Error::MemoryLock)
    );
    assert_eq!(
        adopt.inner.get_mut().adopt_locked(incoming),
        Err(Error::MemoryLock)
    );
    assert!(allocate.expose().is_empty() && adopt.expose().is_empty());
    allocate.assert_metadata_locked();
    adopt.assert_metadata_locked();
}
