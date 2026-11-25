//! DE: Echte Konstruktorfehler nur im begrenzten eigenen Linux-Kindprozess.
//! EN: Actual constructor failures only in a bounded private Linux child.
#![allow(clippy::unwrap_used)]

use super::*;
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn fixed_workspace_denial_is_checked_in_bounded_child() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crypto::hkdf_locked::tests::denial::fixed_workspace_denial_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PQKEEP_FIXED_WORKSPACE_DENIAL_CHILD", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        let timed_out = Instant::now() >= deadline;
        if timed_out {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        assert!(!timed_out, "DE/EN: Kindprozess-Timeout / child timeout");
        std::thread::sleep(Duration::from_millis(10));
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"));
}

#[test]
#[ignore = "DE: Nur isoliert ausführen. EN: Execute only in an isolated child."]
fn fixed_workspace_denial_child() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    assert_eq!(
        std::env::var("PQKEEP_FIXED_WORKSPACE_DENIAL_CHILD").unwrap(),
        "1"
    );
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
    assert!(matches!(LockedHmac::new(), Err(crate::Error::MemoryLock)));
    assert!(matches!(
        derive(&[], &[], &[]),
        Err(crate::Error::MemoryLock)
    ));
    assert!(matches!(
        crate::crypto::locked_hash::LockedHash::<Sha3_256>::new(),
        Err(crate::Error::MemoryLock)
    ));
    assert!(matches!(
        SecretBytes::zeroed(32),
        Err(crate::Error::MemoryLock)
    ));
}
