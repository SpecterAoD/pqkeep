//! DE: Tatsächliche öffentliche KEM-APIs verweigern fehlende Sperren ohne Fallback.
//! EN: Actual public KEM APIs refuse unavailable locks without fallback.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;

#[test]
fn public_kem_operations_deny_unavailable_locks_in_bounded_child() {
    use std::time::{Duration, Instant};
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crypto::kem::operation_workspace_tests::denial::operation_denial_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PQKEEP_KEM_OPERATION_DENIAL", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            assert!(
                String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout)
                    .contains("1 passed")
            );
            break;
        }
        let timed_out = Instant::now() >= deadline;
        if timed_out {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        assert!(!timed_out);
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "DE: Nur im begrenzten eigenen Kindprozess. EN: Bounded own child process only."]
fn operation_denial_child() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    assert_eq!(std::env::var("PQKEEP_KEM_OPERATION_DENIAL").unwrap(), "1");
    let mut cases = Vec::new();
    for algorithm in [
        KemAlgorithm::MlKem512,
        KemAlgorithm::MlKem768,
        KemAlgorithm::MlKem1024,
    ] {
        let key = generate(algorithm).unwrap();
        let ciphertext = encapsulate(algorithm, &key.public_key).unwrap().ciphertext;
        cases.push((algorithm, key, ciphertext));
    }
    let before = memlock::stats();
    // DE: Ausschließlich diesen Testprozess beschränken, vorhandene Sperren bleiben aktiv.
    // EN: Restrict only this test process; existing locks remain active.
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
    for (algorithm, key, ciphertext) in cases {
        let baseline = memlock::stats().locked_pages;
        assert!(matches!(
            encapsulate(algorithm, &key.public_key),
            Err(Error::MemoryLock)
        ));
        assert!(matches!(
            decapsulate(algorithm, key.seed().expose(), &ciphertext),
            Err(Error::MemoryLock)
        ));
        assert_eq!(memlock::stats().locked_pages, baseline);
    }
    assert!(memlock::stats().failed_attempts > before.failed_attempts);
}
