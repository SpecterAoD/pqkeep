//! DE: Sperrverweigerung vor Provideraufruf im begrenzten eigenen Kindprozess.
//! EN: Lock denial before provider entry in our own bounded child process.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;

#[test]
fn encapsulation_lock_denial_precedes_private_entry_in_bounded_child() {
    use std::time::{Duration, Instant};
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crypto::kem::encapsulation::tests::denial::encapsulation_denial_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PQKEEP_KEM_ENCAP_DENIAL", "1")
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
#[ignore = "DE: Nur durch den begrenzten Elternprozess. EN: Only through the bounded parent."]
fn encapsulation_denial_child() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    assert_eq!(std::env::var("PQKEEP_KEM_ENCAP_DENIAL").unwrap(), "1");
    assert_eq!(memlock::stats().locked_pages, 0);
    let before = memlock::stats().failed_attempts;
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
    let visited = std::cell::Cell::new(false);
    let result = run(|_, _, _| {
        visited.set(true);
        Vec::new()
    });
    assert!(matches!(result, Err(Error::MemoryLock)));
    assert!(!visited.get());
    assert_eq!(memlock::stats().locked_pages, 0);
    assert!(memlock::stats().failed_attempts > before);
}
