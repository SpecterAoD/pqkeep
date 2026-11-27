//! DE: Tatsächliche öffentliche DSA-APIs verweigern fehlende Sperren ohne Fallback.
//! EN: Actual public DSA APIs refuse unavailable locks without fallback.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;

#[test]
fn public_dsa_operations_deny_unavailable_locks_in_bounded_child() {
    use std::time::{Duration, Instant};
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crypto::dsa::key_state::tests::denial::operation_denial_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PQKEEP_DSA_OPERATION_DENIAL", "1")
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
    assert_eq!(std::env::var("PQKEEP_DSA_OPERATION_DENIAL").unwrap(), "1");
    let cases = prepare_cases();
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
    let mut public_cases = Vec::new();
    for (algorithm, key, signature) in cases {
        let baseline = memlock::stats().locked_pages;
        assert!(matches!(
            from_seed(algorithm, key.seed().expose()),
            Err(Error::MemoryLock)
        ));
        assert!(matches!(
            sign(
                algorithm,
                key.seed().expose(),
                b"private message",
                b"context"
            ),
            Err(Error::MemoryLock)
        ));
        assert_eq!(memlock::stats().locked_pages, baseline);
        public_cases.push((algorithm, key.public_key, signature));
    }
    // DE: Kleine Hashflächen könnten dieselbe bereits gesperrte Seed-Seite nutzen.
    // EN: Small hash workspaces could share an already locked seed page.
    // DE/EN: Erst alle privaten Owner freigeben / release every private owner first.
    assert_eq!(memlock::stats().locked_pages, 0);
    for (algorithm, public_key, signature) in public_cases {
        assert!(!verify(
            algorithm,
            &public_key,
            b"private message",
            b"context",
            &signature
        ));
        assert_eq!(memlock::stats().locked_pages, 0);
    }
    assert!(memlock::stats().failed_attempts > before.failed_attempts);
}

fn prepare_cases() -> Vec<(DsaAlgorithm, DsaKeyPair, Vec<u8>)> {
    let mut cases = Vec::new();
    for algorithm in [
        DsaAlgorithm::MlDsa44,
        DsaAlgorithm::MlDsa65,
        DsaAlgorithm::MlDsa87,
    ] {
        let key = generate(algorithm).unwrap();
        let signature = sign(
            algorithm,
            key.seed().expose(),
            b"private message",
            b"context",
        )
        .unwrap();
        cases.push((algorithm, key, signature));
    }
    cases
}
