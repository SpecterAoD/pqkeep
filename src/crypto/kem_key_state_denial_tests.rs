//! DE: Teilweise gesperrte private Payloads vor Seed-Verarbeitung sicher ablehnen.
//! EN: Safely reject partially locked private payloads before seed processing.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn nested_key_lock_denial_releases_prior_payloads_before_private_entry() {
    use std::time::{Duration, Instant};
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crypto::kem::key_state::tests::order::denial::nested_key_denial_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PQKEEP_NESTED_KEM_DENIAL", "1")
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
#[ignore = "DE: Nur im begrenzten Kindprozess. EN: Only in the bounded child process."]
fn nested_key_denial_child() {
    assert_eq!(std::env::var("PQKEEP_NESTED_KEM_DENIAL").unwrap(), "1");
    let seed = rng::secret(64).unwrap();
    let witness = Arc::new(Witness {
        mode: 4,
        ..Witness::default()
    });
    CURRENT.with(|current| *current.borrow_mut() = Some(witness.clone()));
    let before = memlock::stats();
    let result = KeyState::<Probe>::new(seed_state::view(&seed).unwrap());
    assert!(matches!(result, Err(Error::MemoryLock)));
    assert!(!witness.entered.load(Ordering::SeqCst));
    assert_eq!(witness.wipes.load(Ordering::SeqCst), 0);
    assert!(witness.released_before_free.load(Ordering::SeqCst));
    assert_eq!(memlock::stats().locked_pages, before.locked_pages);
    assert!(memlock::stats().failed_attempts > before.failed_attempts);
    CURRENT.with(|current| *current.borrow_mut() = None);
}
