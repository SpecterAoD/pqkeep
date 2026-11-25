//! DE: Sperrfehler nur im eigenen kurzlebigen Kindprozess.
//! EN: Lock failure only in our own short-lived child.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn parser_protection_denial_is_checked_in_bounded_children() {
    use std::time::{Duration, Instant};
    for mode in ["metadata", "payload"] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "api::locked_json::protection_tests::denial::parser_protection_denial_child",
                "--ignored",
                "--test-threads=1",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .env("PQKEEP_PARSER_PROTECTION_DENIAL", mode)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{mode}");
                let output = child.wait_with_output().unwrap();
                assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
                break;
            }
            let timed_out = Instant::now() >= deadline;
            if timed_out {
                child.kill().unwrap();
                child.wait().unwrap();
            }
            assert!(!timed_out, "{mode}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
#[ignore = "DE: Nur isoliert ausführen. EN: Execute only in an isolated child."]
fn parser_protection_denial_child() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    let mode = std::env::var("PQKEEP_PARSER_PROTECTION_DENIAL").unwrap();
    assert!(matches!(mode.as_str(), "metadata" | "payload"));
    assert_eq!(memlock::stats().locked_pages, 0);
    let size = region::page::size();
    let scratch = vec![0u8; 4 * size];
    let address = scratch.as_ptr().addr();
    let interior = address - address % size + size;
    let mut state = (mode == "payload").then(|| SecretState::new(LockedRange::empty()).unwrap());
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
    if let Some(state) = state.as_mut() {
        assert!(!state.get_mut().acquire(interior, size));
        assert!(!state.get().complete(interior, size));
        locked(state.get());
    } else {
        assert!(matches!(
            ScratchLock::new(interior, size),
            Err(ApiError::Busy)
        ));
    }
    assert!(!memlock::is_locked(interior));
    drop(state);
    assert_eq!(memlock::stats().locked_pages, 0);
}
