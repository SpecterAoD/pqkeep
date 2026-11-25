//! DE: Tatsächliche Parser-Sperrverweigerung im begrenzten eigenen Kind.
//! EN: Actual parser lock denial in bounded isolated children.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn parser_state_denial_is_checked_before_private_binding_in_bounded_children() {
    use std::time::{Duration, Instant};
    for mode in ["metadata", "payload"] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "api::locked_json::locked_parser::tests::denial::parser_state_denial_child",
                "--ignored",
                "--test-threads=1",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .env("PQKEEP_PARSER_STATE_DENIAL", mode)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{mode}");
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
            assert!(!timed_out, "{mode}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
#[ignore = "DE: Nur isoliert ausführen. EN: Execute only in an isolated child."]
fn parser_state_denial_child() {
    use crate::hardening::memlock::LockedRange;
    use rustix::process::{Resource, Rlimit, setrlimit};
    let mode = std::env::var("PQKEEP_PARSER_STATE_DENIAL").unwrap();
    assert!(matches!(mode.as_str(), "metadata" | "payload"));
    assert_eq!(memlock::stats().locked_pages, 0);
    let mut state = (mode == "payload").then(|| empty().unwrap());
    let mut record = (mode == "payload").then(|| SecretState::new(LockedRange::empty()).unwrap());
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
    if let (Some(state), Some(record)) = (state.as_mut(), record.as_mut()) {
        let result =
            state
                .get_mut()
                .0
                .prepare_protected_scratch(4 * region::page::size(), |ptr, cap| {
                    assert!(!record.get_mut().acquire(ptr, cap));
                    Err::<Box<dyn serde_json::de::ScratchProtection>, _>(ApiError::Busy)
                });
        assert!(matches!(
            result,
            Err(serde_json::de::ProtectedScratchError::Protection(
                ApiError::Busy
            ))
        ));
        locked(&state.get().0);
        locked(record.get());
        assert!(
            state
                .get_mut()
                .0
                .deserialize_protected_slice::<Counted>(b"true")
                .err()
                .unwrap()
                .is_io()
        );
    } else {
        assert!(matches!(empty(), Err(ApiError::Busy)));
    }
    drop(state);
    drop(record);
    assert_eq!(VISITS.with(std::cell::Cell::get), 0);
    assert_eq!(memlock::stats().locked_pages, 0);
}
