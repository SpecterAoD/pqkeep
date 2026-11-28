//! DE: Echte Sperrverweigerung und Unwind ohne Änderung des Elternlimits.
//! EN: Actual lock denial and unwind without changing the parent limit.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{Error, files::hidden_result::HiddenResult, hardening::memlock};
use rustix::process::{Resource, getrlimit, setrlimit};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn identity_denial_and_unwind_are_checked_in_an_owned_child() {
    let before = getrlimit(Resource::Memlock);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "files::signed_by::denial_tests::identity_denial_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PQKEEP_IDENTITY_DENIAL_CHILD", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            assert!(
                status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
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
    assert_eq!(getrlimit(Resource::Memlock), before);
}

#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded owned child only"]
fn identity_denial_child() {
    assert_eq!(std::env::var("PQKEEP_IDENTITY_DENIAL_CHILD").unwrap(), "1");
    let baseline = memlock::stats().locked_pages;
    let unwind = std::panic::catch_unwind(|| {
        let shared = HiddenResult::new().unwrap();
        shared.store(SignedBy::from_public_key(b"public unwind fixture").unwrap());
        let other = shared.clone();
        let signed = other.take().unwrap();
        let _duplicate = signed.try_duplicate().unwrap();
        shared.store(signed);
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(unwind.is_err());
    assert_eq!(memlock::stats().locked_pages, baseline);
    actual_denial();
    assert_eq!(memlock::stats().locked_pages, baseline);
}

fn actual_denial() {
    let signed = SignedBy::from_public_key(b"public retained fixture").unwrap();
    let expected = signed.try_duplicate().unwrap();
    let mut limit = getrlimit(Resource::Memlock);
    limit.current = Some(0);
    setrlimit(Resource::Memlock, limit).unwrap();
    assert_eq!(getrlimit(Resource::Memlock).current, Some(0));
    // DE: Bereits gesperrte gemeinsame Seiten können weitere kleine Owner aufnehmen.
    // EN: Already locked shared pages may accommodate additional small owners.
    assert_eventual_denial(|| signed.try_duplicate());
    assert_eq!(signed, expected);
    crate::files::locked_owner_tests::locked(signed.0.get());
    signed.0.get().assert_metadata_locked();
    assert_eventual_denial(HiddenResult::new);
    assert_eventual_denial(|| SignedBy::from_public_key(b"public hash fixture"));
}

fn assert_eventual_denial<T>(mut create: impl FnMut() -> Result<T>) {
    let failures = memlock::stats().failed_attempts;
    let mut retained = Vec::new();
    let mut denied = false;
    for _ in 0..1024 {
        match create() {
            Ok(value) => retained.push(value),
            Err(error) => {
                assert!(matches!(error, Error::MemoryLock));
                denied = true;
                break;
            }
        }
    }
    assert!(
        denied,
        "DE/EN: Tatsächliche Verweigerung erforderlich / actual denial required"
    );
    assert!(memlock::stats().failed_attempts > failures);
}
