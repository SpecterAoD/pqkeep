//! DE: Tatsächliche Ressourcenverweigerung und Unwind im begrenzten eigenen Kind.
//! EN: Actual resource denial and unwind in a bounded owned child.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;
use rustix::process::{Resource, getrlimit, setrlimit};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn growth_denial_preserves_index_and_unwind_releases_actual_locks() {
    let before = getrlimit(Resource::Memlock);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "files::confidential_path_index::denial_tests::index_denial_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PQKEEP_PATH_INDEX_DENIAL_CHILD", "1")
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
#[ignore = "DE/EN: Eigenes begrenztes Kind / bounded owned child only"]
fn index_denial_child() {
    assert_eq!(
        std::env::var("PQKEEP_PATH_INDEX_DENIAL_CHILD").unwrap(),
        "1"
    );
    let baseline = memlock::stats().locked_pages;
    let result = std::panic::catch_unwind(|| {
        let mut index = Index::default();
        for n in 0..32 {
            index
                .insert(
                    ConfidentialText::from_text(&format!("unwind-{n}")).unwrap(),
                    true,
                )
                .unwrap();
        }
        super::tests::assert_storage_locked(&index);
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(result.is_err());
    assert_eq!(memlock::stats().locked_pages, baseline);
    actual_growth_denial(baseline);
}

fn actual_growth_denial(baseline: usize) {
    let mut index = Index::default();
    for n in 0..16 {
        index
            .insert(
                ConfidentialText::from_text(&format!("retained-{n:04}")).unwrap(),
                true,
            )
            .unwrap();
    }
    // DE: Quellen vor der Limitabsenkung sperren, damit die tatsächliche Indexoperation geprüft wird.
    // EN: Prelock sources before lowering the limit to test the actual index operation.
    let prepared: Vec<_> = (0..512)
        .map(|n| ConfidentialText::from_text(&format!("additional-{n:04}")).unwrap())
        .collect();
    let mut limit = getrlimit(Resource::Memlock);
    limit.current = Some(0);
    setrlimit(Resource::Memlock, limit).unwrap();
    assert_eq!(getrlimit(Resource::Memlock).current, Some(0));
    let failures_before = memlock::stats().failed_attempts;
    let mut refused = false;
    for key in prepared {
        let before = index.len();
        match index.insert(key, true) {
            Ok(()) => assert_eq!(index.len(), before + 1),
            Err(error) => {
                assert!(matches!(error, Error::MemoryLock));
                assert_eq!(index.len(), before);
                refused = true;
                break;
            }
        }
    }
    assert!(
        refused,
        "DE/EN: Tatsächliche Sperrverweigerung erforderlich / actual lock denial required"
    );
    assert!(memlock::stats().failed_attempts > failures_before);
    for n in 0..16 {
        assert_eq!(index.get(format!("retained-{n:04}").as_bytes()), Some(true));
    }
    super::tests::assert_storage_locked(&index);
    drop(index);
    assert_eq!(memlock::stats().locked_pages, baseline);
}
