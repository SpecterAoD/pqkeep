//! DE: Zu kleines Sperrbudget (#325): Mit dem üblichen Desktop-Limit (8 MiB) bricht die
//! Passphrase-Verschlüsselung sicher ab – verständliche Meldung mit Limit und Abhilfe, Exit-Code 1,
//! kein Ziel, keine Reste. Das Limit senkt `prlimit` nur für den Kindprozess (ohne Rechte).
//! EN: Too small lock budget (#325): with the usual desktop limit (8 MiB) passphrase encryption
//! fails safely – clear message with limit and remedy, exit code 1, no target, no leftovers.
//! `prlimit` lowers the limit for the child only (no privileges).
#![cfg(target_os = "linux")]
// DE: Tests dürfen unwrap/expect nutzen. EN: Tests may use unwrap/expect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

/// DE: Als root (oder mit `CAP_IPC_LOCK`) gilt das Limit nicht. EN: Root or `CAP_IPC_LOCK` ignore the limit.
fn limit_applies() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let cap_eff = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .map(|v| u64::from_str_radix(v.trim(), 16).unwrap())
        .unwrap();
    cap_eff & (1 << 14) == 0 && Command::new("prlimit").arg("--version").output().is_ok()
}

#[test]
fn low_memlock_limit_fails_with_clear_hint() {
    // DE: Eine übersprungene Verweigerungsprüfung ist kein Sicherheitsnachweis.
    // EN: Skipping denial is not security evidence; require an effective child limit.
    assert!(
        limit_applies(),
        "test requires effective memlock limit/prlimit"
    );
    for profile in ["standard", "hardened"] {
        check_profile(profile);
    }
}

// DE: Beide unveränderten Profile müssen bei 8MiB vollständig verweigern.
// EN: Both unchanged profiles must refuse completely at 8MiB.
fn check_profile(profile: &str) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
    let pass = common::random_passphrase();
    let mut child = Command::new("prlimit")
        .args(["--memlock=8388608:8388608", env!("CARGO_BIN_EXE_pqkeep")])
        .args([
            "--lang",
            "en",
            "encrypt",
            "--profile",
            profile,
            "--passphrase-stdin",
            "--",
            "a.txt",
        ])
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let line = format!("{}\n", pass.as_ref().expose_str());
    let _ = child.stdin.take().unwrap().write_all(line.as_bytes());
    let out = finish(child);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("allowed: 8 MiB"), "{err}");
    assert!(
        err.contains("cap_ipc_lock+p") && err.contains("INSTALL.md"),
        "{err}"
    );
    assert_eq!(common::dir_names(dir.path()), vec!["a.txt"]);
}

// DE/EN: Nur das eigene Testkind bei Zeitüberschreitung beenden / bound own test child.
fn finish(mut child: std::process::Child) -> std::process::Output {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        let timed_out = std::time::Instant::now() >= deadline;
        if timed_out {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        assert!(!timed_out);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}
