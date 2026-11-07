//! DE: Sandbox-Profil `Api` (nur Linux). Jede Probe läuft in einem eigenen Kindprozess
//! (dieses Testprogramm startet sich selbst mit `KF_SANDBOX_PROBE=<name>`), weil die
//! Sandbox unumkehrbar ist. Verbotenes muss scheitern oder den Prozess beenden (SIGSYS),
//! Erlaubtes (Threads, Argon2, Zufall) muss funktionieren.
//! EN: Sandbox profile `Api` (Linux only). Every probe runs in its own child process
//! (this test program restarts itself with `KF_SANDBOX_PROBE=<name>`) because the
//! sandbox is irreversible. Forbidden things must fail or kill the process (SIGSYS);
//! allowed things (threads, Argon2, randomness) must work.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Output};

use pqc_keyforge::crypto::{kdf, rng};
use pqc_keyforge::hardening::sandbox::{self, Profile, Status};

const ENV: &str = "KF_SANDBOX_PROBE";
const SIGSYS: i32 = 31;

/// DE: Einstieg im Kindprozess; im normalen Testlauf ohne Wirkung.
/// EN: Entry point in the child process; no effect in a normal test run.
#[test]
fn zz_probe_entry() {
    let Ok(probe) = std::env::var(ENV) else {
        return;
    };
    let dir = std::env::var("KF_PROBE_DIR").unwrap();
    let report = sandbox::apply(Profile::Api).unwrap();
    println!("LANDLOCK={}", report.landlock.as_str());
    println!("SECCOMP={}", report.seccomp.as_str());
    let outcome = run_probe(&probe, &dir);
    println!("RESULT={outcome}");
    std::process::exit(0);
}

fn ok_or_err<T, E>(r: &Result<T, E>) -> &'static str {
    if r.is_ok() { "ok" } else { "err" }
}

fn run_probe(probe: &str, dir: &str) -> &'static str {
    let file = format!("{dir}/vorhanden.txt");
    match probe {
        "read_file" => ok_or_err(&std::fs::read(&file)),
        "create_file" => ok_or_err(&std::fs::write(format!("{dir}/neu.txt"), b"x")),
        "mkdir" => ok_or_err(&std::fs::create_dir(format!("{dir}/ordner"))),
        "tcp_connect" => ok_or_err(&std::net::TcpStream::connect("127.0.0.1:9")),
        "tcp_listen" => ok_or_err(&std::net::TcpListener::bind("127.0.0.1:0")),
        "spawn" => ok_or_err(&Command::new("/bin/true").status()),
        "exec" => {
            let _err = Command::new("/bin/true").exec();
            "err"
        }
        "threads_kdf_rng" => {
            let worker = std::thread::spawn(|| {
                let salt = rng::array::<16>().unwrap();
                kdf::derive(b"probe", &salt, &common::min_params()).is_ok()
            });
            if worker.join().unwrap() { "ok" } else { "err" }
        }
        _ => "unknown",
    }
}

/// DE: Startet eine Probe; Rückgabe: Ausgabe und ob `neu.txt` entstanden ist.
/// EN: Starts a probe; returns the output and whether `neu.txt` was created.
fn probe(name: &str) -> (Output, bool) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("vorhanden.txt"), b"geheim").unwrap();
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "zz_probe_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENV, name)
        .env("KF_PROBE_DIR", dir.path())
        .output()
        .unwrap();
    // DE: `mkdirat` ist nie erlaubt. EN: `mkdirat` is never allowed.
    assert!(!dir.path().join("ordner").exists());
    let created = dir.path().join("neu.txt").exists();
    (out, created)
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn landlock_active(out: &Output) -> bool {
    let text = stdout(out);
    !text.contains(&format!("LANDLOCK={}", Status::Unsupported.as_str()))
}

#[test]
fn allowed_work_runs_inside_the_sandbox() {
    let (out, _) = probe("threads_kdf_rng");
    let text = stdout(&out);
    assert!(text.contains("SECCOMP=full"), "{text}");
    assert!(text.contains("RESULT=ok"), "{text}");
}

#[test]
fn file_access_is_denied() {
    for name in ["read_file", "create_file", "mkdir"] {
        let (out, created) = probe(name);
        let text = stdout(&out);
        // DE: Ohne Landlock bleibt nur Seccomp: `openat` ist erlaubt, `mkdirat` nicht.
        // EN: Without Landlock only seccomp remains: `openat` is allowed, `mkdirat` is not.
        if name != "mkdir" && !landlock_active(&out) {
            eprintln!("Landlock nicht verfügbar – {name} übersprungen / skipped");
            continue;
        }
        assert!(text.contains("RESULT=err"), "{name}: {text}");
        assert!(!created, "{name}");
    }
}

#[test]
fn network_and_processes_kill_or_fail() {
    for name in ["tcp_connect", "tcp_listen", "exec", "spawn"] {
        let (out, _) = probe(name);
        let killed = out.status.signal() == Some(SIGSYS);
        let failed = stdout(&out).contains("RESULT=err");
        assert!(
            killed || failed,
            "{name}: {:?} {}",
            out.status,
            stdout(&out)
        );
        if name != "spawn" {
            assert!(killed, "{name} muss SIGSYS auslösen / must raise SIGSYS");
        }
    }
}
