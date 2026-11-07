//! DE: Sandbox-Profil `Cli` (nur Linux), Proben im Kindprozess wie in `sandbox_api.rs`:
//! Freigegebenes (Quelle lesen, im Zielordner anlegen/umbenennen/löschen) funktioniert,
//! alles andere (fremde Dateien, Netzwerk, Programme starten) scheitert oder beendet
//! den Prozess.
//! EN: Sandbox profile `Cli` (Linux only), probes in a child process as in
//! `sandbox_api.rs`: permitted things (read the source, create/rename/delete in the
//! target directory) work; everything else (other files, network, starting programs)
//! fails or kills the process.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pqkeep::hardening::sandbox::{self, CliAccess, Profile};

const ENV: &str = "PQK_SANDBOX_CLI_PROBE";
const SIGSYS: i32 = 31;

/// DE: Einstieg im Kindprozess. EN: Entry point in the child process.
#[test]
fn zz_probe_entry() {
    let Ok(probe) = std::env::var(ENV) else {
        return;
    };
    let root = PathBuf::from(std::env::var("PQK_PROBE_DIR").unwrap());
    let access = CliAccess {
        read: vec![root.join("quelle.txt")],
        write_dirs: vec![root.join("ziel")],
    };
    let report = sandbox::apply(&Profile::Cli(access)).unwrap();
    println!("LANDLOCK={}", report.landlock.as_str());
    println!("RESULT={}", run_probe(&probe, &root));
    std::process::exit(0);
}

fn ok_or_err<T, E>(r: &Result<T, E>) -> &'static str {
    if r.is_ok() { "ok" } else { "err" }
}

fn run_probe(probe: &str, root: &Path) -> &'static str {
    let ziel = root.join("ziel");
    match probe {
        "read_source" => ok_or_err(&std::fs::read(root.join("quelle.txt"))),
        "read_other" => ok_or_err(&std::fs::read(root.join("fremd.txt"))),
        "write_target" => {
            let file = ziel.join("neu.txt");
            let steps = std::fs::write(&file, b"x")
                .and_then(|()| std::fs::create_dir(ziel.join("ordner")))
                .and_then(|()| std::fs::hard_link(&file, ziel.join("link.txt")))
                .and_then(|()| std::fs::rename(ziel.join("link.txt"), ziel.join("umbenannt.txt")))
                .and_then(|()| std::fs::remove_file(ziel.join("umbenannt.txt")))
                .and_then(|()| std::fs::remove_dir_all(ziel.join("ordner")))
                .and_then(|()| std::fs::File::open(&file)?.sync_all());
            ok_or_err(&steps)
        }
        "write_outside" => ok_or_err(&std::fs::write(root.join("aussen.txt"), b"x")),
        "symlink_target" => ok_or_err(&std::os::unix::fs::symlink("/etc", ziel.join("s"))),
        "tcp_connect" => ok_or_err(&std::net::TcpStream::connect("127.0.0.1:9")),
        "exec" => {
            let _err = Command::new("/bin/true").exec();
            "err"
        }
        _ => "unknown",
    }
}

fn probe(name: &str) -> (Output, PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("quelle.txt"), b"quelle").unwrap();
    std::fs::write(dir.path().join("fremd.txt"), b"geheim").unwrap();
    std::fs::create_dir(dir.path().join("ziel")).unwrap();
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "zz_probe_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENV, name)
        .env("PQK_PROBE_DIR", dir.path())
        .output()
        .unwrap();
    (out, dir.path().to_path_buf(), dir)
}

fn result(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn landlock_active(out: &Output) -> bool {
    !result(out).contains("LANDLOCK=unsupported")
}

#[test]
fn permitted_paths_work() {
    for name in ["read_source", "write_target"] {
        let (out, root, _dir) = probe(name);
        assert!(
            result(&out).contains("RESULT=ok"),
            "{name}: {}",
            result(&out)
        );
        if name == "write_target" {
            assert!(root.join("ziel/neu.txt").exists());
            assert!(!root.join("ziel/ordner").exists());
        }
    }
}

#[test]
fn other_paths_are_denied() {
    for name in ["read_other", "write_outside", "symlink_target"] {
        let (out, root, _dir) = probe(name);
        if !landlock_active(&out) && name != "symlink_target" {
            eprintln!("Landlock nicht verfügbar – {name} übersprungen / skipped");
            continue;
        }
        assert!(
            result(&out).contains("RESULT=err"),
            "{name}: {}",
            result(&out)
        );
        assert!(!root.join("aussen.txt").exists());
        assert!(!root.join("ziel/s").exists());
    }
}

#[test]
fn network_and_exec_kill_the_process() {
    for name in ["tcp_connect", "exec"] {
        let (out, _, _dir) = probe(name);
        assert_eq!(
            out.status.signal(),
            Some(SIGSYS),
            "{name}: {}",
            result(&out)
        );
    }
}

#[test]
fn missing_path_is_an_error_not_a_silent_gap() {
    let dir = tempfile::tempdir().unwrap();
    // DE: Im Kindprozess prüfen, damit dieser Testprozess frei bleibt.
    // EN: Check in a child process so this test process stays unrestricted.
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "zz_missing_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("PQK_SANDBOX_MISSING", dir.path().join("fehlt"))
        .output()
        .unwrap();
    assert!(result(&out).contains("MISSING=err"), "{}", result(&out));
}

/// DE: Einstieg für den Test mit fehlendem Pfad. EN: Entry for the missing-path test.
#[test]
fn zz_missing_entry() {
    let Ok(path) = std::env::var("PQK_SANDBOX_MISSING") else {
        return;
    };
    let access = CliAccess {
        read: vec![PathBuf::from(path)],
        write_dirs: Vec::new(),
    };
    let r = sandbox::apply(&Profile::Cli(access));
    println!("MISSING={}", if r.is_ok() { "ok" } else { "err" });
    std::process::exit(0);
}
