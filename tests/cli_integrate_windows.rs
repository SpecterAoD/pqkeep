//! DE: `pqkeep integrate` unter Windows gegen die echte Registry, aber in einem eigenen Zweig
//! `HKCU\Software\PQKeepTest-…` (nur Debug-Builds lassen sich umlenken) und mit temporärem
//! `APPDATA`: Einrichten, Wiederholen, Trockenlauf, fremde und geänderte Einträge bleiben,
//! Entfernen räumt vollständig auf, Programmpfade mit Leerzeichen/Umlauten, Temp-Pfad abgelehnt.
//! EN: `pqkeep integrate` on Windows against the real registry, but in a separate branch
//! `HKCU\Software\PQKeepTest-…` (only debug builds can be redirected) and with a temporary
//! `APPDATA`: install, repeat, dry run, foreign and modified entries stay, uninstall cleans up
//! completely, program paths with spaces/umlauts, temp path rejected.
#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use windows_registry::CURRENT_USER;

const BIN: &str = env!("CARGO_BIN_EXE_pqkeep");
const LAUNCHER: &str = env!("CARGO_BIN_EXE_pqkeepw");
const VERBS: [&str; 3] = [
    r"*\shell\PQKeep.Encrypt",
    r"Directory\shell\PQKeep.Encrypt",
    r"SystemFileAssociations\.pqkf\shell\PQKeep.Decrypt",
];

static NEXT: AtomicU32 = AtomicU32::new(0);

/// DE: Eigener Registry-Zweig und APPDATA; räumt beim Drop auf. EN: Own branch and APPDATA; cleans up on drop.
struct Env {
    root: String,
    appdata: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let root = format!(r"Software\PQKeepTest-{}-{n}", std::process::id());
        let _ = CURRENT_USER.remove_tree(&root);
        Self {
            root,
            appdata: tempfile::tempdir().unwrap(),
        }
    }

    fn run_with(&self, bin: &Path, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(bin)
            .args(["--lang", "en", "integrate"])
            .args(args)
            .env("PQKEEP_TEST_REG_ROOT", &self.root)
            .env("APPDATA", self.appdata.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        (
            out.status.code().unwrap_or(-1),
            s(&out.stdout),
            s(&out.stderr),
        )
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        self.run_with(Path::new(BIN), args)
    }

    fn key(&self, rel: &str) -> String {
        format!(r"{}\{rel}", self.root)
    }

    fn exists(&self, rel: &str) -> bool {
        CURRENT_USER.open(self.key(rel)).is_ok()
    }

    fn command(&self, verb: &str) -> String {
        let key = CURRENT_USER
            .open(self.key(&format!(r"{verb}\command")))
            .unwrap();
        key.get_string("").unwrap()
    }

    fn manifest(&self) -> PathBuf {
        self.appdata.path().join(r"PQKeep\integration.json")
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = CURRENT_USER.remove_tree(&self.root);
    }
}

#[test]
fn install_writes_all_verbs_and_is_idempotent() {
    let e = Env::new();
    let (code, out, err) = e.run(&["install"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("Mode: Windows (pqkeepw.exe"), "{out}");
    for verb in VERBS {
        let cmd = e.command(verb);
        assert!(cmd.starts_with(&format!("\"{LAUNCHER}\" ")), "{cmd}");
        assert!(cmd.ends_with(r#" -- "%1""#), "{cmd}");
        let key = CURRENT_USER.open(e.key(verb)).unwrap();
        assert_eq!(key.get_string("MultiSelectModel").unwrap(), "Single");
    }
    assert!(e.command(VERBS[2]).contains("\" decrypt -- "));
    assert!(e.manifest().is_file());
    assert!(out.contains("Show more options"));
    let (code, out, _) = e.run(&["install"]);
    assert_eq!(code, 0);
    assert_eq!(out.matches("Unchanged").count(), 3, "{out}");
    let (code, out, _) = e.run(&["status"]);
    assert_eq!(code, 0);
    assert_eq!(out.matches("Set up").count(), 3, "{out}");
}

#[test]
fn terminal_option_uses_the_console_program() {
    let e = Env::new();
    let (code, out, err) = e.run(&["install", "--terminal"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("Mode: Terminal"), "{out}");
    let cmd = e.command(VERBS[0]);
    assert_eq!(cmd, format!("\"{BIN}\" context encrypt -- \"%1\""));
    // DE: Wechsel zurück ersetzt die eigenen Einträge. EN: Switching back replaces own entries.
    let (_, out, _) = e.run(&["install"]);
    assert_eq!(out.matches("Set up").count(), 3, "{out}");
    assert!(e.command(VERBS[0]).starts_with(&format!("\"{LAUNCHER}\" ")));
}

#[test]
fn uninstall_removes_everything_it_created() {
    let e = Env::new();
    assert_eq!(e.run(&["install"]).0, 0);
    let (code, out, err) = e.run(&["uninstall"]);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(out.matches("Removed").count(), 3, "{out}");
    for rel in ["*", "Directory", "SystemFileAssociations"] {
        assert!(!e.exists(rel), "{rel} bleibt / remains");
    }
    assert!(!e.manifest().exists());
}

#[test]
fn dry_run_changes_nothing() {
    let e = Env::new();
    let (code, out, _) = e.run(&["install", "--dry-run"]);
    assert_eq!(code, 0);
    assert!(out.contains("Dry run"));
    assert!(!e.exists("*"));
    assert!(!e.manifest().exists());
}

#[test]
fn foreign_entry_is_left_alone() {
    let e = Env::new();
    let foreign = CURRENT_USER.create(e.key(VERBS[0])).unwrap();
    foreign.set_string("MUIVerb", "fremd").unwrap();
    let (code, _, err) = e.run(&["install"]);
    assert_eq!(code, 0);
    assert!(err.contains("Not touched"), "{err}");
    assert_eq!(foreign.get_string("MUIVerb").unwrap(), "fremd");
    assert_eq!(e.run(&["uninstall"]).0, 0);
    assert!(e.exists(VERBS[0]));
    assert!(!e.exists("Directory"));
}

#[test]
fn modified_entry_survives_uninstall() {
    let e = Env::new();
    assert_eq!(e.run(&["install"]).0, 0);
    let cmd = CURRENT_USER
        .create(e.key(&format!(r"{}\command", VERBS[1])))
        .unwrap();
    cmd.set_string("", "notepad.exe \"%1\"").unwrap();
    let (_, out, _) = e.run(&["status"]);
    assert!(out.contains("Not touched"), "{out}");
    let (code, out, err) = e.run(&["uninstall"]);
    assert_eq!(code, 0);
    assert_eq!(out.matches("Removed").count(), 2, "{out}");
    assert!(err.contains("Not touched"));
    assert_eq!(e.command(VERBS[1]), "notepad.exe \"%1\"");
    assert!(!e.exists(VERBS[0]));
}

#[test]
fn program_path_with_spaces_and_umlauts() {
    let e = Env::new();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("Programme ä ö {}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let copy = dir.join("pqkeep.exe");
    std::fs::copy(BIN, &copy).unwrap();
    let (code, out, err) = e.run_with(&copy, &["install"]);
    assert_eq!(code, 0, "{out}{err}");
    let expected = format!("\"{}\" context encrypt -- \"%1\"", copy.display());
    assert_eq!(e.command(VERBS[0]), expected);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn program_in_temp_folder_is_rejected() {
    let e = Env::new();
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("pqkeep.exe");
    std::fs::copy(BIN, &copy).unwrap();
    let (code, _, err) = e.run_with(&copy, &["install"]);
    assert_ne!(code, 0);
    assert!(err.contains("Unsuitable program path"), "{err}");
    assert!(!e.exists("*"));
}
