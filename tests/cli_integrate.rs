//! DE: `pqkeep integrate` und `pqkeep context` (Linux) mit temporärem `XDG_DATA_HOME` und
//! gefälschten Dateimanager-/Terminalprogrammen: Einrichten, Wiederholen, Trockenlauf, fremde
//! Dateien bleiben unberührt, Entfernen, Status, sichere Übergabe böswilliger Dateinamen.
//! EN: `pqkeep integrate` and `pqkeep context` (Linux) with a temporary `XDG_DATA_HOME` and fake
//! file manager/terminal programs: install, repeat, dry run, foreign files untouched, uninstall,
//! status, safe passing of malicious file names.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_pqkeep");

struct Env {
    _dir: tempfile::TempDir,
    data: PathBuf,
    fake: PathBuf,
}

/// DE: Gefälschte Programme; das Terminal schreibt seine Argumente NUL-getrennt nach `$RECORD`.
/// EN: Fake programs; the terminal writes its arguments NUL-separated to `$RECORD`.
fn env(managers: &[&str]) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("fakebin");
    fs::create_dir(&fake).unwrap();
    let mut progs: Vec<&str> = managers.to_vec();
    progs.push("gnome-terminal");
    for p in progs {
        let path = fake.join(p);
        fs::write(&path, "#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$RECORD\"\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    Env {
        data: dir.path().join("data"),
        fake,
        _dir: dir,
    }
}

fn run(e: &Env, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN)
        .args(["--lang", "en"])
        .args(args)
        .env("XDG_DATA_HOME", &e.data)
        .env("HOME", e.data.parent().unwrap())
        .env("PATH", &e.fake)
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

fn files(e: &Env) -> Vec<(PathBuf, u32)> {
    let mut out = Vec::new();
    for sub in ["nemo/actions", "nautilus/scripts", "kio/servicemenus"] {
        if let Ok(rd) = fs::read_dir(e.data.join(sub)) {
            for f in rd {
                let p = f.unwrap().path();
                let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
                out.push((p, mode));
            }
        }
    }
    out.sort();
    out
}

fn real_bin() -> String {
    fs::canonicalize(BIN).unwrap().to_str().unwrap().to_owned()
}

#[test]
fn install_writes_entries_for_all_managers_and_is_repeatable() {
    let e = env(&["nemo", "nautilus", "dolphin"]);
    let (code, out, err) = run(&e, &["integrate", "install"]);
    assert_eq!(code, 0, "{err}");
    let list = files(&e);
    assert_eq!(list.len(), 6, "{list:?}");
    for (p, mode) in &list {
        let want = if p.to_str().unwrap().contains("nemo/") {
            0o644
        } else {
            0o755
        };
        assert_eq!(*mode, want, "{p:?}");
        assert!(
            fs::read_to_string(p).unwrap().contains(&real_bin()),
            "{p:?}"
        );
    }
    assert!(e.data.join("pqkeep/integration.json").is_file());
    assert!(out.contains("Set up"));
    let (code, out, _) = run(&e, &["integrate", "install"]);
    assert_eq!(code, 0);
    assert_eq!(out.matches("Unchanged").count(), 6, "{out}");
}

#[test]
fn dry_run_changes_nothing() {
    let e = env(&["nemo"]);
    let (code, out, _) = run(&e, &["integrate", "install", "--dry-run"]);
    assert_eq!(code, 0);
    assert!(out.contains("Dry run"));
    assert!(!e.data.exists() || files(&e).is_empty());
}

#[test]
fn foreign_and_modified_files_are_never_touched() {
    let e = env(&["nemo"]);
    let foreign = e.data.join("nemo/actions/pqkeep-encrypt.nemo_action");
    fs::create_dir_all(foreign.parent().unwrap()).unwrap();
    fs::write(&foreign, "fremd").unwrap();
    let (code, _, err) = run(&e, &["integrate", "install"]);
    assert_eq!(code, 0);
    assert!(err.contains("Not touched"), "{err}");
    assert_eq!(fs::read_to_string(&foreign).unwrap(), "fremd");
    let ours = e.data.join("nemo/actions/pqkeep-decrypt.nemo_action");
    fs::write(
        &ours,
        format!(
            "{}# vom Nutzer geändert\n",
            fs::read_to_string(&ours).unwrap()
        ),
    )
    .unwrap();
    let (code, out, err) = run(&e, &["integrate", "uninstall"]);
    assert_eq!(code, 0, "{err}");
    assert!(ours.exists() && foreign.exists(), "{out}{err}");
    assert!(!e.data.join("pqkeep/integration.json").exists());
}

#[test]
fn uninstall_removes_own_entries_and_status_reports() {
    let e = env(&["nemo", "nautilus", "dolphin"]);
    assert_eq!(run(&e, &["integrate", "install"]).0, 0);
    let (code, out, _) = run(&e, &["integrate", "status"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("nemo, nautilus, dolphin") && out.matches("Set up").count() == 6,
        "{out}"
    );
    let (code, out, _) = run(&e, &["integrate", "uninstall"]);
    assert_eq!(code, 0);
    assert_eq!(out.matches("Removed").count(), 6, "{out}");
    assert_eq!(files(&e), Vec::new());
}

#[test]
fn no_file_manager_is_an_error_but_all_installs_nemo_without_terminal() {
    let e = env(&[]);
    fs::remove_file(e.fake.join("gnome-terminal")).unwrap();
    let (code, _, err) = run(&e, &["integrate", "install"]);
    assert_eq!(code, 1);
    assert!(err.contains("No supported file manager"), "{err}");
    let (code, _, err) = run(&e, &["integrate", "install", "--all"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("No terminal found"), "{err}");
    assert_eq!(files(&e).len(), 2);
}

/// DE: Das erzeugte Nautilus-Skript übergibt einen böswilligen Namen als genau ein Argument.
/// EN: The generated Nautilus script passes a malicious name as exactly one argument.
#[test]
fn nautilus_script_passes_malicious_name_as_one_argument() {
    let e = env(&["nautilus"]);
    assert_eq!(run(&e, &["integrate", "install"]).0, 0);
    let script = files(&e)
        .into_iter()
        .map(|(p, _)| p)
        .find(|p| p.ends_with("Decrypt with PQKeep"))
        .unwrap();
    let record = e.data.join("record");
    let nasty = "a b'\"; touch /tmp/pwned $(id) `id`\n--no-sandbox.pqkf";
    let status = Command::new("/bin/sh")
        .arg(&script)
        .arg(nasty)
        .env("RECORD", &record)
        .status()
        .unwrap();
    assert!(status.success());
    let args: Vec<String> = fs::read_to_string(&record)
        .unwrap()
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    assert_eq!(args, ["--", &real_bin(), "context", "decrypt", "--", nasty]);
    // DE: Mehrfachauswahl wird ignoriert. EN: Multiple selection is ignored.
    fs::remove_file(&record).unwrap();
    let status = Command::new("/bin/sh")
        .arg(&script)
        .args(["a", "b"])
        .env("RECORD", &record)
        .status()
        .unwrap();
    assert!(status.success() && !record.exists());
}

#[test]
fn context_needs_terminal_and_exactly_one_path() {
    let e = env(&[]);
    let (code, _, _) = run(&e, &["context", "encrypt", "--", "x"]);
    assert_eq!(code, 2);
    let (code, _, err) = run(&e, &["context", "encrypt", "--", "a", "b"]);
    assert_eq!(code, 2, "{err}");
}

#[test]
fn install_runs_sandboxed() {
    let e = env(&["nemo"]);
    let (code, _, err) = run(&e, &["--verbose", "integrate", "install"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("Sandbox: landlock=") && err.contains("seccomp=full"),
        "{err}"
    );
}

#[test]
fn window_mode_is_used_when_zenity_exists_unless_terminal_is_forced() {
    let e = env(&["nemo", "nautilus", "zenity"]);
    let (code, out, err) = run(&e, &["integrate", "install"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Mode: Windows"), "{out}");
    let action = e.data.join("nemo/actions/pqkeep-encrypt.nemo_action");
    let text = fs::read_to_string(&action).unwrap();
    assert!(text.contains(" context --dialog encrypt -- %F") && text.contains("Terminal=false"));
    let script = fs::read_to_string(e.data.join("nautilus/scripts/Encrypt with PQKeep")).unwrap();
    assert!(script.contains("context --dialog encrypt") && !script.contains("gnome-terminal"));
    let (_, out, _) = run(&e, &["integrate", "status"]);
    assert!(out.contains("Mode: Windows"), "{out}");
    let (code, out, _) = run(&e, &["integrate", "install", "--terminal"]);
    assert_eq!(code, 0);
    assert!(out.contains("Mode: Terminal"), "{out}");
    let text = fs::read_to_string(&action).unwrap();
    assert!(text.contains("Terminal=true") && !text.contains("--dialog"));
}
