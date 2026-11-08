//! DE: `pqkeep context --dialog` (Linux) mit einem nachgebauten zenity/kdialog: Das Ersatzprogramm
//! protokolliert seine Argumente und gibt vorbereitete Antworten aus. Geprüft: Ver- und
//! Entschlüsseln mit Passphrase und für einen Empfänger, ungleiche und schwache Passphrase mit
//! Wiederholung, Abbruch, böswillige Dateinamen, keine Passphrase in Fenster-Argumenten.
//! EN: `pqkeep context --dialog` (Linux) with a fake zenity/kdialog: the stand-in logs its arguments
//! and prints prepared answers. Checked: encrypt and decrypt with passphrase and for a recipient,
//! mismatched and weak passphrase with retry, cancel, malicious file names, no passphrase in window
//! arguments.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_pqkeep");

/// DE: Ersatz für zenity/kdialog: Antwort Nr. n aus `$ANSWERS/n.code` und `n.out`.
/// EN: Stand-in for zenity/kdialog: answer no. n from `$ANSWERS/n.code` and `n.out`.
const FAKE: &str = r#"#!/bin/sh
d="$ANSWERS"
case " $* " in *" --progress "*) exec sleep 60;; esac
for a in "$@"; do printf '%s\037' "$a"; done >> "$d/record"
printf '\036' >> "$d/record"
n=$(cat "$d/next"); echo $((n+1)) > "$d/next"
[ -f "$d/$n.out" ] && cat "$d/$n.out"
exit "$(cat "$d/$n.code" 2>/dev/null || echo 1)"
"#;

struct Env {
    dir: tempfile::TempDir,
    answers: PathBuf,
    fake: PathBuf,
}

impl Env {
    fn new(tool: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fakebin");
        let answers = dir.path().join("answers");
        fs::create_dir(&fake).unwrap();
        fs::create_dir(&answers).unwrap();
        let script = fake.join(tool);
        fs::write(&script, FAKE).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        // DE: PATH enthält nur diesen Ordner – echte zenity/kdialog bleiben unsichtbar.
        // EN: PATH holds only this folder – real zenity/kdialog stay invisible.
        for tool in ["cat", "sleep"] {
            let real = ["/usr/bin", "/bin"]
                .iter()
                .map(|d| Path::new(d).join(tool))
                .find(|p| p.exists())
                .unwrap();
            std::os::unix::fs::symlink(real, fake.join(tool)).unwrap();
        }
        Self { dir, answers, fake }
    }

    fn work(&self) -> &Path {
        self.dir.path()
    }

    /// DE: Antworten der Reihe nach: (Exit-Code, Ausgabe). EN: Answers in order: (exit code, output).
    fn answer(&self, list: &[(i32, &str)]) {
        let _ = fs::remove_file(self.answers.join("record"));
        fs::write(self.answers.join("next"), "0\n").unwrap();
        for (i, (code, out)) in list.iter().enumerate() {
            fs::write(self.answers.join(format!("{i}.code")), code.to_string()).unwrap();
            fs::write(self.answers.join(format!("{i}.out")), out).unwrap();
        }
    }

    /// DE: Protokoll: je Aufruf die Argumente. EN: Log: arguments per call.
    fn calls(&self) -> Vec<Vec<String>> {
        let raw = fs::read_to_string(self.answers.join("record")).unwrap_or_default();
        raw.split('\u{1e}')
            .filter(|c| !c.is_empty())
            .map(|c| {
                c.split('\u{1f}')
                    .filter(|a| !a.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .collect()
    }

    fn context(&self, action: &str, path: &Path) -> i32 {
        Command::new(BIN)
            .args(["--lang", "en", "context", "--dialog", action, "--"])
            .arg(path)
            .env("PATH", &self.fake)
            .env("DISPLAY", ":99")
            .env("ANSWERS", &self.answers)
            .env("HOME", self.work())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .code()
            .unwrap_or(-1)
    }
}

fn pass() -> String {
    common::random_passphrase().as_ref().expose_str().to_owned()
}

fn joined(calls: &[Vec<String>]) -> String {
    calls
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn passphrase_roundtrip_with_zenity() {
    let e = Env::new("zenity");
    let file = e.work().join("bericht.txt");
    fs::write(&file, b"geheimer Inhalt").unwrap();
    let p = pass();
    e.answer(&[(0, "0\n"), (0, &format!("{p}\n{p}\n")), (0, "")]);
    assert_eq!(e.context("encrypt", &file), 0);
    let enc = e.work().join("bericht.txt.pqkf");
    assert!(enc.is_file());
    let calls = e.calls();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(calls[1].contains(&"--forms".to_owned()));
    assert!(calls[2].contains(&"--info".to_owned()));
    assert!(joined(&calls).contains(enc.to_str().unwrap()));
    fs::rename(&file, e.work().join("original.txt")).unwrap();
    e.answer(&[(0, &format!("{p}\n")), (0, "")]);
    assert_eq!(e.context("decrypt", &enc), 0);
    assert_eq!(fs::read(&file).unwrap(), b"geheimer Inhalt");
    assert!(!joined(&e.calls()).contains(&p), "Passphrase in Argumenten");
}

#[test]
fn mismatch_shows_error_and_can_be_abandoned() {
    let e = Env::new("zenity");
    let file = e.work().join("a.txt");
    fs::write(&file, b"x").unwrap();
    let (p, q) = (pass(), pass());
    e.answer(&[(0, "0\n"), (0, &format!("{p}\n{q}\n")), (0, ""), (1, "")]);
    assert_ne!(e.context("encrypt", &file), 0);
    assert!(!e.work().join("a.txt.pqkf").exists());
    let calls = e.calls();
    assert!(calls[2].contains(&"--error".to_owned()), "{calls:?}");
    assert!(joined(&calls).contains("do not match"));
    assert!(calls[3].contains(&"--question".to_owned()));
}

#[test]
fn weak_passphrase_then_retry_succeeds() {
    let e = Env::new("zenity");
    let file = e.work().join("b.txt");
    fs::write(&file, b"x").unwrap();
    let p = pass();
    e.answer(&[
        (0, "0\n"),
        (0, "abc\nabc\n"),
        (0, ""),
        (0, ""),
        (0, &format!("{p}\n{p}\n")),
        (0, ""),
    ]);
    assert_eq!(e.context("encrypt", &file), 0);
    assert!(e.work().join("b.txt.pqkf").is_file());
    assert_eq!(e.calls().len(), 6);
}

#[test]
fn cancel_in_password_window_starts_nothing() {
    let e = Env::new("zenity");
    let file = e.work().join("c.txt");
    fs::write(&file, b"x").unwrap();
    e.answer(&[(0, "0\n"), (1, "")]);
    assert_eq!(e.context("encrypt", &file), 2);
    assert!(!e.work().join("c.txt.pqkf").exists());
    assert_eq!(e.calls().len(), 2, "kein Fehlerfenster / no error window");
    e.answer(&[(1, "")]);
    assert_eq!(e.context("encrypt", &file), 2);
}

#[test]
fn recipient_roundtrip_with_kdialog() {
    let e = Env::new("kdialog");
    let key_pass = format!("{}\n", pass());
    let gen_args = ["generate", "--name", "Anna", "--out", "anna.key.json"];
    let generate = [&gen_args[..], &["--passphrase-stdin"]].concat();
    assert_eq!(common::pqkeep(&generate, &key_pass, e.work()).0, 0);
    let export = ["export", "anna.key.json", "-o", "anna.pub.json"];
    assert_eq!(common::pqkeep(&export, "", e.work()).0, 0);
    let file = e.work().join("plan.txt");
    fs::write(&file, b"Plan").unwrap();
    let public = e.work().join("anna.pub.json");
    e.answer(&[
        (0, "1\n"),
        (0, &format!("{}\n", public.display())),
        (0, ""),
        (0, ""),
    ]);
    assert_eq!(e.context("encrypt", &file), 0);
    let calls = e.calls();
    assert!(calls[0].contains(&"--menu".to_owned()), "{calls:?}");
    assert!(calls[2].contains(&"--yesno".to_owned()));
    fs::remove_file(&file).unwrap();
    let key = e.work().join("anna.key.json");
    e.answer(&[
        (0, &format!("{}\n", key.display())),
        (0, &key_pass),
        (0, ""),
    ]);
    assert_eq!(e.context("decrypt", &e.work().join("plan.txt.pqkf")), 0);
    assert_eq!(fs::read(&file).unwrap(), b"Plan");
    assert!(e.calls()[1].contains(&"--password".to_owned()));
}

#[test]
fn kdialog_new_password_is_one_line() {
    let e = Env::new("kdialog");
    let file = e.work().join("d.txt");
    fs::write(&file, b"x").unwrap();
    let p = pass();
    e.answer(&[(0, "0\n"), (0, &format!("{p}\n")), (0, "")]);
    assert_eq!(e.context("encrypt", &file), 0);
    assert!(e.calls()[1].contains(&"--newpassword".to_owned()));
}

#[test]
fn malicious_file_name_is_one_argument() {
    let e = Env::new("zenity");
    // DE: Erlaubt sind alle Zeichen außer Steuerzeichen und \ : < > " | ? * (Archiv-Regeln).
    // EN: All characters are allowed except control characters and \ : < > " | ? * (archive rules).
    let file = e.work().join("--no-sandbox a'b; $(id) `id` & ä.txt");
    fs::write(&file, b"x").unwrap();
    let p = pass();
    e.answer(&[(0, "0\n"), (0, &format!("{p}\n{p}\n")), (0, "")]);
    assert_eq!(e.context("encrypt", &file), 0, "{:?}", e.calls());
    let mut enc = file.into_os_string();
    enc.push(".pqkf");
    assert!(Path::new(&enc).is_file());
}

#[test]
fn control_characters_in_names_are_rejected_cleanly() {
    // DE: Die Pfadregeln des Archivs lehnen Steuerzeichen ab; Meldung im Fenster, keine Ausgabe.
    // EN: The archive's path rules reject control characters; message in a window, no output.
    let e = Env::new("zenity");
    let file = e.work().join("zeile\nbruch.txt");
    fs::write(&file, b"x").unwrap();
    let p = pass();
    e.answer(&[(0, "0\n"), (0, &format!("{p}\n{p}\n")), (0, ""), (1, "")]);
    assert_ne!(e.context("encrypt", &file), 0);
    let calls = e.calls();
    assert!(calls[2].contains(&"--error".to_owned()), "{calls:?}");
    assert!(joined(&calls).contains("'path'"));
    assert_eq!(
        fs::read_dir(e.work()).unwrap().count(),
        3,
        "keine Ausgabe / no output"
    );
}

#[test]
fn without_display_or_tool_it_fails_cleanly() {
    let e = Env::new("zenity");
    let file = e.work().join("e.txt");
    fs::write(&file, b"x").unwrap();
    let out = Command::new(BIN)
        .args(["--lang", "en", "context", "--dialog", "encrypt", "--"])
        .arg(&file)
        .env("PATH", &e.fake)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("No window tool"));
}

#[test]
fn skipped_entries_are_shown_as_warning_not_plain_success() {
    let e = Env::new("zenity");
    let dir = e.work().join("ordner");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("a.txt"), b"a").unwrap();
    std::os::unix::fs::symlink("/etc/hostname", dir.join("link")).unwrap();
    let p = pass();
    e.answer(&[(0, "0\n"), (0, &format!("{p}\n{p}\n")), (0, "")]);
    assert_eq!(e.context("encrypt", &dir), 0);
    assert!(e.work().join("ordner.pqkf").is_file());
    let calls = e.calls();
    let last = calls.last().unwrap();
    assert!(last.contains(&"--warning".to_owned()), "{calls:?}");
    let text = last.join("\n");
    assert!(
        text.contains("not everything was included") && text.contains("link"),
        "{text}"
    );
}
