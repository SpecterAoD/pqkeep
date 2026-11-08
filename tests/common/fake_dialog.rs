//! DE: Ersatz für zenity/kdialog in Tests (Linux): protokolliert Argumente, gibt vorbereitete
//! Antworten aus. `cancel_after(s)`: das Fortschrittsfenster „klickt“ nach `s` Sekunden Abbrechen.
//! EN: Stand-in for zenity/kdialog in tests (Linux): logs arguments, prints prepared answers.
//! `cancel_after(s)`: the progress window "clicks" cancel after `s` seconds.
#![cfg(target_os = "linux")]
#![allow(dead_code, clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_pqkeep");

/// DE: Ersatz für zenity/kdialog: Antwort Nr. n aus `$ANSWERS/n.code` und `n.out`.
/// EN: Stand-in for zenity/kdialog: answer no. n from `$ANSWERS/n.code` and `n.out`.
const FAKE: &str = r#"#!/bin/sh
d="$ANSWERS"
case " $* " in *" --progress "*)
  if [ -f "$d/cancel" ]; then sleep "$(cat "$d/cancel")"; exit 1; fi
  exec cat >> "$d/progress";;
esac
for a in "$@"; do printf '%s\037' "$a"; done >> "$d/record"
printf '\036' >> "$d/record"
n=$(cat "$d/next"); echo $((n+1)) > "$d/next"
[ -f "$d/$n.out" ] && cat "$d/$n.out"
exit "$(cat "$d/$n.code" 2>/dev/null || echo 1)"
"#;

pub struct Env {
    dir: tempfile::TempDir,
    pub answers: PathBuf,
    pub fake: PathBuf,
}

impl Env {
    pub fn new(tool: &str) -> Self {
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

    pub fn work(&self) -> &Path {
        self.dir.path()
    }

    /// DE: Antworten der Reihe nach: (Exit-Code, Ausgabe). EN: Answers in order: (exit code, output).
    pub fn answer(&self, list: &[(i32, &str)]) {
        let _ = fs::remove_file(self.answers.join("record"));
        fs::write(self.answers.join("next"), "0\n").unwrap();
        for (i, (code, out)) in list.iter().enumerate() {
            fs::write(self.answers.join(format!("{i}.code")), code.to_string()).unwrap();
            fs::write(self.answers.join(format!("{i}.out")), out).unwrap();
        }
    }

    /// DE: Protokoll: je Aufruf die Argumente. EN: Log: arguments per call.
    pub fn calls(&self) -> Vec<Vec<String>> {
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

    /// DE: Fortschrittsfenster bricht nach `secs` Sekunden ab. EN: Progress window cancels after `secs`.
    pub fn cancel_after(&self, secs: &str) {
        fs::write(self.answers.join("cancel"), secs).unwrap();
    }

    /// DE: Was das Fortschrittsfenster über stdin erhielt. EN: What the progress window got via stdin.
    pub fn progress(&self) -> String {
        fs::read_to_string(self.answers.join("progress")).unwrap_or_default()
    }

    pub fn context(&self, action: &str, path: &Path) -> i32 {
        self.context_many(action, &[path])
    }

    pub fn context_many(&self, action: &str, paths: &[&Path]) -> i32 {
        Command::new(BIN)
            .args(["--lang", "en", "context", "--dialog", action, "--"])
            .args(paths)
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
