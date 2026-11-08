//! DE: Schlanke Fenster für das Kontextmenü (SPEC Abschnitt 9, U4 – bewusste Abweichung vom
//! GUI-Non-Goal: nur Eingabe-/Meldungsfenster, keine Anwendungsoberfläche). Genutzt werden
//! vorhandene Systemwerkzeuge: zenity, sonst kdialog. Eine Passphrase gelangt nie in diesen
//! Prozess: Das Passwortfenster schreibt per OS-Pipe direkt in stdin des Kindprozesses.
//! EN: Lean windows for the context menu (SPEC section 9, U4 – deliberate deviation from the
//! GUI non-goal: only input/message windows, no application UI). Existing system tools are used:
//! zenity, otherwise kdialog. A passphrase never enters this process: the password window writes
//! through an OS pipe straight into the child process's stdin.

mod args;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub use args::{Kind, Request};

/// DE: Gefundenes Fenster-Werkzeug. EN: Found window tool.
pub struct Dialog {
    kind: Kind,
    path: PathBuf,
    title: String,
}

/// DE: Ausführbare Datei in einem absoluten `PATH`-Eintrag. EN: Executable in an absolute `PATH` entry.
#[cfg(unix)]
fn find(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(&std::env::var_os("PATH")?)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| {
            std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

#[cfg(not(unix))]
fn find(_name: &str) -> Option<PathBuf> {
    None
}

/// DE: Gibt es eine grafische Sitzung? EN: Is there a graphical session?
fn has_display() -> bool {
    ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()))
}

/// DE: Erstes verfügbares Werkzeug (zenity vor kdialog) ohne Prüfung der Sitzung.
/// EN: First available tool (zenity before kdialog) without checking the session.
pub fn available() -> Option<(Kind, PathBuf)> {
    [("zenity", Kind::Zenity), ("kdialog", Kind::Kdialog)]
        .into_iter()
        .find_map(|(name, kind)| find(name).map(|p| (kind, p)))
}

impl Dialog {
    /// DE: Werkzeug für die laufende grafische Sitzung. EN: Tool for the running graphical session.
    pub fn detect(title: &str) -> Option<Self> {
        if !has_display() {
            return None;
        }
        available().map(|(kind, path)| Self {
            kind,
            path,
            title: title.to_owned(),
        })
    }

    /// DE: Befehl für eine Anfrage (stdin leer). EN: Command for a request (empty stdin).
    fn command(&self, req: &Request<'_>) -> Option<Command> {
        let list = args::args(self.kind, &self.title, req)?;
        let mut cmd = Command::new(&self.path);
        cmd.args(list).stdin(Stdio::null()).stderr(Stdio::null());
        Some(cmd)
    }

    /// DE: Startet und liefert (Erfolg, erste Ausgabezeile). EN: Runs and returns (success, first line).
    fn ask(&self, req: &Request<'_>) -> (bool, String) {
        let Some(out) = self.command(req).and_then(|mut c| c.output().ok()) else {
            return (false, String::new());
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text.lines().next().unwrap_or_default().to_owned();
        (out.status.success(), line)
    }

    /// DE: Auswahl; `None` bei Abbruch. EN: Choice; `None` on cancel.
    pub fn choose(&self, text: &str, items: &[&str]) -> Option<usize> {
        let (ok, line) = self.ask(&Request::Choose { text, items });
        ok.then(|| line.trim().parse().ok())
            .flatten()
            .filter(|i| *i < items.len())
    }

    /// DE: Datei wählen; `None` bei Abbruch. EN: Pick a file; `None` on cancel.
    pub fn open_file(
        &self,
        prompt: &str,
        start: &Path,
        pattern: &str,
        label: &str,
    ) -> Option<PathBuf> {
        let start = start.to_string_lossy();
        let (ok, line) = self.ask(&Request::OpenFile {
            prompt,
            start: &start,
            pattern,
            label,
        });
        let path = PathBuf::from(line);
        (ok && path.is_absolute()).then_some(path)
    }

    /// DE: Ja/Nein. EN: Yes/no.
    pub fn question(&self, text: &str) -> bool {
        self.ask(&Request::Question { text }).0
    }

    /// DE: Hinweisfenster. EN: Information window.
    pub fn info(&self, text: &str) {
        let _ = self.ask(&Request::Info { text });
    }

    /// DE: Fehlerfenster. EN: Error window.
    pub fn error(&self, text: &str) {
        let _ = self.ask(&Request::Error { text });
    }

    /// DE: Startet das Passwortfenster mit Ausgabe in eine Pipe. `confirm` = neue Passphrase
    /// zweimal. Liefert den Prozess und ob der Empfänger zwei Zeilen vergleichen muss.
    /// EN: Starts the password window with output into a pipe. `confirm` = new passphrase twice.
    /// Returns the process and whether the receiver must compare two lines.
    pub fn password(&self, text: &str, confirm: Option<(&str, &str)>) -> Option<(Child, bool)> {
        let req = match confirm {
            Some((first, second)) => Request::NewPassword {
                text,
                first,
                second,
            },
            None => Request::Password { text },
        };
        let two_lines = confirm.is_some() && !self.kind.confirms_itself();
        let child = self.command(&req)?.stdout(Stdio::piped()).spawn().ok()?;
        Some((child, two_lines))
    }

    /// DE: Pulsierender Fortschritt, solange der Rückgabewert lebt (nur zenity).
    /// EN: Pulsating progress while the return value lives (zenity only).
    pub fn progress(&self, text: &str) -> Progress {
        let child = self
            .command(&Request::Progress { text })
            .and_then(|mut c| c.stdin(Stdio::piped()).stdout(Stdio::null()).spawn().ok());
        Progress(child)
    }
}

/// DE: Laufendes Fortschrittsfenster; wird beim Drop geschlossen.
/// EN: Running progress window; closed on drop.
pub struct Progress(Option<Child>);

impl Drop for Progress {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
