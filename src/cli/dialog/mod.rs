//! DE: Schlanke Fenster für das Kontextmenü (SPEC Abschnitt 9, U4 – bewusste Abweichung vom
//! GUI-Non-Goal: nur Eingabe-/Meldungsfenster, keine Anwendungsoberfläche). Genutzt werden
//! vorhandene Systemwerkzeuge: zenity, sonst kdialog. Eine Passphrase gelangt nie in diesen
//! Prozess: Das Passwortfenster schreibt per OS-Pipe direkt in stdin des Kindprozesses.
//! EN: Lean windows for the context menu (SPEC section 9, U4 – deliberate deviation from the
//! GUI non-goal: only input/message windows, no application UI). Existing system tools are used:
//! zenity, otherwise kdialog. A passphrase never enters this process: the password window writes
//! through an OS pipe straight into the child process's stdin.

mod args;
mod powershell;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub use args::{Kind, Request};

/// DE: Gefundenes Fenster-Werkzeug. EN: Found window tool.
pub struct Dialog {
    kind: Kind,
    path: PathBuf,
    title: String,
    cancel: String,
}

/// DE: Windows: Unterprozess ohne eigenes Konsolenfenster (`CREATE_NO_WINDOW`); sonst nichts.
/// EN: Windows: subprocess without its own console window (`CREATE_NO_WINDOW`); otherwise nothing.
pub fn no_console_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        /// DE/EN: `CREATE_NO_WINDOW` (Win32).
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = cmd;
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

/// DE: Gibt es eine grafische Sitzung? EN: Is there a graphical session?
#[cfg(not(windows))]
fn has_display() -> bool {
    ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()))
}

#[cfg(windows)]
fn has_display() -> bool {
    true
}

/// DE: Erstes verfügbares Werkzeug (zenity vor kdialog) ohne Prüfung der Sitzung.
/// EN: First available tool (zenity before kdialog) without checking the session.
#[cfg(unix)]
pub fn available() -> Option<(Kind, PathBuf)> {
    [("zenity", Kind::Zenity), ("kdialog", Kind::Kdialog)]
        .into_iter()
        .find_map(|(name, kind)| find(name).map(|p| (kind, p)))
}

#[cfg(not(any(unix, windows)))]
pub fn available() -> Option<(Kind, PathBuf)> {
    None
}

/// DE: Windows: PowerShell aus dem Systemordner (nicht über `PATH`), nur wenn die Probe gelingt
/// (volle Sprache, Windows Forms) – sonst z. B. bei Constrained Language Mode keine Fenster.
/// EN: Windows: PowerShell from the system folder (not via `PATH`), only if the probe succeeds
/// (full language, Windows Forms) – otherwise, e.g. in Constrained Language Mode, no windows.
#[cfg(windows)]
pub fn available() -> Option<(Kind, PathBuf)> {
    let path = powershell_path()?;
    run_powershell(&powershell::probe()).then_some((Kind::PowerShell, path))
}

#[cfg(windows)]
pub use powershell::quote;

/// DE: PowerShell aus dem Systemordner. EN: PowerShell from the system folder.
#[cfg(windows)]
fn powershell_path() -> Option<PathBuf> {
    let root = PathBuf::from(std::env::var_os("SystemRoot")?);
    Some(root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe"))
}

/// DE: Führt ein festes Skript ohne Konsolenfenster aus; `true` bei Exit 0.
/// EN: Runs a fixed script without a console window; `true` on exit 0.
#[cfg(windows)]
pub fn run_powershell(script: &str) -> bool {
    let Some(path) = powershell_path() else {
        return false;
    };
    let mut cmd = Command::new(path);
    no_console_window(&mut cmd);
    cmd.args(powershell::args(script))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

impl Dialog {
    /// DE: Werkzeug für die laufende grafische Sitzung. EN: Tool for the running graphical session.
    pub fn detect(title: &str, cancel: &str) -> Option<Self> {
        if !has_display() {
            return None;
        }
        available().map(|(kind, path)| Self {
            kind,
            path,
            title: title.to_owned(),
            cancel: cancel.to_owned(),
        })
    }

    /// DE: Befehl für eine Anfrage (stdin leer). EN: Command for a request (empty stdin).
    fn command(&self, req: &Request<'_>) -> Option<Command> {
        let list = if self.kind == Kind::PowerShell {
            powershell::args(&powershell::script(&self.title, &self.cancel, req))
        } else {
            args::args(self.kind, &self.title, req)?
        };
        let mut cmd = Command::new(&self.path);
        no_console_window(&mut cmd);
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

    /// DE: Warnfenster. EN: Warning window.
    pub fn warning(&self, text: &str) {
        let _ = self.ask(&Request::Warning { text });
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

    /// DE: Texteingabe mit Vorgabe; `None` bei Abbruch. EN: Text input with default; `None` on cancel.
    pub fn entry(&self, text: &str, default: &str) -> Option<String> {
        let (ok, line) = self.ask(&Request::Entry { text, default });
        ok.then_some(line)
    }

    /// DE: Fortschritt, solange der Rückgabewert lebt (zenity, PowerShell); `cancel` = mit
    /// Abbrechen-Knopf (siehe [`Progress::closed`]), `steps` = Balken für [`Progress::step`].
    /// EN: Progress while the return value lives (zenity, PowerShell); `cancel` = with a cancel
    /// button (see [`Progress::closed`]), `steps` = bar for [`Progress::step`].
    pub fn progress(&self, text: &str, cancel: bool, steps: bool) -> Progress {
        let req = Request::Progress {
            text,
            cancel,
            steps,
        };
        let child = self
            .command(&req)
            .and_then(|mut c| c.stdin(Stdio::piped()).stdout(Stdio::null()).spawn().ok());
        Progress {
            child,
            kind: self.kind,
        }
    }
}

/// DE: Laufendes Fortschrittsfenster; wird beim Drop geschlossen.
/// EN: Running progress window; closed on drop.
pub struct Progress {
    child: Option<Child>,
    kind: Kind,
}

impl Progress {
    /// DE: Hat der Benutzer das Fenster geschlossen bzw. abgebrochen? EN: Did the user close/cancel it?
    pub fn closed(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|c| c.try_wait().ok().flatten().is_some())
    }

    /// DE: Stand setzen (0–99 %, nie 100: zenity würde sich sonst schließen) und Text.
    /// EN: Set the state (0–99 %, never 100: zenity would close itself) and text.
    pub fn step(&mut self, percent: u8, text: &str) {
        use std::io::Write;
        let percent = percent.min(99);
        let line = match self.kind {
            Kind::Zenity => format!("# {text}\n{percent}\n"),
            Kind::PowerShell => format!("{percent}|{text}\n"),
            Kind::Kdialog => return,
        };
        if let Some(stdin) = self.child.as_mut().and_then(|c| c.stdin.as_mut()) {
            let _ = stdin.write_all(line.as_bytes());
            let _ = stdin.flush();
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
