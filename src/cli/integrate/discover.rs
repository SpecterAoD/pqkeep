//! DE: Erkennung und Planung für `integrate` (Linux): Datenordner, Dateimanager, Terminal,
//! Prüfung des Programmpfads, geplante Einträge.
//! EN: Discovery and planning for `integrate` (Linux): data folder, file managers, terminal,
//! program path check, planned entries.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::entries::{self, Action, Launch, Terminal};
use crate::cli::integrate_text::IntegrateTexts;
use crate::cli::io::{CliResult, Failure, code};

/// DE: Geplante Datei. EN: Planned file.
pub(super) struct Target {
    pub path: PathBuf,
    pub content: String,
    pub mode: u32,
}

/// DE: `$XDG_DATA_HOME` (absolut) oder `~/.local/share`. EN: `$XDG_DATA_HOME` (absolute) or `~/.local/share`.
pub(super) fn data_home() -> Option<PathBuf> {
    let xdg = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from);
    xdg.filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
}

pub(super) fn find_in_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(name))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

/// DE: Erstes vorhandenes Terminal; Dolphin bevorzugt konsole.
/// EN: First available terminal; Dolphin prefers konsole.
fn terminal(prefer_konsole: bool) -> Option<Terminal> {
    let mut list = vec![
        ("gnome-terminal", "--"),
        ("konsole", "-e"),
        ("xfce4-terminal", "-x"),
        ("mate-terminal", "-x"),
        ("x-terminal-emulator", "-e"),
        ("xterm", "-e"),
    ];
    if prefer_konsole {
        list.swap(0, 1);
    }
    list.into_iter().find_map(|(name, flag)| {
        let path = find_in_path(name)?.to_str()?.to_owned();
        entries::safe_path(&path).then_some(Terminal {
            path,
            exec_flag: flag,
        })
    })
}

/// DE: Absoluter Programmpfad; abgelehnt bei temporären Orten, für andere beschreibbar oder
/// Sonderzeichen. EN: Absolute program path; rejected for temporary places, world-writable or
/// special characters.
pub(super) fn binary(s: &IntegrateTexts) -> CliResult<String> {
    let bad = || Failure::new(code::ERROR, s.msg_unsafe_binary);
    let exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| bad())?;
    let text = exe
        .to_str()
        .filter(|t| entries::safe_path(t))
        .ok_or_else(bad)?;
    let temp = ["/tmp/", "/var/tmp/", "/dev/shm/"]
        .iter()
        .any(|p| text.starts_with(p));
    let modes: Vec<u32> = [Some(exe.as_path()), exe.parent()]
        .into_iter()
        .flatten()
        .map(|p| fs::metadata(p).map_or(0o777, |m| m.permissions().mode()))
        .collect();
    if temp || modes.iter().any(|m| m & 0o002 != 0) {
        return Err(bad());
    }
    if modes.iter().any(|m| m & 0o020 != 0) {
        eprintln!("{}", s.msg_group_writable);
    }
    Ok(text.to_owned())
}

/// DE: Plant alle Einträge für die gewählten Dateimanager; `dialog` = Fenster statt Terminal.
/// EN: Plans all entries for the chosen file managers; `dialog` = windows instead of a terminal.
pub(super) fn plan(
    s: &IntegrateTexts,
    data: &Path,
    bin: &str,
    all: bool,
    dialog: bool,
) -> Vec<Target> {
    let mut out = Vec::new();
    let actions = [
        (Action::Encrypt, s.name_encrypt, s.comment_encrypt),
        (Action::Decrypt, s.name_decrypt, s.comment_decrypt),
    ];
    let has = |name| all || find_in_path(name).is_some();
    if has("nemo") {
        for (a, name, comment) in actions {
            let path = data.join(format!("nemo/actions/pqkeep-{}.nemo_action", a.arg()));
            out.push(Target {
                path,
                content: entries::nemo(a, name, comment, bin, dialog),
                mode: 0o644,
            });
        }
    }
    for (fm, konsole) in [("nautilus", false), ("dolphin", true)] {
        if !has(fm) {
            continue;
        }
        let term = if dialog { None } else { terminal(konsole) };
        let launch = match &term {
            Some(t) => Launch::Terminal(t),
            None if dialog => Launch::Dialog,
            None => {
                eprintln!("{} ({fm})", s.msg_no_terminal);
                continue;
            }
        };
        for (a, name, _) in actions {
            let (path, content) = if fm == "nautilus" {
                (
                    data.join("nautilus/scripts").join(name),
                    entries::nautilus(a, bin, launch),
                )
            } else {
                let file = format!("kio/servicemenus/pqkeep-{}.desktop", a.arg());
                (data.join(file), entries::dolphin(a, name, bin, launch))
            };
            out.push(Target {
                path,
                content,
                mode: 0o755,
            });
        }
    }
    out
}
