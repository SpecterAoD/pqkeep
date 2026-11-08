//! DE: Windows „Senden an → PQKeep“ (U4-4): Der Explorer übergibt darüber **alle** markierten
//! Dateien in einem Aufruf (klassische Kontextmenü-Einträge starten je Datei einen eigenen Prozess).
//! Die Verknüpfung `%APPDATA%\Microsoft\Windows\SendTo\PQKeep.lnk` wird über PowerShell
//! (`WScript.Shell`) angelegt und zeigt auf `pqkeepw.exe auto --` (Fenster) bzw.
//! `pqkeep.exe context auto --` (Konsole). Wie die Registry-Einträge mit Prüfsumme im Manifest:
//! nur eigene, unveränderte Verknüpfungen werden ersetzt oder entfernt.
//! EN: Windows "Send to → PQKeep" (U4-4): Explorer passes **all** selected files in one call this
//! way (classic context menu entries start one process per file). The shortcut
//! `%APPDATA%\Microsoft\Windows\SendTo\PQKeep.lnk` is created via PowerShell (`WScript.Shell`) and
//! points to `pqkeepw.exe auto --` (windows) or `pqkeep.exe context auto --` (console). As with the
//! registry entries, a checksum in the manifest ensures only own unchanged shortcuts are replaced
//! or removed.

use std::fs;
use std::path::{Path, PathBuf};

use super::manifest::{FileState, Manifest, digest};
use crate::cli::dialog::{quote, run_powershell};
use crate::cli::integrate_text::IntegrateTexts;

/// DE: Pfad der Verknüpfung. EN: Path of the shortcut.
pub(super) fn path() -> Option<PathBuf> {
    let appdata = PathBuf::from(std::env::var_os("APPDATA")?);
    appdata
        .is_absolute()
        .then(|| appdata.join(r"Microsoft\Windows\SendTo\PQKeep.lnk"))
}

/// DE: Ist `entry` die Verknüpfung (und kein Registry-Eintrag)? EN: Is `entry` the shortcut?
pub(super) fn is_shortcut(entry: &Path) -> bool {
    entry
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
}

fn state(manifest: &Manifest, lnk: &Path) -> FileState {
    match fs::read(lnk) {
        Err(_) => FileState::Missing,
        Ok(data) if manifest.recorded(lnk) == Some(digest(&data).as_str()) => FileState::Ours,
        Ok(_) => FileState::Foreign,
    }
}

fn script(lnk: &Path, target: &str, args: &str, icon: &str) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\ntry {{\n\
         $s = (New-Object -ComObject WScript.Shell).CreateShortcut({})\n\
         $s.TargetPath = {}; $s.Arguments = {}; $s.IconLocation = {}\n\
         $s.Description = 'PQKeep'; $s.Save(); exit 0\n}} catch {{ exit 3 }}\n",
        quote(&lnk.to_string_lossy()),
        quote(target),
        quote(args),
        quote(&format!("{icon},0"))
    )
}

/// DE: Verknüpfung anlegen bzw. eigene ersetzen. EN: Create the shortcut or replace our own.
pub(super) fn install(
    s: &IntegrateTexts,
    m: &mut Manifest,
    bin: &str,
    launcher: Option<&str>,
    dry: bool,
) {
    let Some(lnk) = path() else {
        return;
    };
    let shown = lnk.display();
    let st = state(m, &lnk);
    if st == FileState::Foreign {
        eprintln!("{}: {shown}", s.msg_foreign);
        return;
    }
    if dry {
        println!("{}: {shown}", s.msg_written);
        return;
    }
    if st == FileState::Ours {
        let _ = fs::remove_file(&lnk);
    }
    let (target, args) = launcher.map_or((bin, "context auto --"), |w| (w, "auto --"));
    let created = lnk.parent().is_some_and(|d| fs::create_dir_all(d).is_ok())
        && run_powershell(&script(&lnk, target, args, bin));
    match fs::read(&lnk) {
        Ok(data) if created => {
            m.record(&lnk, digest(&data));
            println!("{}: {shown}", s.msg_written);
        }
        _ => eprintln!("{}", s.msg_sendto_failed),
    }
}

/// DE: Eigene, unveränderte Verknüpfung entfernen. EN: Remove our own unchanged shortcut.
pub(super) fn uninstall(s: &IntegrateTexts, m: &Manifest, dry: bool) {
    for e in m.files.iter().filter(|e| is_shortcut(&e.path)) {
        match state(m, &e.path) {
            FileState::Ours => {
                if !dry {
                    let _ = fs::remove_file(&e.path);
                }
                println!("{}: {}", s.msg_removed, e.path.display());
            }
            FileState::Foreign => eprintln!("{}: {}", s.msg_foreign, e.path.display()),
            FileState::Missing => {}
        }
    }
}

/// DE: Zustand für `status`. EN: State for `status`.
pub(super) fn status(s: &IntegrateTexts, m: &Manifest) {
    for e in m.files.iter().filter(|e| is_shortcut(&e.path)) {
        let label = match state(m, &e.path) {
            FileState::Ours => s.msg_written,
            FileState::Foreign => s.msg_foreign,
            FileState::Missing => "-",
        };
        println!("{label}: {}", e.path.display());
    }
}
