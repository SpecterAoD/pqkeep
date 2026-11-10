//! DE: Thunar (Xfce): eigene Aktionen in `~/.config/Thunar/uca.xml` eintragen, entfernen und
//! anzeigen. Die Datei gehört dem Benutzer und enthält auch fremde Aktionen; geändert werden nur
//! die eigenen Blöcke (siehe `uca.rs`), vor jedem Schreiben entsteht eine Sicherung daneben.
//! Fehlt die Datei, dient die systemweite Vorgabe als Ausgangspunkt – wie bei Thunar selbst.
//! EN: Thunar (Xfce): add, remove and show own actions in `~/.config/Thunar/uca.xml`. The file
//! belongs to the user and also holds foreign actions; only the own blocks are changed (see
//! `uca.rs`), and a backup is created next to it before every write. If the file is missing, the
//! system-wide default is the starting point – just as Thunar does.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use pqkeep::security::Lang;

use super::discover::{find_in_path, terminal};
use super::entries::{self, Action, Launch};
use super::linux::{io_fail, write_atomic};
use super::manifest::{FileState, Manifest};
use super::uca;
use crate::cli::integrate_text::IntegrateTexts;
use crate::cli::io::CliResult;

const FILE: &str = "Thunar/uca.xml";

/// DE: Geplante Aktionen. EN: Planned actions.
pub(super) struct Plan {
    pub path: PathBuf,
    /// DE: Ausgangsinhalt, falls die Datei fehlt; `None` = Vorgabe des Systems nicht verwendbar.
    /// EN: Starting content if the file is missing; `None` = system default not usable.
    seed: Option<String>,
    /// DE/EN: (`unique-id`, Block) / (`unique-id`, block).
    blocks: Vec<(String, String)>,
}

/// DE: `$XDG_CONFIG_HOME/Thunar/uca.xml` (absolut) oder `~/.config/Thunar/uca.xml`.
/// EN: `$XDG_CONFIG_HOME/Thunar/uca.xml` (absolute) or `~/.config/Thunar/uca.xml`.
pub(super) fn uca_path() -> Option<PathBuf> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    xdg.filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|p| p.join(FILE))
}

/// DE: Vorgabe aus `$XDG_CONFIG_DIRS` (sonst `/etc/xdg`); ohne Vorgabe eine leere Datei.
/// EN: Default from `$XDG_CONFIG_DIRS` (else `/etc/xdg`); an empty file without a default.
fn system_seed() -> Option<String> {
    let dirs = std::env::var_os("XDG_CONFIG_DIRS").unwrap_or_else(|| "/etc/xdg".into());
    let found = std::env::split_paths(&dirs)
        .map(|d| d.join(FILE))
        .find(|p| p.is_file());
    match found {
        None => Some(uca::empty()),
        Some(path) => load(&path).ok().flatten().and_then(|d| uca::seed(&d)),
    }
}

/// DE: Plant die Thunar-Aktionen, wenn Thunar vorhanden ist (oder `all`).
/// EN: Plans the Thunar actions if Thunar is present (or `all`).
pub(super) fn plan(s: &IntegrateTexts, bin: &str, all: bool, dialog: bool) -> Option<Plan> {
    if !all && find_in_path("thunar").is_none() {
        return None;
    }
    let path = uca_path()?;
    let term = if dialog {
        None
    } else {
        terminal(Some("xfce4-terminal"))
    };
    let launch = match &term {
        Some(t) => Launch::Terminal(t),
        None if dialog => Launch::Dialog,
        None => {
            eprintln!("{} (thunar)", s.msg_no_terminal);
            return None;
        }
    };
    let actions = [
        (Action::Encrypt, s.name_encrypt, s.comment_encrypt),
        (Action::Decrypt, s.name_decrypt, s.comment_decrypt),
    ];
    let block = |(a, name, comment)| {
        (
            entries::thunar_id(a),
            entries::thunar(a, name, comment, bin, launch),
        )
    };
    Some(Plan {
        path,
        seed: system_seed(),
        blocks: actions.map(block).to_vec(),
    })
}

/// DE: Liest die Datei; `None`, wenn sie fehlt. Zu groß oder kein UTF-8: `InvalidData`.
/// EN: Reads the file; `None` if missing. Too large or not UTF-8: `InvalidData`.
fn load(path: &Path) -> std::io::Result<Option<String>> {
    match fs::metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
        Ok(m) if m.len() > uca::MAX_BYTES as u64 => return Err(ErrorKind::InvalidData.into()),
        Ok(_) => {}
    }
    let text = String::from_utf8(fs::read(path)?).map_err(|_| ErrorKind::InvalidData)?;
    Ok(Some(text))
}

/// DE: Wie `load`, aber nur Dateien im erwarteten Aufbau; sonst Meldung und `Err(())`.
/// EN: Like `load`, but only files in the expected layout; otherwise a message and `Err(())`.
fn load_valid(
    s: &IntegrateTexts,
    path: &Path,
    lang: Lang,
) -> CliResult<Result<Option<String>, ()>> {
    let doc = match load(path) {
        Err(e) if e.kind() == ErrorKind::InvalidData => None,
        Err(e) => return Err(io_fail(lang)(e)),
        Ok(None) => return Ok(Ok(None)),
        Ok(Some(doc)) => Some(doc).filter(|d| uca::valid(d)),
    };
    if doc.is_none() {
        eprintln!("{}: {}", s.msg_uca_unknown, path.display());
    }
    Ok(doc.map(Some).ok_or(()))
}

/// DE: UTC-Zeitstempel `JJJJ-MM-TT_HHMM` (Tage → Datum nach Howard Hinnant).
/// EN: UTC time stamp `YYYY-MM-DD_HHMM` (days → date after Howard Hinnant).
pub(super) fn stamp(secs: u64) -> String {
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let z = days + 719_468;
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (day, month) = (doy - (153 * mp + 2) / 5 + 1, (mp + 2) % 12 + 1);
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}_{:02}{:02}",
        rest / 3_600,
        rest % 3_600 / 60
    )
}

/// DE: Sichert die vorhandene Datei und schreibt die neue (Rechte bleiben, sonst 0644).
/// EN: Backs up the existing file and writes the new one (mode kept, otherwise 0644).
fn save(s: &IntegrateTexts, path: &Path, doc: &str, existed: bool) -> std::io::Result<()> {
    let mut mode = 0o644;
    if existed {
        mode = fs::metadata(path)?.permissions().mode() & 0o777;
        let now = SystemTime::now().duration_since(UNIX_EPOCH);
        let secs = now.map_or(0, |d| d.as_secs());
        let base = format!("uca.xml.pqkeep-bak_{}", stamp(secs));
        let backup = std::iter::once(base.clone())
            .chain((2..100).map(|n| format!("{base}-{n}")))
            .map(|name| path.with_file_name(name))
            .find(|p| !p.exists())
            .ok_or(ErrorKind::AlreadyExists)?;
        fs::copy(path, &backup)?;
        println!("{}: {}", s.msg_backup, backup.display());
    }
    write_atomic(path, doc, mode)
}

/// DE: Trägt die Aktionen ein; fremde oder geänderte gleichnamige Blöcke bleiben stehen.
/// EN: Adds the actions; foreign or modified blocks with the same id stay.
pub(super) fn install(
    s: &IntegrateTexts,
    plan: &Plan,
    manifest: &mut Manifest,
    dry: bool,
    lang: Lang,
) -> CliResult {
    let Ok(existing) = load_valid(s, &plan.path, lang)? else {
        return Ok(());
    };
    let existed = existing.is_some();
    let Some(original) = existing.or_else(|| plan.seed.clone()) else {
        eprintln!("{}: {}", s.msg_uca_unknown, plan.path.display());
        return Ok(());
    };
    let mut doc = original.clone();
    for (id, block) in &plan.blocks {
        let label = format!("{} [{id}]", plan.path.display());
        let wanted = uca::fingerprint(block);
        let recorded = manifest.recorded_entry(&plan.path, id);
        if uca::state(&doc, id, recorded, Some(&wanted)) == FileState::Foreign {
            eprintln!("{}: {label}", s.msg_foreign);
            continue;
        }
        let next = uca::upsert(&doc, id, block);
        let same = next == doc;
        println!(
            "{}: {label}",
            if same { s.msg_unchanged } else { s.msg_written }
        );
        doc = next;
        manifest.record_entry(&plan.path, id, wanted);
    }
    if doc != original && !dry {
        save(s, &plan.path, &doc, existed).map_err(io_fail(lang))?;
    }
    Ok(())
}

/// DE: Dateien mit eigenen Einträgen laut Liste. EN: Files with own entries according to the list.
pub(super) fn files(manifest: &Manifest) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = manifest.entries.iter().map(|e| e.path.clone()).collect();
    paths.sort();
    paths.dedup();
    paths
}

/// DE: Entfernt eigene, unveränderte Aktionen; die Datei selbst bleibt (Thunar legt sie ohnehin an).
/// EN: Removes own unchanged actions; the file itself stays (Thunar creates it anyway).
pub(super) fn uninstall(
    s: &IntegrateTexts,
    manifest: &Manifest,
    dry: bool,
    lang: Lang,
) -> CliResult {
    for path in files(manifest) {
        let Ok(Some(original)) = load_valid(s, &path, lang)? else {
            continue;
        };
        let mut doc = original.clone();
        for e in manifest.entries.iter().filter(|e| e.path == path) {
            let label = format!("{} [{}]", path.display(), e.id);
            match uca::state(&doc, &e.id, Some(&e.sha3), None) {
                FileState::Ours => {
                    doc = uca::remove(&doc, &e.id);
                    println!("{}: {label}", s.msg_removed);
                }
                FileState::Foreign => eprintln!("{}: {label}", s.msg_foreign),
                FileState::Missing => {}
            }
        }
        if doc != original && !dry {
            save(s, &path, &doc, true).map_err(io_fail(lang))?;
        }
    }
    Ok(())
}

/// DE: Zeigt den Zustand der eigenen Aktionen. EN: Shows the state of the own actions.
pub(super) fn status(s: &IntegrateTexts, manifest: &Manifest) {
    for e in &manifest.entries {
        let doc = load(&e.path).ok().flatten().unwrap_or_default();
        let label = match uca::state(&doc, &e.id, Some(&e.sha3), None) {
            FileState::Ours => s.msg_written,
            FileState::Foreign => s.msg_foreign,
            FileState::Missing => "-",
        };
        println!("{label}: {} [{}]", e.path.display(), e.id);
    }
}

#[cfg(test)]
#[path = "thunar_tests.rs"]
mod thunar_tests;
