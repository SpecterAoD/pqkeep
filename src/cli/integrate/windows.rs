//! DE: Windows-Umsetzung von `integrate`: Einträge unter `HKCU\Software\Classes` schreiben, prüfen
//! oder entfernen – nur für den aktuellen Benutzer, ohne Administratorrechte. Wie unter Linux
//! werden nur eigene, unveränderte Einträge ersetzt oder entfernt (Prüfsumme im Manifest
//! `%APPDATA%\PQKeep\integration.json`). Keine Sandbox unter Windows (siehe `docs/SANDBOX.md`).
//! EN: Windows implementation of `integrate`: write, check or remove entries below
//! `HKCU\Software\Classes` – current user only, without administrator rights. As on Linux, only
//! own unchanged entries are replaced or removed (checksum in the manifest
//! `%APPDATA%\PQKeep\integration.json`). No sandbox on Windows (see `docs/SANDBOX.md`).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use pqkeep::Error;
use pqkeep::security::Lang;
use windows_registry::{CURRENT_USER, Key, Type};

use super::Options;
use super::manifest::{FileState, Manifest, digest};
use super::winplan::{COMMAND_KEY, SZ, Snapshot, Verb, plan, safe_windows_path};
use crate::cli::integrate_text::{IntegrateTexts, integrate_texts};
use crate::cli::io::{CliResult, Failure, code};

/// DE: Klassen-Wurzel unter HKCU. EN: Classes root below HKCU.
const CLASSES: &str = r"Software\Classes";
/// DE: Win32-Fehler 2 (nicht gefunden) als HRESULT. EN: Win32 error 2 (not found) as HRESULT.
const NOT_FOUND: u32 = 0x8007_0002;

type RegResult<T> = windows_registry::Result<T>;

/// DE: Test-Wurzel `Software\PQKeepTest…`, nur in Debug-Builds per Umgebungsvariable.
/// EN: Test root `Software\PQKeepTest…`, only in debug builds via environment variable.
#[cfg(debug_assertions)]
fn test_root() -> Option<String> {
    std::env::var("PQKEEP_TEST_REG_ROOT")
        .ok()
        .filter(|r| r.starts_with(r"Software\PQKeepTest"))
}

#[cfg(not(debug_assertions))]
fn test_root() -> Option<String> {
    None
}

/// DE: Klassen-Wurzel (oder Test-Wurzel). EN: Classes root (or test root).
fn root() -> String {
    test_root().unwrap_or_else(|| CLASSES.to_owned())
}

/// DE: Registry-Fehler ohne Details (keine Pfade in Meldungen). EN: Registry error without details.
fn reg_fail<T>(lang: Lang, r: RegResult<T>) -> CliResult<T> {
    r.map_err(|_| Failure::from_error(&Error::Io(ErrorKind::Other), lang))
}

fn io_fail(lang: Lang) -> impl Fn(std::io::Error) -> Failure {
    move |e| Failure::from_error(&Error::from(e), lang)
}

/// DE: Öffnet lesend; `None`, wenn der Schlüssel fehlt. EN: Opens for reading; `None` if missing.
fn open(path: &str) -> RegResult<Option<Key>> {
    match CURRENT_USER.open(path) {
        Ok(k) => Ok(Some(k)),
        Err(e) if e.code().0.cast_unsigned() == NOT_FOUND => Ok(None),
        Err(e) => Err(e),
    }
}

/// DE: Alle Werte; Nicht-Text-Werte nur mit Typ (weichen ohnehin vom Plan ab).
/// EN: All values; non-text values only with their type (they differ from the plan anyway).
fn values(key: &Key) -> RegResult<Vec<(String, String, String)>> {
    let mut out = Vec::new();
    for (name, value) in key.values()? {
        let entry = match value.ty() {
            Type::String => (name, SZ.to_owned(), String::try_from(value)?),
            other => (name, format!("{other:?}"), String::new()),
        };
        out.push(entry);
    }
    Ok(out)
}

/// DE: Liest den Zustand eines Eintrags (Verb + `command`). EN: Reads the state of an entry.
fn snapshot(full: &str) -> RegResult<Option<Snapshot>> {
    let Some(key) = open(full)? else {
        return Ok(None);
    };
    let mut snap = Snapshot {
        values: values(&key)?,
        subkeys: key.keys()?.collect(),
        ..Snapshot::default()
    };
    let has_command = snap
        .subkeys
        .iter()
        .any(|k| k.eq_ignore_ascii_case(COMMAND_KEY));
    let cmd = if has_command {
        open(&format!(r"{full}\{COMMAND_KEY}"))?
    } else {
        None
    };
    if let Some(cmd) = cmd {
        snap.command_values = values(&cmd)?;
        snap.command_subkeys = cmd.keys()?.collect();
    }
    Ok(Some(snap))
}

fn state(manifest: &Manifest, full: &str) -> RegResult<(FileState, Option<String>)> {
    let current = snapshot(full)?.map(|s| digest(s.canonical().as_bytes()));
    let st = match &current {
        None => FileState::Missing,
        Some(d) if manifest.recorded(Path::new(full)) == Some(d.as_str()) => FileState::Ours,
        Some(_) => FileState::Foreign,
    };
    Ok((st, current))
}

fn write(full: &str, verb: &Verb) -> RegResult<()> {
    let key = CURRENT_USER.create(full)?;
    for (name, data) in &verb.values {
        key.set_string(name, data)?;
    }
    key.create(COMMAND_KEY)?.set_string("", &verb.command)
}

/// DE: Entfernt leere Elternschlüssel bis unterhalb der Wurzel. EN: Removes empty parents below the root.
fn prune_empty(root: &str, full: &str) {
    let mut path = full;
    while let Some((parent, _)) = path.rsplit_once('\\') {
        if parent.len() <= root.len() {
            break;
        }
        let empty = matches!(open(parent), Ok(Some(k))
            if k.keys().is_ok_and(|mut i| i.next().is_none())
                && k.values().is_ok_and(|mut i| i.next().is_none()));
        if !empty || CURRENT_USER.remove_tree(parent).is_err() {
            break;
        }
        path = parent;
    }
}

fn manifest_path(s: &IntegrateTexts) -> CliResult<PathBuf> {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .map(|p| p.join(r"PQKeep\integration.json"))
        .ok_or_else(|| Failure::new(code::ERROR, s.msg_unsupported))
}

/// DE: Geprüfter Programmpfad. EN: Checked program path.
fn binary(s: &IntegrateTexts) -> CliResult<String> {
    let temps: Vec<String> = ["TEMP", "TMP"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .collect();
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .filter(|p| safe_windows_path(p, &temps))
        .ok_or_else(|| Failure::new(code::ERROR, s.msg_unsafe_binary_win))
}

/// DE: Einstieg für Windows. EN: Entry point on Windows.
pub fn run(action: &str, opts: &Options, lang: Lang) -> CliResult {
    let s = integrate_texts(lang);
    let mpath = manifest_path(s)?;
    let root = root();
    match action {
        "install" => install(s, &root, &mpath, opts, lang),
        "uninstall" => uninstall(s, &root, &mpath, opts, lang),
        _ => status(s, &mpath, lang),
    }
}

fn save_manifest(path: &Path, manifest: &Manifest, lang: Lang) -> CliResult {
    let json = serde_json::to_string_pretty(manifest).map_err(|_| Failure::new(code::ERROR, ""))?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(io_fail(lang))?;
    }
    let temp = path.with_extension("json.pqkeep-tmp");
    fs::write(&temp, json + "\n").map_err(io_fail(lang))?;
    fs::rename(&temp, path).map_err(io_fail(lang))
}

fn install(s: &IntegrateTexts, root: &str, mpath: &Path, opts: &Options, lang: Lang) -> CliResult {
    let bin = binary(s)?;
    let mut manifest = Manifest::load(mpath).map_err(io_fail(lang))?;
    manifest.version = 1;
    manifest.binary.clone_from(&bin);
    for verb in plan(s, &bin) {
        let full = format!(r"{root}\{}", verb.path);
        let wanted = digest(verb.snapshot().canonical().as_bytes());
        let (st, current) = reg_fail(lang, state(&manifest, &full))?;
        let shown = format!(r"HKCU\{full}");
        if current.as_deref() == Some(wanted.as_str()) {
            manifest.record(Path::new(&full), wanted);
            println!("{}: {shown}", s.msg_unchanged);
        } else if st == FileState::Foreign {
            eprintln!("{}: {shown}", s.msg_foreign);
        } else {
            if !opts.dry_run {
                // DE: Eigenen alten Stand vollständig ersetzen. EN: Fully replace our own old state.
                if st == FileState::Ours {
                    reg_fail(lang, CURRENT_USER.remove_tree(&full))?;
                }
                reg_fail(lang, write(&full, &verb))?;
            }
            manifest.record(Path::new(&full), wanted);
            println!("{}: {shown}", s.msg_written);
        }
    }
    if opts.dry_run {
        println!("{}", s.msg_dry);
        return Ok(());
    }
    save_manifest(mpath, &manifest, lang)?;
    println!("{}", s.msg_restart_win);
    Ok(())
}

fn uninstall(
    s: &IntegrateTexts,
    root: &str,
    mpath: &Path,
    opts: &Options,
    lang: Lang,
) -> CliResult {
    let manifest = Manifest::load(mpath).map_err(io_fail(lang))?;
    for e in &manifest.files {
        let full = e.path.to_string_lossy();
        if !full.starts_with(&format!("{root}\\")) {
            continue;
        }
        match reg_fail(lang, state(&manifest, &full))?.0 {
            FileState::Ours => {
                if !opts.dry_run {
                    reg_fail(lang, CURRENT_USER.remove_tree(&*full))?;
                    prune_empty(root, &full);
                }
                println!(r"{}: HKCU\{full}", s.msg_removed);
            }
            FileState::Foreign => eprintln!(r"{}: HKCU\{full}", s.msg_foreign),
            FileState::Missing => {}
        }
    }
    if opts.dry_run {
        println!("{}", s.msg_dry);
    } else if mpath.exists() {
        fs::remove_file(mpath).map_err(io_fail(lang))?;
    }
    Ok(())
}

fn status(s: &IntegrateTexts, mpath: &Path, lang: Lang) -> CliResult {
    let manifest = Manifest::load(mpath).map_err(io_fail(lang))?;
    for e in &manifest.files {
        let full = e.path.to_string_lossy();
        let label = match reg_fail(lang, state(&manifest, &full))?.0 {
            FileState::Ours => s.msg_written,
            FileState::Foreign => s.msg_foreign,
            FileState::Missing => "-",
        };
        println!(r"{label}: HKCU\{full}");
    }
    let current = binary(s).ok();
    if !manifest.files.is_empty() && current.as_deref() != Some(manifest.binary.as_str()) {
        eprintln!("{}: {}", s.msg_binary_moved, manifest.binary);
    }
    Ok(())
}
