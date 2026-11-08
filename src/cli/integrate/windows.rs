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
use windows_registry::CURRENT_USER;

use super::Options;
use super::manifest::{FileState, Manifest, digest};
use super::registry::{RegResult, prune_empty, root, state, write};
use super::winplan::{Verb, plan, safe_windows_path};
use crate::cli::integrate_text::{IntegrateTexts, integrate_texts};
use crate::cli::io::{CliResult, Failure, code};

/// DE: Registry-Fehler ohne Details (keine Pfade in Meldungen). EN: Registry error without details.
fn reg_fail<T>(lang: Lang, r: RegResult<T>) -> CliResult<T> {
    r.map_err(|_| Failure::from_error(&Error::Io(ErrorKind::Other), lang))
}

fn io_fail(lang: Lang) -> impl Fn(std::io::Error) -> Failure {
    move |e| Failure::from_error(&Error::from(e), lang)
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

/// DE: `pqkeepw.exe` neben dem Programm (Fenster ohne Konsole), außer bei `--terminal`.
/// EN: `pqkeepw.exe` next to the program (windows without a console), unless `--terminal`.
fn launcher(bin: &str, opts: &Options) -> Option<String> {
    if opts.terminal {
        return None;
    }
    let w = Path::new(bin).with_file_name("pqkeepw.exe");
    let text = w.to_str()?.to_owned();
    (w.is_file() && safe_windows_path(&text, &[])).then_some(text)
}

fn mode_label<'a>(s: &'a IntegrateTexts, mode: &str) -> &'a str {
    if mode == "dialog" {
        s.mode_dialog_win
    } else {
        s.mode_terminal
    }
}

/// DE: Schreibt einen Eintrag, sofern er fehlt oder ein unveränderter eigener ist.
/// EN: Writes an entry if it is missing or an unchanged own one.
fn apply(
    s: &IntegrateTexts,
    full: &str,
    verb: &Verb,
    m: &mut Manifest,
    dry: bool,
    lang: Lang,
) -> CliResult {
    let wanted = digest(verb.snapshot().canonical().as_bytes());
    let (st, current) = reg_fail(lang, state(m, full))?;
    let shown = format!(r"HKCU\{full}");
    if current.as_deref() == Some(wanted.as_str()) {
        m.record(Path::new(full), wanted);
        println!("{}: {shown}", s.msg_unchanged);
    } else if st == FileState::Foreign {
        eprintln!("{}: {shown}", s.msg_foreign);
    } else {
        if !dry {
            // DE: Eigenen alten Stand vollständig ersetzen. EN: Fully replace our own old state.
            if st == FileState::Ours {
                reg_fail(lang, CURRENT_USER.remove_tree(full))?;
            }
            reg_fail(lang, write(full, verb))?;
        }
        m.record(Path::new(full), wanted);
        println!("{}: {shown}", s.msg_written);
    }
    Ok(())
}

fn install(s: &IntegrateTexts, root: &str, mpath: &Path, opts: &Options, lang: Lang) -> CliResult {
    let bin = binary(s)?;
    let launcher = launcher(&bin, opts);
    let mut manifest = Manifest::load(mpath).map_err(io_fail(lang))?;
    manifest.version = 1;
    manifest.binary.clone_from(&bin);
    (if launcher.is_some() {
        "dialog"
    } else {
        "terminal"
    })
    .clone_into(&mut manifest.mode);
    println!("{}: {}", s.lbl_mode, mode_label(s, &manifest.mode));
    for verb in plan(s, &bin, launcher.as_deref()) {
        let full = format!(r"{root}\{}", verb.path);
        apply(s, &full, &verb, &mut manifest, opts.dry_run, lang)?;
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
    if !manifest.files.is_empty() {
        println!("{}: {}", s.lbl_mode, mode_label(s, &manifest.mode));
    }
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
