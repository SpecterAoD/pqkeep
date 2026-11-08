//! DE: Linux-Umsetzung: Programmpfad prüfen, Dateimanager und Terminal finden, Einträge planen,
//! schreiben oder entfernen. Schreiben atomar (Temporärdatei + Umbenennen), Rechte 0644 bzw. 0755.
//! EN: Linux implementation: check the program path, find file managers and terminals, plan,
//! write or remove entries. Atomic writes (temporary file + rename), mode 0644 or 0755.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use pqkeep::Error;
use pqkeep::hardening::sandbox::{CliAccess, Profile};
use pqkeep::security::Lang;

use super::Options;
use super::discover::{Target, binary, data_home, find_in_path, plan};
use super::manifest::{FileState, Manifest, digest, state};
use crate::cli::integrate_text::{IntegrateTexts, integrate_texts};
use crate::cli::io::{CliResult, Failure, code};
use crate::cli::sandbox;

fn io_fail(lang: Lang) -> impl Fn(std::io::Error) -> Failure {
    move |e| Failure::from_error(&Error::from(e), lang)
}

/// DE: Temporärdatei schreiben, Rechte am Handle setzen (`fchmod`, kein `chmod`), umbenennen.
/// EN: Write a temporary file, set the mode on the handle (`fchmod`, no `chmod`), rename.
fn write_atomic(path: &Path, content: &str, mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = path.with_file_name(format!(".{name}.pqkeep-tmp"));
    let _ = fs::remove_file(&temp);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    file.write_all(content.as_bytes())?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, path)
}

/// DE: Sandbox nur mit Schreibrecht in den (vorhandenen) Zielordnern.
/// EN: Sandbox with write access only to the (existing) target folders.
fn enter_sandbox(dirs: &[PathBuf], opts: &Options, lang: Lang) -> CliResult {
    let mut write_dirs: Vec<PathBuf> = dirs.iter().filter(|d| d.is_dir()).cloned().collect();
    write_dirs.sort();
    write_dirs.dedup();
    let access = CliAccess {
        read: Vec::new(),
        write_dirs,
    };
    sandbox::enable(&Profile::Cli(access), opts.sandboxed, opts.verbose, lang)
}

/// DE: Einstieg für Linux. EN: Entry point on Linux.
pub fn run(action: &str, opts: &Options, lang: Lang) -> CliResult {
    let s = integrate_texts(lang);
    let data = data_home().ok_or_else(|| Failure::new(code::ERROR, s.msg_unsupported))?;
    let manifest_path = data.join("pqkeep/integration.json");
    match action {
        "install" => install(s, &data, &manifest_path, opts, lang),
        "uninstall" => uninstall(s, &manifest_path, opts, lang),
        _ => status(s, &data, &manifest_path, opts, lang),
    }
}

fn install(s: &IntegrateTexts, data: &Path, mpath: &Path, opts: &Options, lang: Lang) -> CliResult {
    let bin = binary(s)?;
    let dialog = !opts.terminal && crate::cli::dialog::available().is_some();
    let targets = plan(s, data, &bin, opts.all, dialog);
    if targets.is_empty() {
        return Err(Failure::new(code::ERROR, s.msg_no_manager));
    }
    let mut dirs: Vec<PathBuf> = targets
        .iter()
        .filter_map(|t| t.path.parent().map(Path::to_path_buf))
        .collect();
    dirs.extend(mpath.parent().map(Path::to_path_buf));
    if !opts.dry_run {
        for d in &dirs {
            fs::create_dir_all(d).map_err(io_fail(lang))?;
        }
    }
    enter_sandbox(&dirs, opts, lang)?;
    let mut manifest = Manifest::load(mpath).map_err(io_fail(lang))?;
    manifest.version = 1;
    manifest.binary.clone_from(&bin);
    (if dialog { "dialog" } else { "terminal" }).clone_into(&mut manifest.mode);
    println!("{}: {}", s.lbl_mode, mode_label(s, &manifest.mode));
    for t in &targets {
        apply(s, t, &mut manifest, opts.dry_run, lang)?;
    }
    if opts.dry_run {
        println!("{}", s.msg_dry);
        return Ok(());
    }
    let json =
        serde_json::to_string_pretty(&manifest).map_err(|_| Failure::new(code::ERROR, ""))?;
    write_atomic(mpath, &(json + "\n"), 0o644).map_err(io_fail(lang))?;
    println!("{}", s.msg_restart);
    Ok(())
}

/// DE: Schreibt eine Datei, sofern sie fehlt oder eine unveränderte eigene ist.
/// EN: Writes a file if it is missing or an unchanged own one.
fn apply(
    s: &IntegrateTexts,
    t: &Target,
    manifest: &mut Manifest,
    dry: bool,
    lang: Lang,
) -> CliResult {
    let wanted = digest(t.content.as_bytes());
    let current = fs::read(&t.path).ok().map(|d| digest(&d));
    let st = state(manifest, &t.path).map_err(io_fail(lang))?;
    if current.as_deref() == Some(wanted.as_str()) {
        manifest.record(&t.path, wanted);
        println!("{}: {}", s.msg_unchanged, t.path.display());
    } else if st == FileState::Foreign {
        eprintln!("{}: {}", s.msg_foreign, t.path.display());
    } else {
        if !dry {
            write_atomic(&t.path, &t.content, t.mode).map_err(io_fail(lang))?;
        }
        manifest.record(&t.path, wanted);
        println!("{}: {}", s.msg_written, t.path.display());
    }
    Ok(())
}

fn uninstall(s: &IntegrateTexts, mpath: &Path, opts: &Options, lang: Lang) -> CliResult {
    let mut dirs: Vec<PathBuf> = Vec::new();
    dirs.extend(mpath.parent().map(Path::to_path_buf));
    let manifest = Manifest::load(mpath).map_err(io_fail(lang))?;
    dirs.extend(
        manifest
            .files
            .iter()
            .filter_map(|e| e.path.parent().map(Path::to_path_buf)),
    );
    enter_sandbox(&dirs, opts, lang)?;
    for e in &manifest.files {
        match state(&manifest, &e.path).map_err(io_fail(lang))? {
            FileState::Ours => {
                if !opts.dry_run {
                    fs::remove_file(&e.path).map_err(io_fail(lang))?;
                }
                println!("{}: {}", s.msg_removed, e.path.display());
            }
            FileState::Foreign => eprintln!("{}: {}", s.msg_foreign, e.path.display()),
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

fn mode_label<'a>(s: &'a IntegrateTexts, mode: &str) -> &'a str {
    match mode {
        "dialog" => s.mode_dialog,
        "terminal" => s.mode_terminal,
        _ => "-",
    }
}

fn status(s: &IntegrateTexts, data: &Path, mpath: &Path, opts: &Options, lang: Lang) -> CliResult {
    let found: Vec<&str> = ["nemo", "nautilus", "dolphin"]
        .into_iter()
        .filter(|n| find_in_path(n).is_some())
        .collect();
    let current = binary(s).ok();
    let dirs = vec![
        data.join("pqkeep"),
        data.join("nemo/actions"),
        data.join("nautilus/scripts"),
        data.join("kio/servicemenus"),
    ];
    enter_sandbox(&dirs, opts, lang)?;
    println!(
        "{}: {}",
        s.lbl_found,
        if found.is_empty() {
            "-".to_owned()
        } else {
            found.join(", ")
        }
    );
    let manifest = Manifest::load(mpath).map_err(io_fail(lang))?;
    if !manifest.files.is_empty() {
        println!("{}: {}", s.lbl_mode, mode_label(s, &manifest.mode));
    }
    for e in &manifest.files {
        let st = state(&manifest, &e.path).map_err(io_fail(lang))?;
        let label = match st {
            FileState::Ours => s.msg_written,
            FileState::Foreign => s.msg_foreign,
            FileState::Missing => "-",
        };
        println!("{label}: {}", e.path.display());
    }
    if !manifest.files.is_empty() && current.as_deref() != Some(manifest.binary.as_str()) {
        eprintln!("{}: {}", s.msg_binary_moved, manifest.binary);
    }
    Ok(())
}
