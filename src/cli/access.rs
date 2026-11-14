//! DE: Welche Pfade ein CLI-Befehl in der Sandbox braucht. Gelesen wird nur, was als
//! Quelle/Schlüssel genannt ist; geschrieben nur im Ordner des Ziels (dort entstehen
//! auch die Temporärdateien). Fehlende Pfade werden vorab mit „nicht gefunden“
//! gemeldet, damit die Sandbox keine irreführende „Zugriff verweigert“-Meldung erzeugt.
//!
//! EN: Which paths a CLI command needs in the sandbox. Only what is named as
//! source/key is read; writing happens only in the target's directory (where the
//! temporary files are created as well). Missing paths are reported as "not found"
//! up front so the sandbox does not cause a misleading "permission denied".

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use clap::ArgMatches;
use pqkeep::Error;
use pqkeep::hardening::sandbox::CliAccess;
use pqkeep::security::Lang;

use super::files_cmd::{default_decrypted, default_encrypted};
use super::io::{CliResult, Failure};

/// DE: Ordner, in dem `path` entsteht (`.` für einen bloßen Dateinamen).
/// EN: Directory in which `path` is created (`.` for a bare file name).
fn parent(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf()
}

fn existing(path: PathBuf, lang: Lang) -> CliResult<PathBuf> {
    if path.exists() {
        Ok(path)
    } else {
        Err(Failure::from_error(&Error::Io(ErrorKind::NotFound), lang))
    }
}

fn path_arg(m: &ArgMatches, id: &str) -> Option<PathBuf> {
    m.get_one::<PathBuf>(id).cloned()
}

/// DE: Ver-/Entschlüsseln: alle Quellen und der Schlüssel lesbar; Ziel `--out` oder je Quelle
/// daneben. EN: Encrypt/decrypt: all sources and the key readable; target `--out` or next to each.
fn file_access(
    name: &str,
    m: &ArgMatches,
    lang: Lang,
    access: &mut CliAccess,
) -> CliResult<Option<PathBuf>> {
    let sources = super::files_cmd::sources(m);
    // DE: Beim Verschlüsseln jede `--to`-Datei einzeln, sonst nur `--key`.
    // EN: When encrypting each `--to` file on its own, otherwise only `--key`.
    let keys = if name == "encrypt" {
        super::recipients::paths(m)
    } else {
        path_arg(m, "key").into_iter().collect()
    };
    for p in sources.iter().cloned().chain(keys) {
        access.read.push(existing(p, lang)?);
    }
    if let Some(out) = path_arg(m, "out") {
        return Ok(Some(out));
    }
    // DE: Ziele entstehen jeweils neben der Quelle. EN: Targets are created next to each source.
    for source in &sources {
        let target = if name == "encrypt" {
            default_encrypted(source)
        } else {
            default_decrypted(source)
        };
        if let Some(t) = target {
            access.write_dirs.push(existing(parent(&t), lang)?);
        }
    }
    Ok(None)
}

/// DE: Freigaben für einen Befehl; `None` = Befehl richtet die Sandbox selbst ein
/// (`serve` ohne `--init-token`).
/// EN: Permissions for a command; `None` = the command sets up the sandbox itself
/// (`serve` without `--init-token`).
pub fn for_command(name: &str, m: &ArgMatches, lang: Lang) -> CliResult<Option<CliAccess>> {
    // DE: Bedienfehler vor „nicht gefunden“ melden. EN: Report usage errors before "not found".
    if name == "encrypt" {
        super::recipients::check_factor(m, lang)?;
    }
    let mut access = CliAccess::default();
    // DE: Passphrase-Datei (global) immer lesbar. EN: Passphrase file (global) always readable.
    if let Some(p) = super::unattended::pass_file() {
        access.read.push(existing(p.to_path_buf(), lang)?);
    }
    // DE: Faktordatei: nur diese eine Datei, nur lesen. EN: Factor file: this one file, read only.
    if let Some(p) = super::factor_cmd::path(m) {
        access.read.push(existing(p, lang)?);
    }
    let mut read = |p: Option<PathBuf>| -> CliResult {
        if let Some(p) = p {
            access.read.push(existing(p, lang)?);
        }
        Ok(())
    };
    let target = match name {
        "generate" | "factor" => path_arg(m, "out"),
        "inspect" => {
            read(path_arg(m, "file"))?;
            None
        }
        "export" => {
            read(path_arg(m, "file"))?;
            path_arg(m, "out")
        }
        "encrypt" | "decrypt" => file_access(name, m, lang, &mut access)?,
        "sign" => {
            read(path_arg(m, "file"))?;
            read(path_arg(m, "key"))?;
            super::sign_cmd::sig_path(m, "out")
        }
        "verify" => {
            read(path_arg(m, "file"))?;
            read(path_arg(m, "pub"))?;
            read(super::sign_cmd::sig_path(m, "sig"))?;
            None
        }
        "serve" if m.get_flag("init-token") => path_arg(m, "token-file"),
        // DE: Diese Befehle richten ihre Sandbox selbst ein (`serve`, `integrate`: Ziele erst später
        //     bekannt) bzw. starten Kindprozesse mit voller Sandbox (`context`, keine Geheimnisse).
        // EN: These commands set up their own sandbox (`serve`, `integrate`: targets known later) or
        //     start child processes with the full sandbox (`context`, no secrets).
        "serve" | "integrate" | "context" => return Ok(None),
        _ => None,
    };
    if let Some(target) = target {
        access.write_dirs.push(existing(parent(&target), lang)?);
    }
    Ok(Some(access))
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
