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
use pqc_keyforge::Error;
use pqc_keyforge::hardening::sandbox::CliAccess;
use pqc_keyforge::security::Lang;

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

/// DE: Freigaben für einen Befehl; `None` = Befehl richtet die Sandbox selbst ein
/// (`serve` ohne `--init-token`).
/// EN: Permissions for a command; `None` = the command sets up the sandbox itself
/// (`serve` without `--init-token`).
pub fn for_command(name: &str, m: &ArgMatches, lang: Lang) -> CliResult<Option<CliAccess>> {
    let mut access = CliAccess::default();
    let mut read = |p: Option<PathBuf>| -> CliResult {
        if let Some(p) = p {
            access.read.push(existing(p, lang)?);
        }
        Ok(())
    };
    let target = match name {
        "generate" => path_arg(m, "out"),
        "inspect" => {
            read(path_arg(m, "file"))?;
            None
        }
        "export" => {
            read(path_arg(m, "file"))?;
            path_arg(m, "out")
        }
        "encrypt" | "decrypt" => {
            let source = path_arg(m, "source").unwrap_or_default();
            read(Some(source.clone()))?;
            read(path_arg(m, if name == "encrypt" { "to" } else { "key" }))?;
            path_arg(m, "out").or_else(|| {
                if name == "encrypt" {
                    default_encrypted(&source)
                } else {
                    default_decrypted(&source)
                }
            })
        }
        "serve" if m.get_flag("init-token") => path_arg(m, "token-file"),
        "serve" => return Ok(None),
        _ => None,
    };
    if let Some(target) = target {
        access.write_dirs.push(existing(parent(&target), lang)?);
    }
    Ok(Some(access))
}
