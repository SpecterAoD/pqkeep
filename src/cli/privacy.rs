//! DE: Zufällige äußere Dateinamen (#315). `encrypt --random-name` bzw. `--privacy high` gibt der
//! `.pqkf` einen zufälligen Namen neben der Quelle; ein Ordner wird dabei mit seinem Namen als
//! oberstem Eintrag verschlüsselt, ein Container unter dem Namen aus `--out` (der Containername
//! steht dann nur im Archiv). `decrypt` stellt den Originalnamen aus dem Archiv her – mit
//! `--original-name` oder automatisch, wenn der Name die zufällige Form hat und kein `--out`
//! angegeben ist. Kein Formatwechsel.
//! EN: Random outer file names (#315). `encrypt --random-name` or `--privacy high` gives the
//! `.pqkf` a random name next to the source; a directory is then encrypted with its name as the
//! top-level entry, a container under the name from `--out` (the container name then only lives in
//! the archive). `decrypt` restores the original name from the archive – with `--original-name` or
//! automatically if the name has the random shape and no `--out` is given. No format change.

use std::path::{Path, PathBuf};

use clap::{Arg, ArgMatches};
use pqkeep::envelope::PublicKeyFile;
use pqkeep::files::{self, Report, Unlock};
use pqkeep::security::Lang;

use super::args::{flag, opt};
use super::files_cmd::{OwnedProtection, free_target};
use super::io::{CliResult, Failure, code, localize};

/// DE: Name des Schalters beim Entschlüsseln. EN: Name of the decrypt switch.
pub const ORIGINAL_NAME: &str = "original-name";

/// DE: Argumente für `encrypt`. EN: Arguments for `encrypt`.
pub fn encrypt_args(lang: Lang) -> [Arg; 2] {
    let (random, level) = match lang {
        Lang::De => (
            "Zufälliger äußerer Name (26 Zeichen + .pqkf) neben der Quelle; der Originalname bleibt verschlüsselt im Archiv. Bei mehreren Quellen als Container gibt --out den Namen im Archiv vor",
            "Privatsphäre-Stufe: standard (Vorgabe) oder high (setzt --random-name; künftige Privatsphäre-Optionen kommen hinzu)",
        ),
        Lang::En => (
            "Random outer name (26 characters + .pqkf) next to the source; the original name stays encrypted in the archive. With several sources as a container --out sets the name inside the archive",
            "Privacy level: standard (default) or high (sets --random-name; future privacy options will be added)",
        ),
    };
    [
        flag("random-name", random),
        opt("privacy", level).value_parser(["standard", "high"]),
    ]
}

/// DE: Argument für `decrypt`. EN: Argument for `decrypt`.
pub fn decrypt_arg(lang: Lang) -> Arg {
    let help = match lang {
        Lang::De => {
            "Unter dem Originalnamen aus dem Archiv neben der Quelle entschlüsseln (automatisch bei zufälligem Namen ohne --out)"
        }
        Lang::En => {
            "Decrypt under the original name from the archive next to the source (automatic for a random name without --out)"
        }
    };
    flag(ORIGINAL_NAME, help).conflicts_with("out")
}

/// DE: Frage im Menü. EN: Menu question.
pub fn menu_question(lang: Lang) -> &'static str {
    match lang {
        Lang::De => "Privatsphäre hoch (zufälliger Dateiname, Originalname nur verschlüsselt)?",
        Lang::En => "Privacy high (random file name, original name encrypted only)?",
    }
}

/// DE: Meldungen zu Feldnamen der Bibliothek. EN: Messages for library field names.
pub fn message(field: &str) -> Option<&'static str> {
    (field == "original_name").then_some(
        "Das Archiv enthält keinen einzelnen Originalnamen – Ziel mit -o/--out angeben / the archive holds no single original name – give a target with -o/--out",
    )
}

/// DE: Zufällige Namen gewünscht? EN: Random names requested?
pub fn random(m: &ArgMatches) -> bool {
    m.get_flag("random-name") || m.get_one::<String>("privacy").map(String::as_str) == Some("high")
}

/// DE: Mit zufälligem Namen passt `--out` nur zum Container (dort = Name im Archiv).
/// EN: With a random name `--out` only fits a container (there = name inside the archive).
pub fn check_out(m: &ArgMatches, container: bool, lang: Lang) -> CliResult {
    if random(m) && !container && m.get_one::<PathBuf>("out").is_some() {
        return Err(Failure::new(
            code::USAGE,
            localize(
                "Zufälliger Name und --out schließen sich aus (außer beim Container) / random name and --out exclude each other (except for a container)",
                lang,
            ),
        ));
    }
    Ok(())
}

/// DE: Ordner, in dem `path` liegt (`.` für einen bloßen Namen).
/// EN: Directory containing `path` (`.` for a bare name).
pub fn dir_of(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf()
}

/// DE: Verschlüsselt eine Quelle unter zufälligem Namen; Ordner mit Namen als oberstem Eintrag.
/// EN: Encrypts one source under a random name; directories with their name as top entry.
pub fn encrypt_random(
    p: &OwnedProtection,
    src: &Path,
) -> (Option<PathBuf>, pqkeep::Result<Report>) {
    let out = match files::random_target(&dir_of(src)) {
        Ok(out) => out,
        Err(e) => return (None, Err(e)),
    };
    let is_dir = std::fs::symlink_metadata(src).is_ok_and(|m| m.file_type().is_dir());
    let r = if is_dir {
        p.encrypt_many(&[src], &out)
    } else {
        p.encrypt(src, &out)
    };
    (Some(out), r)
}

/// DE: Container unter zufälligem Namen neben `--out`; Name aus `--out` (ohne `.pqkf`) im Archiv.
/// EN: Container under a random name next to `--out`; name from `--out` (without `.pqkf`) inside.
pub fn encrypt_container(
    p: &OwnedProtection,
    list: &[&Path],
    out: &Path,
) -> pqkeep::Result<(PathBuf, Report)> {
    let name = out
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(pqkeep::Error::InvalidInput { field: "path" })?;
    let suffix = format!(".{}", files::EXTENSION);
    let root = name
        .strip_suffix(&suffix)
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    let target = files::random_target(&dir_of(out))?;
    let report = p.encrypt_under(list, root, &target)?;
    Ok((target, report))
}

/// DE: Hat die Datei einen zufälligen Namen? EN: Does the file have a random name?
pub fn is_random_path(src: &Path) -> bool {
    src.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(files::is_random_name)
}

/// DE: Originalnamen herstellen? `--original-name` oder zufällige Form ohne `--out`.
/// EN: Restore the original name? `--original-name` or random shape without `--out`.
pub fn restore(m: &ArgMatches, src: &Path) -> bool {
    m.get_flag(ORIGINAL_NAME) || (m.get_one::<PathBuf>("out").is_none() && is_random_path(src))
}

/// DE: Argumente fürs Kontextmenü: Originalname mit freiem Namen statt `--out`.
/// EN: Arguments for the context menu: original name with a free name instead of `--out`.
pub const CONTEXT_RESTORE: [&str; 2] = ["--original-name", "--rename"];

/// DE: Ziel zum Aufräumen eigener Reste beim Entschlüsseln: bei zufälligem Namen die Quelle (die
/// Temporärausgaben heißen nach ihr), sonst das Standardziel.
/// EN: Target for cleaning up own leftovers when decrypting: for a random name the source (the
/// temporary output is named after it), else the default target.
pub fn cleanup_target(source: &Path) -> Option<PathBuf> {
    if is_random_path(source) {
        Some(source.to_path_buf())
    } else {
        super::files_cmd::default_decrypted(source)
    }
}

/// DE: Ziel fürs Fenster-Kontextmenü: bei zufälligem Namen die Quelle selbst (Anzeige; Reste heißen
/// nach ihr) und [`CONTEXT_RESTORE`], sonst ein freies `--out`-Ziel.
/// EN: Target for the window context menu: for a random name the source itself (display; leftovers
/// are named after it) and [`CONTEXT_RESTORE`], else a free `--out` target.
pub fn context_out(
    source: &Path,
    path: &str,
    lang: Lang,
) -> CliResult<(String, Option<[&'static str; 2]>)> {
    if is_random_path(source) {
        return Ok((path.to_owned(), Some(CONTEXT_RESTORE)));
    }
    let default = super::files_cmd::default_decrypted(source);
    Ok((super::context::out_arg(default.as_deref(), lang)?, None))
}

/// DE: Entschlüsselt unter dem Originalnamen neben der Quelle; `--rename` wählt einen freien Namen.
/// EN: Decrypts under the original name next to the source; `--rename` picks a free name.
pub fn decrypt_original(
    m: &ArgMatches,
    src: &Path,
    unlock: &Unlock<'_>,
    expected: Option<&PublicKeyFile>,
) -> (Option<PathBuf>, pqkeep::Result<Report>) {
    let rename = m.get_flag("rename");
    let choose = |p: &Path| {
        if rename {
            free_target(p)
        } else {
            Some(p.to_path_buf())
        }
    };
    match files::decrypt_original(src, &dir_of(src), unlock, expected, &choose) {
        Ok((out, report)) => (Some(out), Ok(report)),
        Err(e) => (None, Err(e)),
    }
}

#[cfg(test)]
#[path = "privacy_tests.rs"]
mod privacy_tests;
