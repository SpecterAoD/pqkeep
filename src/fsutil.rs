//! DE: Gemeinsame Dateihilfen für atomares Schreiben (Container und Datei-
//! verschlüsselung): Temporärname im Zielordner, Anlegen mit `create_new` (Linux
//! 0600), Veröffentlichen ohne Überschreiben per Hardlink, fsync des Ordners.
//!
//! EN: Shared file helpers for atomic writing (container and file encryption):
//! temporary name in the target directory, creation with `create_new` (Linux
//! 0600), publishing without overwriting via hard link, fsync of the directory.

use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::crypto::rng;
use crate::envelope::hex_encode;
use crate::{Error, Result};

/// DE: Kennung dieses Prozesses für Temporärnamen (16 Hex), siehe [`set_temp_tag`].
/// EN: This process's tag for temporary names (16 hex), see [`set_temp_tag`].
static TEMP_TAG: OnceLock<String> = OnceLock::new();

/// DE: Legt einmal pro Prozess eine Kennung (genau 16 Hex-Kleinbuchstaben) fest, die in jeden
/// Temporärnamen kommt (`.<name>.tmp-<kennung><zufall>`). So kann ein aufrufender Prozess nach
/// einem Abbruch genau die Reste **dieses** Prozesses entfernen.
/// EN: Sets once per process a tag (exactly 16 lowercase hex) that goes into every temporary name
/// (`.<name>.tmp-<tag><random>`). A calling process can thus remove exactly **this** process's
/// leftovers after cancelling.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (Form / format, schon gesetzt / already set).
pub fn set_temp_tag(tag: &str) -> Result<()> {
    let ok = tag.len() == 16
        && tag
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ok {
        return Err(Error::InvalidInput { field: "temp_tag" });
    }
    TEMP_TAG
        .set(tag.to_owned())
        .map_err(|_| Error::InvalidInput { field: "temp_tag" })
}

/// DE: Temporärer Name `.<name>.tmp-[<kennung>]<zufall>` neben `path`.
/// EN: Temporary name `.<name>.tmp-[<tag>]<random>` next to `path`.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (`path` ohne Dateinamen / without file name), [`Error::Rng`].
pub(crate) fn temp_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or(Error::InvalidInput { field: "path" })?;
    let suffix = hex_encode(&rng::array::<8>()?);
    let mut temp = std::ffi::OsString::from(".");
    temp.push(name);
    let tag = TEMP_TAG.get().map_or("", String::as_str);
    temp.push(format!(".tmp-{tag}{suffix}"));
    Ok(path.with_file_name(temp))
}

/// DE: Neue Datei, darf nicht existieren (Linux 0600). EN: New file, must not exist (Linux 0600).
pub(crate) fn open_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// DE: Veröffentlicht `temp` als `path`, ohne zu überschreiben.
/// EN: Publishes `temp` as `path` without overwriting.
pub(crate) fn publish_no_overwrite(temp: &Path, path: &Path) -> std::io::Result<()> {
    match fs::hard_link(temp, path) {
        Ok(()) => fs::remove_file(temp),
        // DE: Dateisysteme ohne Hardlinks (z. B. FAT): Prüfen + Umbenennen, nicht atomar.
        // EN: File systems without hard links (e.g. FAT): check + rename, not atomic.
        Err(e) if e.kind() == ErrorKind::Unsupported => {
            if path.exists() {
                return Err(ErrorKind::AlreadyExists.into());
            }
            fs::rename(temp, path)
        }
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
/// DE: fsync des Elternordners (best effort). EN: fsync of the parent directory (best effort).
pub(crate) fn sync_dir(path: &Path) {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // DE: Best effort: Ordnereintrag dauerhaft machen. EN: Best effort: persist the dir entry.
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

#[cfg(not(unix))]
pub(crate) fn sync_dir(_path: &Path) {}
