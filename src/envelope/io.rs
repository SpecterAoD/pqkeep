//! DE: Dateizugriff: Lesen mit Größengrenze und Rechteprüfung (Linux), atomares
//! Schreiben über eine Temporärdatei im Zielordner. Ohne Überschreiben wird per
//! `hard_link` veröffentlicht (scheitert atomar, wenn das Ziel existiert), mit
//! ausdrücklichem Überschreiben per `rename`. Linux: Rechte 0600, fsync von Datei
//! und Ordner. Windows: Standard-ACL des Zielordners (Benutzerprofil empfohlen).
//!
//! EN: File access: reading with a size limit and permission check (Linux),
//! atomic writing via a temporary file in the target directory. Without
//! overwriting, publishing uses `hard_link` (fails atomically if the target
//! exists); with explicit overwriting, `rename`. Linux: mode 0600, fsync of file
//! and directory. Windows: default ACL of the target directory (user profile recommended).

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use super::keyfile::{KeyFile, MAX_FILE_BYTES};
use super::public::PublicKeyFile;
use crate::fsutil::{open_new, publish_no_overwrite, sync_dir, temp_path};
use crate::security::Lang;
use crate::{Error, Result};

/// DE: Hinweis beim Laden (kein Fehler). EN: Warning when loading (not an error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileWarning {
    /// DE: Datei ist für Gruppe/andere lesbar (Linux). EN: File readable by group/others (Linux).
    PermissiveMode {
        /// DE: Rechtebits. EN: Permission bits.
        mode: u32,
    },
}

impl FileWarning {
    /// DE: Meldung. EN: Message.
    #[must_use]
    pub fn message(&self, lang: Lang) -> String {
        match (self, lang) {
            (Self::PermissiveMode { mode }, Lang::De) => {
                format!("Datei ist für andere lesbar (Rechte {mode:o}); empfohlen: chmod 600")
            }
            (Self::PermissiveMode { mode }, Lang::En) => {
                format!("file is readable by others (mode {mode:o}); recommended: chmod 600")
            }
        }
    }
}

/// DE: Schreiben ohne/mit Überschreiben. EN: Write without/with overwriting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overwrite {
    /// DE: Vorhandenes Ziel → Fehler. EN: Existing target → error.
    No,
    /// DE: Vorhandenes Ziel wird ersetzt (nach Bestätigung durch den Nutzer).
    /// EN: Existing target is replaced (after user confirmation).
    Yes,
}

/// DE: Speichert die Schlüsseldatei atomar. EN: Saves the key file atomically.
///
/// # Errors
/// DE/EN: [`Error::Io`] (u. a. `AlreadyExists`), [`Error::Rng`].
pub fn save(key: &KeyFile, path: &Path, overwrite: Overwrite) -> Result<()> {
    write_atomic(path, key.to_json()?.as_bytes(), overwrite)
}

/// DE: Lädt und prüft eine Schlüsseldatei; liefert Hinweise (z. B. zu offene Rechte).
/// EN: Loads and validates a key file; returns warnings (e.g. permissive mode).
///
/// # Errors
/// DE/EN: [`Error::Io`], [`Error::InvalidInput`], [`Error::Unsupported`], [`Error::KdfParams`].
pub fn load(path: &Path) -> Result<(KeyFile, Vec<FileWarning>)> {
    let file = File::open(path)?;
    let warnings = permission_warnings(&file)?;
    let mut text = String::new();
    // DE: Höchstens Grenze + 1 lesen (kein TOCTOU über die Dateigröße).
    // EN: Read at most limit + 1 (no TOCTOU via the file size).
    let limit = u64::try_from(MAX_FILE_BYTES + 1).unwrap_or(u64::MAX);
    file.take(limit)
        .read_to_string(&mut text)
        .map_err(|_| Error::InvalidInput { field: "file" })?;
    Ok((KeyFile::from_json(&text)?, warnings))
}

/// DE: Speichert eine öffentliche Schlüsseldatei atomar. EN: Saves a public key file atomically.
///
/// # Errors
/// DE/EN: [`Error::Io`] (u. a. `AlreadyExists`).
pub fn save_public(key: &PublicKeyFile, path: &Path, overwrite: Overwrite) -> Result<()> {
    write_atomic(path, key.to_json()?.as_bytes(), overwrite)
}

/// DE: Lädt eine öffentliche Schlüsseldatei. EN: Loads a public key file.
///
/// # Errors
/// DE/EN: [`Error::Io`], [`Error::InvalidInput`], [`Error::Unsupported`].
pub fn load_public(path: &Path) -> Result<PublicKeyFile> {
    PublicKeyFile::from_json(&read_limited(path)?)
}

/// DE: Liest höchstens 64 KiB + 1 als Text. EN: Reads at most 64 KiB + 1 as text.
///
/// # Errors
/// DE/EN: [`Error::Io`], [`Error::InvalidInput`] (`file`).
pub fn read_limited(path: &Path) -> Result<String> {
    let mut text = String::new();
    let limit = u64::try_from(MAX_FILE_BYTES + 1).unwrap_or(u64::MAX);
    File::open(path)?
        .take(limit)
        .read_to_string(&mut text)
        .map_err(|_| Error::InvalidInput { field: "file" })?;
    Ok(text)
}

#[cfg(unix)]
fn permission_warnings(file: &File) -> Result<Vec<FileWarning>> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file.metadata()?.permissions().mode() & 0o777;
    // DE: Maske ist lesbarer als `trailing_zeros`. EN: The mask is clearer than `trailing_zeros`.
    #[allow(clippy::verbose_bit_mask)]
    Ok(if mode & 0o077 == 0 {
        Vec::new()
    } else {
        vec![FileWarning::PermissiveMode { mode }]
    })
}

#[cfg(not(unix))]
// DE: Gleiche Signatur wie die Unix-Variante. EN: Same signature as the Unix variant.
#[allow(clippy::unnecessary_wraps)]
fn permission_warnings(_file: &File) -> Result<Vec<FileWarning>> {
    Ok(Vec::new())
}

/// DE: Schreibt `data` atomar nach `path`. EN: Writes `data` atomically to `path`.
///
/// # Errors
/// DE/EN: [`Error::Io`] (u. a. `AlreadyExists` ohne Überschreiben / without overwrite).
pub fn write_atomic(path: &Path, data: &[u8], overwrite: Overwrite) -> Result<()> {
    let temp = temp_path(path)?;
    let result = write_and_publish(&temp, path, data, overwrite);
    if result.is_err() {
        // DE: Aufräumen; Fehler hier sind zweitrangig. EN: Clean up; errors here are secondary.
        let _ = fs::remove_file(&temp);
    }
    result
}

fn write_and_publish(temp: &Path, path: &Path, data: &[u8], overwrite: Overwrite) -> Result<()> {
    let mut file = open_new(temp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    match overwrite {
        Overwrite::Yes => fs::rename(temp, path)?,
        Overwrite::No => publish_no_overwrite(temp, path)?,
    }
    sync_dir(path);
    Ok(())
}
