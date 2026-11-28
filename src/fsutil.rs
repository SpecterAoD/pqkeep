//! DE: Gemeinsame Dateihilfen für atomares Schreiben (Container und Datei-
//! verschlüsselung): Temporärname im Zielordner, Anlegen mit `create_new` (Linux
//! 0600), Veröffentlichen ohne Überschreiben per Hardlink, fsync des Ordners.
//!
//! EN: Shared file helpers for atomic writing (container and file encryption):
//! temporary name in the target directory, creation with `create_new` (Linux
//! 0600), publishing without overwriting via hard link, fsync of the directory.

use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::crypto::rng;
use crate::envelope::hex_encode;
use crate::fs_identity::{Identity, is_own, link_handle, rename_noreplace, replaced, verify};
use crate::{Error, Result};

// DE: Nur Lib-Tests erhalten einen Wrapper. EN: Only lib tests receive a wrapper.
#[cfg(not(test))]
pub(crate) type OutputFile = fs::File;
#[cfg(test)]
use crate::fault_io_tests::{Point, checkpoint};
#[cfg(test)]
pub(crate) use crate::fault_writer_tests::OutputFile;

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
pub(crate) fn open_new(path: &Path) -> std::io::Result<OutputFile> {
    #[cfg(test)]
    checkpoint(path, Point::BeforeOpen)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(test)]
    let file = OutputFile::new(file, path);
    Ok(file)
}

/// DE: Zweites Handle auf die geschriebene Datei, um sie unabhängig vom Namen zu veröffentlichen
/// und zu prüfen (#338). EN: Second handle to the written file to publish and verify it
/// independent of its name (#338).
pub(crate) fn handle_of(file: &OutputFile) -> std::io::Result<fs::File> {
    #[cfg(not(test))]
    return file.try_clone();
    #[cfg(test)]
    file.try_clone_file()
}

/// DE: Veröffentlicht die über `handle` offene Datei `temp` als `path`, ohne zu überschreiben.
/// EN: Publishes the file `temp`, open via `handle`, as `path` without overwriting.
pub(crate) fn publish_no_overwrite(
    temp: &Path,
    handle: &fs::File,
    path: &Path,
) -> std::io::Result<()> {
    publish(temp, handle, path, true)
}

/// DE: Rekey: ohne Hardlinks kein unsicherer Fallback. EN: Rekey: no weak fallback without links.
pub(crate) fn publish_no_overwrite_strict(
    temp: &Path,
    handle: &fs::File,
    path: &Path,
) -> std::io::Result<()> {
    publish(temp, handle, path, false)
}

/// DE: Linux: über den Deskriptor verlinken, sonst über den Namen. EN: Link via descriptor or name.
fn link(temp: &Path, handle: &fs::File, path: &Path) -> std::io::Result<()> {
    if link_handle(handle, path)? {
        return Ok(());
    }
    fs::hard_link(temp, path)
}

fn publish(
    temp: &Path,
    handle: &fs::File,
    path: &Path,
    allow_fallback: bool,
) -> std::io::Result<()> {
    let id = Identity::of(handle)?;
    #[cfg(test)]
    checkpoint(temp, Point::BeforePublish)?;
    #[cfg(test)]
    let linked = checkpoint(temp, Point::BeforeHardLink).and_then(|()| link(temp, handle, path));
    #[cfg(not(test))]
    let linked = link(temp, handle, path);
    match linked {
        Ok(()) => {
            #[cfg(test)]
            checkpoint(temp, Point::AfterPublish)?;
            if verify(path, id).is_err() {
                // DE: Fremdes Objekt verlinkt: eigenen Namen wieder entfernen. EN: Remove our link.
                let _ = fs::remove_file(path);
                return Err(replaced());
            }
            #[cfg(test)]
            checkpoint(temp, Point::BeforeRemoveFile)?;
            // DE: Nur den eigenen Temporärnamen entfernen. EN: Only remove our own temporary name.
            if is_own(temp, id) {
                fs::remove_file(temp)?;
            }
            Ok(())
        }
        // DE: Dateisysteme ohne Hardlinks (z. B. FAT): Umbenennen ohne Ersetzen, danach prüfen.
        // EN: File systems without hard links (e.g. FAT): rename without replacing, then verify.
        Err(e) if allow_fallback && e.kind() == ErrorKind::Unsupported => {
            if path.exists() {
                return Err(ErrorKind::AlreadyExists.into());
            }
            #[cfg(test)]
            checkpoint(temp, Point::BeforeRename)?;
            if !is_own(temp, id) {
                return Err(replaced());
            }
            rename_noreplace(temp, path)?;
            #[cfg(test)]
            checkpoint(path, Point::AfterPublish)?;
            verify(path, id)
        }
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
/// DE: fsync des Elternordners (best effort). EN: fsync of the parent directory (best effort).
pub(crate) fn sync_dir(path: &Path) {
    #[cfg(test)]
    if checkpoint(path, Point::BeforeDirSync).is_err() {
        return;
    }
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // DE: Best effort: Ordnereintrag dauerhaft machen. EN: Best effort: persist the dir entry.
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

#[cfg(not(unix))]
pub(crate) fn sync_dir(_path: &Path) {}
