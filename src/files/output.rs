//! DE: Sichere Ausgabe: Es wird nur in eine Temporärdatei bzw. einen Temporär-
//! ordner neben dem Ziel geschrieben. Veröffentlicht wird erst nach vollständiger
//! Prüfung; scheitert etwas, entfernt `Drop` die eigene Temporärausgabe, das Ziel
//! entsteht nie. Vorhandene Ziele werden nicht überschrieben.
//! Linux: Dateien 0600, Ordner 0700.
//!
//! EN: Safe output: data is only written to a temporary file or directory next
//! to the target. Publishing happens only after full verification; if anything
//! fails, `Drop` removes our own temporary output and the target never appears.
//! Existing targets are never overwritten. Linux: files 0600, directories 0700.

use std::fs::{self, DirBuilder};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::output_guard::{Guard, cleanup};
use crate::fs_identity::{is_own, rename_noreplace, replaced, verify};
use crate::fsutil::{OutputFile, open_new, publish_no_overwrite, sync_dir, temp_path};
use crate::{Error, Result};

#[cfg(test)]
use crate::fault_io_tests::{Point, checkpoint};

/// DE: Temporäre Ausgabe mit Aufräumen bei Fehlern. EN: Temporary output with cleanup on failure.
pub(crate) struct TempOutput {
    temp: PathBuf,
    target: PathBuf,
    is_dir: bool,
    published: bool,
    /// DE: Eigenes offenes Objekt (#338). EN: Own open object (#338).
    guard: Option<Guard>,
}

fn ensure_absent(target: &Path) -> Result<()> {
    if fs::symlink_metadata(target).is_ok() {
        return Err(Error::Io(ErrorKind::AlreadyExists));
    }
    Ok(())
}

fn dir_builder() -> DirBuilder {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
}

impl TempOutput {
    /// DE: Temporärdatei für ein Dateiziel. EN: Temporary file for a file target.
    pub fn file(target: &Path) -> Result<(Self, OutputFile)> {
        ensure_absent(target)?;
        let temp = temp_path(target)?;
        let file = open_new(&temp)?;
        let output = Self::new(temp, target, false, Some(Guard::file(&file)?));
        #[cfg(test)]
        if let Err(error) = checkpoint(&output.temp, Point::AfterTempCreate) {
            drop(file);
            return Err(error.into());
        }
        Ok((output, file))
    }

    /// DE: Temporärdatei neben `base` (Name der Quelle) für das Ziel `target` (#315): so findet das
    /// Kontextmenü eigene Reste auch, wenn der Originalname vorher unbekannt war.
    /// EN: Temporary file next to `base` (the source's name) for the target `target` (#315): this
    /// way the context menu finds own leftovers even if the original name was unknown before.
    pub fn file_near(base: &Path, target: &Path) -> Result<(Self, OutputFile)> {
        ensure_absent(target)?;
        let temp = temp_path(base)?;
        let file = open_new(&temp)?;
        let guard = Guard::file(&file)?;
        Ok((Self::new(temp, target, false, Some(guard)), file))
    }

    /// DE: Temporärordner für ein Ordnerziel. EN: Temporary directory for a directory target.
    pub fn dir(target: &Path) -> Result<Self> {
        ensure_absent(target)?;
        let temp = temp_path(target)?;
        let mut builder = dir_builder();
        builder.recursive(false);
        builder.create(&temp)?;
        let mut output = Self::new(temp, target, true, None);
        #[cfg(test)]
        checkpoint(&output.temp, Point::AfterTempCreate)?;
        output.guard = Guard::dir(&output.temp)?;
        Ok(output)
    }

    /// DE: Temporärordner neben `base`, ohne Ziel (Originalname wird erst beim Entpacken bekannt,
    /// #315); veröffentlicht wird mit [`Self::publish_child`].
    /// EN: Temporary directory next to `base`, without a target (the original name is only known
    /// while extracting, #315); published with [`Self::publish_child`].
    pub fn scratch_dir(base: &Path) -> Result<Self> {
        let temp = temp_path(base)?;
        let mut builder = dir_builder();
        builder.recursive(false);
        builder.create(&temp)?;
        let mut output = Self::new(temp, base, true, None);
        output.guard = Guard::dir(&output.temp)?;
        Ok(output)
    }

    /// DE: Veröffentlicht den Unterordner `child` als `target` (ohne Überschreiben) und entfernt
    /// den dann leeren Temporärordner.
    /// EN: Publishes the subdirectory `child` as `target` (no overwriting) and removes the then
    /// empty temporary directory.
    pub fn publish_child(mut self, child: &str, target: &Path) -> Result<()> {
        ensure_absent(target)?;
        // DE: Quelle über das Handle (#338). EN: Source via the handle (#338).
        let source = self.path().join(child);
        let id = crate::fs_identity::Identity::at(&source)?;
        rename_noreplace(&source, target)?;
        verify(target, id)?;
        sync_dir(target);
        self.published = true;
        if self.guard.as_ref().is_none_or(|g| is_own(&self.temp, g.id)) {
            let _ = fs::remove_dir(&self.temp);
        }
        Ok(())
    }

    fn new(temp: PathBuf, target: &Path, is_dir: bool, guard: Option<Guard>) -> Self {
        Self {
            temp,
            target: target.to_path_buf(),
            is_dir,
            published: false,
            guard,
        }
    }

    /// DE: Pfad der Temporärausgabe; Ordner unter Linux über das Handle (`/proc/self/fd/N`), damit
    /// ein ausgetauschter Name keine Schreibvorgänge umlenkt (#338).
    /// EN: Path of the temporary output; directories on Linux via the handle (`/proc/self/fd/N`)
    /// so a swapped name cannot redirect writes (#338).
    pub fn path(&self) -> &Path {
        self.guard
            .as_ref()
            .and_then(|g| g.via.as_deref())
            .unwrap_or(&self.temp)
    }

    /// DE: Veröffentlicht unter dem Zielnamen. Ordner: Prüfen + Umbenennen (unter
    /// POSIX ersetzt `rename` einen leeren Zielordner, daher die Prüfung direkt davor).
    /// EN: Publishes under the target name. Directories: check + rename (on POSIX
    /// `rename` replaces an empty target directory, hence the check right before).
    pub fn publish(mut self) -> Result<()> {
        if self.is_dir {
            ensure_absent(&self.target)?;
            #[cfg(test)]
            checkpoint(&self.temp, Point::BeforePublish)?;
            #[cfg(test)]
            checkpoint(&self.temp, Point::BeforeRename)?;
            // DE: Nur das eigene Objekt, ohne Ersetzen, danach prüfen (#338).
            // EN: Only our own object, without replacing, verified afterwards (#338).
            let id = self.guard.as_ref().map(|g| g.id);
            if id.is_some_and(|id| !is_own(&self.temp, id)) {
                return Err(replaced().into());
            }
            rename_noreplace(&self.temp, &self.target)?;
            #[cfg(test)]
            checkpoint(&self.target, Point::AfterPublish)?;
            if let Some(id) = id {
                verify(&self.target, id)?;
            }
        } else {
            let guard = self.guard.as_ref().ok_or_else(replaced)?;
            publish_no_overwrite(&self.temp, &guard.handle, &self.target)?;
        }
        sync_dir(&self.target);
        self.published = true;
        Ok(())
    }
}

impl Drop for TempOutput {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // DE: Nur die eigene, selbst angelegte Temporärausgabe wird entfernt.
        // EN: Only our own, self-created temporary output is removed.
        #[cfg(test)]
        if checkpoint(
            &self.temp,
            if self.is_dir {
                Point::BeforeRemoveDirAll
            } else {
                Point::BeforeRemoveFile
            },
        )
        .is_err()
        {
            return;
        }
        cleanup(&self.temp, &self.target, self.is_dir, self.guard.as_ref());
    }
}

fn join<'a>(root: &Path, parts: impl Iterator<Item = &'a str>) -> PathBuf {
    parts.fold(root.to_path_buf(), |p, part| p.join(part))
}

/// DE: Legt einen (bereits geprüften) Ordner unter `root` an.
/// EN: Creates an (already validated) directory below `root`.
pub(crate) fn create_dir<'a>(root: &Path, parts: impl Iterator<Item = &'a str>) -> Result<()> {
    dir_builder().create(join(root, parts))?;
    Ok(())
}

/// DE: Legt eine neue Datei unter `root` an (Elternordner bei Bedarf).
/// EN: Creates a new file below `root` (parent directories if needed).
pub(crate) fn create_file<'a>(
    root: &Path,
    parts: impl Iterator<Item = &'a str>,
) -> Result<OutputFile> {
    let path = join(root, parts);
    if let Some(parent) = path.parent() {
        dir_builder().create(parent)?;
    }
    Ok(open_new(&path)?)
}
