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

use std::fs::{self, DirBuilder, File};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::fsutil::{open_new, publish_no_overwrite, sync_dir, temp_path};
use crate::{Error, Result};

/// DE: Temporäre Ausgabe mit Aufräumen bei Fehlern. EN: Temporary output with cleanup on failure.
pub(crate) struct TempOutput {
    temp: PathBuf,
    target: PathBuf,
    is_dir: bool,
    published: bool,
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
    pub fn file(target: &Path) -> Result<(Self, File)> {
        ensure_absent(target)?;
        let temp = temp_path(target)?;
        let file = open_new(&temp)?;
        Ok((Self::new(temp, target, false), file))
    }

    /// DE: Temporärordner für ein Ordnerziel. EN: Temporary directory for a directory target.
    pub fn dir(target: &Path) -> Result<Self> {
        ensure_absent(target)?;
        let temp = temp_path(target)?;
        let mut builder = dir_builder();
        builder.recursive(false);
        builder.create(&temp)?;
        Ok(Self::new(temp, target, true))
    }

    fn new(temp: PathBuf, target: &Path, is_dir: bool) -> Self {
        Self {
            temp,
            target: target.to_path_buf(),
            is_dir,
            published: false,
        }
    }

    /// DE: Pfad der Temporärausgabe. EN: Path of the temporary output.
    pub fn path(&self) -> &Path {
        &self.temp
    }

    /// DE: Veröffentlicht unter dem Zielnamen. Ordner: Prüfen + Umbenennen (unter
    /// POSIX ersetzt `rename` einen leeren Zielordner, daher die Prüfung direkt davor).
    /// EN: Publishes under the target name. Directories: check + rename (on POSIX
    /// `rename` replaces an empty target directory, hence the check right before).
    pub fn publish(mut self) -> Result<()> {
        if self.is_dir {
            ensure_absent(&self.target)?;
            fs::rename(&self.temp, &self.target)?;
        } else {
            publish_no_overwrite(&self.temp, &self.target)?;
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
        let _ = if self.is_dir {
            fs::remove_dir_all(&self.temp)
        } else {
            fs::remove_file(&self.temp)
        };
    }
}

fn join(root: &Path, parts: &[&str]) -> PathBuf {
    parts
        .iter()
        .fold(root.to_path_buf(), |p, part| p.join(part))
}

/// DE: Legt einen (bereits geprüften) Ordner unter `root` an.
/// EN: Creates an (already validated) directory below `root`.
pub(crate) fn create_dir(root: &Path, parts: &[&str]) -> Result<()> {
    dir_builder().create(join(root, parts))?;
    Ok(())
}

/// DE: Legt eine neue Datei unter `root` an (Elternordner bei Bedarf).
/// EN: Creates a new file below `root` (parent directories if needed).
pub(crate) fn create_file(root: &Path, parts: &[&str]) -> Result<File> {
    let path = join(root, parts);
    if let Some(parent) = path.parent() {
        dir_builder().create(parent)?;
    }
    Ok(open_new(&path)?)
}
