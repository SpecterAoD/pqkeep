//! DE: Verschlüsselter Datei-Snapshot mit ausdrücklicher Rekey-Ausgabe und Sicherung.
//! EN: Encrypted file snapshot with explicit rekey output and backup.

use std::path::{Path, PathBuf};

use super::rekey_paths;
use super::{FileWarning, KeyFile, Overwrite, io};
use crate::crypto::factor::Factor;
use crate::crypto::kdf::KdfParams;
use crate::security::{Passphrase, StrongPassphrase};
use crate::{Error, Result};

/// DE: Ausdrückliches Ziel. Bestehende fremde Ziele/Sicherungen werden nie ersetzt.
/// EN: Explicit target. Existing unrelated outputs/backups are never replaced.
pub struct RekeyOptions<'a> {
    /// DE: Neue Datei oder ausdrücklich derselbe Quellpfad. EN: New file or explicit source path.
    pub output: &'a Path,
    /// DE: Neue Sicherung; bei Austausch erforderlich. EN: New backup; required for replacement.
    pub backup: Option<&'a Path>,
    /// DE: Nur am Quellpfad ist Yes erlaubt. EN: Yes only authorizes replacing the source path.
    pub overwrite: Overwrite,
    /// DE: None erhält KDF; Some nur ohne Absenkung. EN: None preserves KDF; Some cannot reduce it.
    pub params: Option<KdfParams>,
}

impl<'a> RekeyOptions<'a> {
    /// DE: Neue Ausgabe ohne Überschreiben, mit bisherigen KDF-Parametern.
    /// EN: New output without overwriting, preserving existing KDF parameters.
    #[must_use]
    pub fn new(output: &'a Path) -> Self {
        Self {
            output,
            backup: None,
            overwrite: Overwrite::No,
            params: None,
        }
    }
}

/// DE: Geprüfter Snapshot einer regulären verschlüsselten Schlüsseldatei. Kein Prozesslock/CAS:
/// Verzeichnisse müssen vertrauenswürdig sein und nur ein Schreiber darf aktiv sein.
/// EN: Validated regular encrypted-key snapshot. No process lock/CAS: directories must be
/// trusted and have only one writer. See `docs/security/REKEY_DESIGN.md`.
pub struct RekeyFile {
    path: PathBuf,
    original: String,
    key: KeyFile,
    warnings: Vec<FileWarning>,
}

impl RekeyFile {
    /// DE: Liest begrenzt, ohne finale Links/Spezialdateien. EN: Bounded read, no final links/devices.
    ///
    /// # Errors
    /// DE/EN: [`Error::Io`], [`Error::InvalidInput`], [`Error::Unsupported`], [`Error::KdfParams`].
    pub fn open(path: &Path) -> Result<Self> {
        let path = rekey_paths::resolve(path)?;
        let (original, warnings) = rekey_paths::read(&path)?;
        let key = KeyFile::from_json(&original)?;
        Ok(Self {
            path,
            original,
            key,
            warnings,
        })
    }

    /// DE: Geschützter Schlüssel, kein Klartext. EN: Protected key, no plaintext secret.
    #[must_use]
    pub fn key(&self) -> &KeyFile {
        &self.key
    }

    /// DE: Rechtehinweise wie beim normalen Laden. EN: Permission warnings as with normal loading.
    #[must_use]
    pub fn warnings(&self) -> &[FileWarning] {
        &self.warnings
    }

    /// DE: Prüft Ziele vor Passphraseeingabe, schreibt nichts. EN: Check targets before input, no writes.
    ///
    /// # Errors
    /// DE/EN: [`Error::Io`], [`Error::InvalidInput`] (`rekey_backup`, `rekey_file`).
    pub fn check(&self, options: &RekeyOptions<'_>) -> Result<()> {
        rekey_paths::targets(&self.path, options).map(|_| ())
    }

    /// DE: Erst authentifizieren/neu schützen, dann Sicherung und vollständige Ausgabe publizieren.
    /// EN: Authenticate/rewrap first, then publish backup and complete output.
    ///
    /// # Errors
    /// DE/EN: [`KeyFile::rekey`] errors, [`Error::Io`], [`Error::InvalidInput`] (`rekey_changed`,
    /// `rekey_backup`, `rekey_file`). After commit an error may leave a complete new key + backup.
    /// DE: Nach Commit kann trotz Fehler ein vollständiger neuer Schlüssel mit Sicherung vorliegen.
    pub fn write(
        &self,
        options: &RekeyOptions<'_>,
        old: &Passphrase,
        new: &StrongPassphrase,
        factor: Option<&Factor>,
    ) -> Result<()> {
        let targets = rekey_paths::targets(&self.path, options)?;
        let key = self.key.rekey(old, new, factor, options.params.as_ref())?;
        let json = key.to_json()?;
        self.unchanged()?;
        if let Some(backup) = &targets.backup {
            io::write_atomic_strict(backup, self.original.as_bytes())?;
        }
        self.unchanged()?;
        if targets.in_place {
            io::write_atomic(&targets.output, json.as_bytes(), Overwrite::Yes)
        } else {
            io::write_atomic_strict(&targets.output, json.as_bytes())
        }
    }

    fn unchanged(&self) -> Result<()> {
        if rekey_paths::read(&self.path)?.0 != self.original {
            return Err(Error::InvalidInput {
                field: "rekey_changed",
            });
        }
        Ok(())
    }
}
