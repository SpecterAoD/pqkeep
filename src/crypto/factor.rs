//! DE: Faktordatei (Format v2, `docs/V2_DRAFT.md`): genau 32 rohe Zufallsbytes, die als
//! Argon2id-Secret zusätzlich zur Passphrase nötig sind. Gelesen werden höchstens 33 Bytes und
//! nur reguläre Dateien (keine Links, Geräte, FIFOs); alles außer exakt 32 Bytes ist ein Fehler.
//! Linux: Rechte für Gruppe/andere oder ein fremder Eigentümer führen zur Ablehnung (D4).
//! Erzeugt wird nur auf ausdrücklichen Aufruf, ohne zu überschreiben (Linux 0600).
//! Windows: keine ACL-Prüfung ohne `unsafe` möglich (dokumentierte Grenze).
//!
//! EN: Factor file (format v2, `docs/V2_DRAFT.md`): exactly 32 raw random bytes required as the
//! Argon2id secret in addition to the passphrase. At most 33 bytes are read, and only regular
//! files (no links, devices, FIFOs); anything but exactly 32 bytes is an error. Linux:
//! permissions for group/others or a foreign owner are rejected (D4). A file is only created on
//! explicit request, never overwriting (Linux 0600). Windows: no ACL check possible without
//! `unsafe` (documented limit).

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use crate::crypto::{SecretBytes, rng};
use crate::fsutil::{open_new, publish_no_overwrite, sync_dir, temp_path};
use crate::{Error, Result};

/// DE: Länge der Faktordatei in Bytes. EN: Length of the factor file in bytes.
pub const FACTOR_LEN: usize = 32;

const FIELD: Error = Error::InvalidInput { field: "factor" };
const MODE: Error = Error::InvalidInput {
    field: "factor_permissions",
};

/// DE: Inhalt einer Faktordatei; wird beim Drop genullt. Kein `Debug`, `Clone` oder `Display`.
/// EN: Content of a factor file; zeroed on drop. No `Debug`, `Clone` or `Display`.
pub struct Factor(SecretBytes);

impl Factor {
    /// DE: Übernimmt genau 32 Bytes (z. B. aus einer anderen sicheren Quelle).
    /// EN: Takes exactly 32 bytes (e.g. from another safe source).
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (`factor`) bei anderer Länge / for any other length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != FACTOR_LEN {
            return Err(FIELD);
        }
        Ok(Self(SecretBytes::from_slice(bytes)))
    }

    /// DE: Liest eine Faktordatei. Der Pfad darf kein Link sein; geprüft wird die geöffnete
    /// Datei selbst (Art, Rechte, Eigentümer), nicht nur der Name.
    /// EN: Reads a factor file. The path must not be a link; the opened file itself is checked
    /// (type, permissions, owner), not just the name.
    ///
    /// # Errors
    /// DE/EN: [`Error::Io`] (fehlt, nicht lesbar / missing, unreadable), [`Error::InvalidInput`]
    /// mit `factor` (keine reguläre Datei, nicht genau 32 Bytes / not a regular file, not exactly
    /// 32 bytes) oder `factor_permissions` (zu offene Rechte / too open permissions).
    pub fn read(path: &Path) -> Result<Self> {
        if !fs::symlink_metadata(path)?.is_file() {
            return Err(FIELD);
        }
        let mut file = open_existing(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(FIELD);
        }
        if !permissions_ok(&meta) {
            return Err(MODE);
        }
        // DE: Ein Byte mehr als nötig lesen, um zu große Dateien zu erkennen.
        // EN: Read one byte more than needed to detect files that are too large.
        let mut buffer = SecretBytes::new(vec![0u8; FACTOR_LEN + 1]);
        let mut filled = 0;
        while filled < buffer.len() {
            match file.read(&mut buffer.expose_mut()[filled..])? {
                0 => break,
                n => filled += n,
            }
        }
        Self::from_bytes(&buffer.expose()[..filled])
    }

    /// DE: Erzeugt eine neue Faktordatei mit 32 Bytes aus dem Zufallsgenerator des
    /// Betriebssystems. Ein vorhandenes Ziel wird nie überschrieben.
    /// EN: Creates a new factor file with 32 bytes from the operating system's random
    /// generator. An existing target is never overwritten.
    ///
    /// # Errors
    /// DE/EN: [`Error::Io`] (u. a. `AlreadyExists`), [`Error::Rng`], [`Error::InvalidInput`] (Pfad / path).
    pub fn create(path: &Path) -> Result<()> {
        if fs::symlink_metadata(path).is_ok() {
            return Err(Error::Io(std::io::ErrorKind::AlreadyExists));
        }
        let bytes = rng::secret(FACTOR_LEN)?;
        let temp = temp_path(path)?;
        let result = write_and_publish(&temp, path, bytes.expose());
        if result.is_err() {
            // DE: Aufräumen; Fehler hier sind zweitrangig. EN: Clean up; errors here are secondary.
            let _ = fs::remove_file(&temp);
        }
        result
    }

    /// DE: Die 32 Bytes (nur für die Schlüsselableitung). EN: The 32 bytes (key derivation only).
    pub(crate) fn expose(&self) -> &[u8] {
        self.0.expose()
    }
}

fn write_and_publish(temp: &Path, path: &Path, data: &[u8]) -> Result<()> {
    let mut file = open_new(temp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    publish_no_overwrite(temp, path)?;
    sync_dir(path);
    Ok(())
}

fn open_existing(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // DE: O_NOFOLLOW: kein Link, auch wenn der Name nach der Prüfung getauscht wird.
        //     O_NONBLOCK: eine FIFO ohne Schreiber blockiert das Öffnen nicht.
        // EN: O_NOFOLLOW: no link, even if the name is swapped after the check.
        //     O_NONBLOCK: a FIFO without writer does not block opening.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

/// DE: Rechte und Eigentümer (Linux). EN: Permissions and owner (Linux).
#[cfg(target_os = "linux")]
// DE: Maske 0o077 (Gruppe/andere) ist lesbarer als `trailing_zeros`. EN: Mask is clearer.
#[allow(clippy::verbose_bit_mask)]
fn permissions_ok(meta: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let euid = rustix::process::geteuid().as_raw();
    meta.mode() & 0o077 == 0 && (meta.uid() == euid || meta.uid() == 0)
}

#[cfg(not(target_os = "linux"))]
fn permissions_ok(_meta: &Metadata) -> bool {
    true
}
