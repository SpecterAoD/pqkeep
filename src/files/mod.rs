//! DE: Datei- und Ordnerverschlüsselung (Spezifikation Abschnitt 4a). Eine
//! verschlüsselte Datei enthält immer ein kleines Archiv: Einzeldatei = Archiv mit
//! einem Eintrag, Ordner = Archiv mit allen Einträgen. Schutz per Passphrase
//! (Argon2id) oder für einen ML-KEM-Empfänger. Nicht über die API verfügbar.
//! Format: `docs/FILE_FORMAT.md`.
//!
//! EN: File and directory encryption (specification section 4a). An encrypted
//! file always contains a small archive: single file = archive with one entry,
//! directory = archive with all entries. Protection by passphrase (Argon2id) or
//! for an ML-KEM recipient. Not available via the API. Format: `docs/FILE_FORMAT.md`.

mod archive;
mod decrypt;
mod encrypt;
pub mod format;
pub mod format_v2;
mod output;
pub mod paths;
mod slot_v2;
mod walk;

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub use crate::fsutil::set_temp_tag;
pub use decrypt::decrypt;
pub use encrypt::{encrypt, encrypt_many};
pub use format::{Content, FileHeader, HeaderMode};
pub use format_v2::{HeaderV2, Slot};
pub use walk::{SkipReason, Skipped};

use crate::Result;
use crate::crypto::kdf::KdfParams;
use crate::envelope::{PublicKeyFile, UnlockedKey};
use crate::security::{Passphrase, StrongPassphrase};

/// DE: Empfohlene Dateiendung. EN: Recommended file extension.
pub const EXTENSION: &str = "pqkf";

/// DE: Schutz beim Verschlüsseln. EN: Protection when encrypting.
pub enum Protection<'a> {
    /// DE: Passphrase mit Argon2id-Parametern. EN: Passphrase with Argon2id parameters.
    Passphrase {
        /// DE: Geprüfte Passphrase. EN: Checked passphrase.
        passphrase: &'a StrongPassphrase,
        /// DE: KDF-Parameter. EN: KDF parameters.
        params: KdfParams,
    },
    /// DE: Öffentlicher ML-KEM-Schlüssel des Empfängers (`*.pub.json`).
    /// EN: Recipient's public ML-KEM key (`*.pub.json`).
    Recipient(&'a PublicKeyFile),
}

/// DE: Schlüssel zum Entschlüsseln. EN: Key for decrypting.
pub enum Unlock<'a> {
    /// DE: Passphrase. EN: Passphrase.
    Passphrase(&'a Passphrase),
    /// DE: Entsperrter ML-KEM-Schlüssel. EN: Unlocked ML-KEM key.
    Key(&'a UnlockedKey),
}

/// DE: Bericht über einen Vorgang. EN: Report of an operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// DE: Anzahl Dateien. EN: Number of files.
    pub files: u64,
    /// DE: Anzahl Ordner. EN: Number of directories.
    pub directories: u64,
    /// DE: Summe der Dateigrößen. EN: Total size of files.
    pub bytes: u64,
    /// DE: Übersprungene Einträge (nur beim Verschlüsseln). EN: Skipped entries (encrypting only).
    pub skipped: Vec<Skipped>,
}

/// DE: Liest nur den Header (ohne Schlüssel): Inhaltstyp, Schutzart, KDF-Parameter
/// bzw. Empfänger-ID – hilft, den richtigen Schlüssel zu finden.
/// EN: Reads only the header (no key): content type, protection, KDF parameters or
/// recipient ID – helps to find the right key.
///
/// # Errors
/// DE/EN: [`crate::Error::Io`], [`crate::Error::InvalidInput`], [`crate::Error::Unsupported`],
/// [`crate::Error::KdfParams`].
pub fn inspect(source: &Path) -> Result<FileHeader> {
    let mut reader = BufReader::new(File::open(source)?);
    FileHeader::read(&mut reader)
}
