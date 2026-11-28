//! DE: Datei- und Ordnerverschlüsselung (Spezifikation Abschnitt 4a). Eine
//! verschlüsselte Datei enthält immer ein kleines Archiv: Einzeldatei = Archiv mit
//! einem Eintrag, Ordner = Archiv mit allen Einträgen. Schutz per Passphrase
//! (Argon2id) oder für einen ML-KEM-Empfänger. Nicht über die API verfügbar.
//! Format: `docs/FILE_FORMAT.md`. Mit Faktordatei oder mehreren Zugängen entsteht Format v2
//! (`docs/V2_DRAFT.md`), sonst weiterhin v1; gelesen wird beides.
//!
//! EN: File and directory encryption (specification section 4a). An encrypted
//! file always contains a small archive: single file = archive with one entry,
//! directory = archive with all entries. Protection by passphrase (Argon2id) or
//! for an ML-KEM recipient. Not available via the API. Format: `docs/FILE_FORMAT.md`.
//! A factor file or several access slots produce format v2 (`docs/V2_DRAFT.md`), anything
//! else still v1; both are read.

mod anon_v4;
mod archive;
mod check;
mod confidential_entries;
mod confidential_framing;
mod confidential_path_index;
mod confidential_text;
mod decrypt;
mod decrypt_v2;
mod encrypt;
mod encrypt_header;
mod encrypt_v2;
pub mod format;
pub mod format_v2;
pub mod format_v4;
mod hidden_result;
mod list;
#[cfg(test)]
mod locked_owner_tests;
mod native_path;
mod original;
mod output;
mod output_guard;
pub mod paths;
#[cfg(test)]
#[path = "race_tests.rs"]
mod race_tests;
pub mod random_name;
#[cfg(test)]
#[path = "recovery_v4_tests.rs"]
mod recovery_v4_tests;
mod scan;
mod signed_by;
mod signed_io;
mod signer_v3;
mod slot_v2;
mod stream_v4;
mod tail_v4;
mod tail_v4_drain;
mod walk;

use std::io::BufReader;
use std::path::Path;

pub use crate::fsutil::set_temp_tag;
pub use check::{check, check_with};
pub use confidential_entries::ConfidentialEntries;
pub use confidential_text::ConfidentialText;
pub use decrypt::{decrypt, decrypt_with};
pub use encrypt::{
    encrypt, encrypt_many, encrypt_many_signed, encrypt_many_under, encrypt_many_with_options,
    encrypt_signed, encrypt_with_options,
};
pub use format::{Content, FileHeader, HeaderMode};
pub use format_v2::{HeaderV2, Slot};
pub use list::{EntryKind, ListEntry, Listing, MAX_LIST_ENTRIES, MAX_LIST_PATH_BYTES, list};
pub use original::{ChooseTarget, decrypt_original};
pub use random_name::{is_random_name, random_name, random_target};
pub use signed_by::SignedBy;
pub use signer_v3::Signer;
pub use slot_v2::MAX_RECIPIENTS;
pub use stream_v4::{encrypt_stream, encrypt_stream_to};
pub use walk::{SkipReason, Skipped};

use crate::Result;
use crate::crypto::factor::Factor;
use crate::crypto::kdf::KdfParams;
use crate::envelope::{PublicKeyFile, UnlockedKey};
use crate::security::{Passphrase, StrongPassphrase};

/// DE: Empfohlene Dateiendung. EN: Recommended file extension.
pub const EXTENSION: &str = "pqkf";

/// DE: Zusätzliche Optionen beim Verschlüsseln (Format v4, `docs/V4_DRAFT.md`); Standard = keine,
/// dann bleiben v1–v3 Byte für Byte gleich. Vorläufig bis #98.
/// EN: Additional options when encrypting (format v4, `docs/V4_DRAFT.md`); default = none, then
/// v1–v3 stay byte for byte. Provisional until #98.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EncryptOptions {
    /// DE: Füllung nach PADMÉ (verbirgt die genaue Größe, #316). EN: PADMÉ padding (hides the exact size).
    pub pad: bool,
    /// DE: Anonyme Empfänger ohne ID, nur ML-KEM-1024 – **experimentell** (#316, #340).
    /// EN: Anonymous recipients without ID, ML-KEM-1024 only – **experimental** (#316, #340).
    pub anonymous: bool,
    /// DE: Absender nur im verschlüsselten Teil (braucht einen Signaturschlüssel, #316).
    /// EN: Sender only inside the encrypted part (needs a signing key, #316).
    pub hide_sender: bool,
}

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
    /// DE: Mehrere Zugänge zu einer Datei: höchstens eine Passphrase (optional mit Faktordatei)
    /// und bis zu 64 Empfänger, mindestens ein Zugang. Ein einzelner Zugang ohne Faktordatei
    /// wird weiter als v1 geschrieben, alles andere als v2.
    /// EN: Several access slots for one file: at most one passphrase (optional factor file) and
    /// up to 64 recipients, at least one slot. A single slot without factor file is still
    /// written as v1, everything else as v2.
    Slots {
        /// DE: Passphrase-Zugang. EN: Passphrase slot.
        passphrase: Option<PassphraseAccess<'a>>,
        /// DE: Öffentliche ML-KEM-Schlüssel der Empfänger (keine Doppel).
        /// EN: Recipients' public ML-KEM keys (no duplicates).
        recipients: &'a [&'a PublicKeyFile],
    },
}

/// DE: Passphrase-Zugang beim Verschlüsseln. EN: Passphrase slot when encrypting.
pub struct PassphraseAccess<'a> {
    /// DE: Geprüfte Passphrase. EN: Checked passphrase.
    pub passphrase: &'a StrongPassphrase,
    /// DE: KDF-Parameter. EN: KDF parameters.
    pub params: KdfParams,
    /// DE: Faktordatei, die zusätzlich nötig ist. EN: Factor file required in addition.
    pub factor: Option<&'a Factor>,
}

/// DE: Schlüssel zum Entschlüsseln. EN: Key for decrypting.
pub enum Unlock<'a> {
    /// DE: Passphrase. EN: Passphrase.
    Passphrase(&'a Passphrase),
    /// DE: Passphrase und Faktordatei (nur v2). Passt die Datei nicht dazu (v1 oder Zugang
    /// ohne Faktor), ist das ein Fehler – der Faktor wird nie still ignoriert.
    /// EN: Passphrase and factor file (v2 only). If the file does not match (v1 or slot without
    /// factor) this is an error – the factor is never silently ignored.
    PassphraseWithFactor {
        /// DE: Passphrase. EN: Passphrase.
        passphrase: &'a Passphrase,
        /// DE: Faktordatei. EN: Factor file.
        factor: &'a Factor,
    },
    /// DE: Entsperrter ML-KEM-Schlüssel. EN: Unlocked ML-KEM key.
    Key(&'a UnlockedKey),
}

/// DE: Bericht über einen Vorgang. EN: Report of an operation.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// DE: Anzahl Dateien. EN: Number of files.
    pub files: u64,
    /// DE: Anzahl Ordner. EN: Number of directories.
    pub directories: u64,
    /// DE: Summe der Dateigrößen. EN: Total size of files.
    pub bytes: u64,
    /// DE: Übersprungene Einträge (nur beim Verschlüsseln). EN: Skipped entries (encrypting only).
    pub skipped: Vec<Skipped>,
    /// DE: Geprüfter Absender (nur Format v3, beim Entschlüsseln/Prüfen).
    /// EN: Verified sender (format v3 only, when decrypting/checking).
    pub signer: Option<SignedBy>,
}

/// DE: Liest nur den Header (ohne Schlüssel): Inhaltstyp, Schutzart, KDF-Parameter
/// bzw. Empfänger-ID – hilft, den richtigen Schlüssel zu finden. Nur v1; für v2 siehe
/// [`inspect_v2`].
/// EN: Reads only the header (no key): content type, protection, KDF parameters or
/// recipient ID – helps to find the right key. v1 only; for v2 see [`inspect_v2`].
///
/// # Errors
/// DE/EN: [`crate::Error::Io`], [`crate::Error::InvalidInput`], [`crate::Error::Unsupported`],
/// [`crate::Error::KdfParams`], [`crate::Error::MemoryLock`].
pub fn inspect(source: &Path) -> Result<FileHeader> {
    let mut reader = BufReader::new(native_path::open_file(source)?);
    FileHeader::read(&mut reader)
}

/// DE: Wie [`inspect`], für Dateien im Format v2 (alle Zugänge, keine Geheimnisse).
/// EN: Like [`inspect`], for files in format v2 (all slots, no secrets).
///
/// # Errors
/// DE/EN: wie [`inspect`]; [`crate::Error::Unsupported`] auch für v1-Dateien / also for v1 files.
pub fn inspect_v2(source: &Path) -> Result<HeaderV2> {
    let mut reader = BufReader::new(native_path::open_file(source)?);
    HeaderV2::read(&mut reader)
}
