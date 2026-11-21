//! DE: Prüfen ohne Schreiben (#86): derselbe Weg wie beim Entschlüsseln – Header, Schlüssel,
//! alle Blöcke, Endmarke, Prüfsummen, Archivpfade (inkl. Doppel und Konflikte) –, der Klartext
//! läuft aber nur in einen Null-Ausgang. Es entstehen weder Ziel noch Temporärdateien.
//! EN: Checking without writing (#86): the same path as decrypting – header, key, all chunks, last
//! flag, checksums, archive paths (incl. duplicates and conflicts) – but the plaintext only goes
//! into a null sink. Neither a target nor temporary files are created.

use std::path::Path;

use super::{Report, Unlock, scan};
use crate::Result;

/// DE: Prüft `source` vollständig, ohne etwas zu schreiben; der Bericht zählt wie `decrypt`.
/// EN: Checks `source` completely without writing anything; the report counts like `decrypt`.
///
/// # Errors
/// DE/EN: wie / as [`super::decrypt`]: [`Error::Decrypt`] (falscher Schlüssel/Manipulation /
/// wrong key/tampering), [`Error::InvalidInput`] (Header, Archiv, Pfad, Prüfsumme, Schlüsselart,
/// Faktordatei / header, archive, path, checksum, key kind, factor file), [`Error::Unsupported`],
/// [`Error::Io`].
pub fn check(source: &Path, unlock: &Unlock<'_>) -> Result<Report> {
    scan::read(source, unlock, |_| Ok(()))
}
