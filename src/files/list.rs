//! DE: Authentisierte, begrenzte Metadatenliste ohne Extraktion (#117).
//! EN: Authenticated, bounded metadata listing without extraction (#117).

use std::path::Path;

use super::archive::Entry;
use super::{ConfidentialText, Report, Unlock, scan};
use crate::{Error, Result};

/// DE: List-Grenze; check/decrypt behalten ihre Grenzen. EN: Listing-only entry cap.
pub const MAX_LIST_ENTRIES: usize = 10_000;
/// DE: Summe der UTF-8-Pfadbytes, ohne Dateninhalt. EN: Aggregate UTF-8 path bytes, not payload.
pub const MAX_LIST_PATH_BYTES: usize = 16 * 1024 * 1024;

/// DE: Archivtyp, niemals Symlinks oder aktive Inhalte. EN: Entry kind, never symlinks/active content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// DE: Datei. EN: File.
    File,
    /// DE: Ordner. EN: Directory.
    Directory,
}

/// DE: Geprüfte Metadaten; nur nach ausdrücklicher Anforderung anzeigen.
/// EN: Verified metadata; display only when explicitly requested.
#[derive(PartialEq, Eq)]
pub struct ListEntry {
    /// DE: Relativer UTF-8-Archivpfad. EN: Relative UTF-8 archive path.
    pub path: ConfidentialText,
    /// DE: Datei oder Ordner. EN: File or directory.
    pub kind: EntryKind,
    /// DE: Dateigröße; bei Ordnern None. EN: File size; None for directories.
    pub bytes: Option<u64>,
}

/// DE: Vollständig geprüfte Liste in Archivreihenfolge, keine Absenderidentität.
/// EN: Fully checked listing in archive order, not proof of sender identity.
#[derive(PartialEq, Eq)]
pub struct Listing {
    /// DE: Validierte Einträge. EN: Validated entries.
    pub entries: Vec<ListEntry>,
    /// DE: Derselbe Bericht wie check. EN: Same report as check.
    pub report: Report,
}

#[derive(Default)]
struct Pending {
    entries: Vec<ListEntry>,
    path_bytes: usize,
}

fn limit() -> Error {
    Error::InvalidInput {
        field: "list_limit",
    }
}

impl Pending {
    fn push(&mut self, entry: &Entry) -> Result<()> {
        let (path, kind, bytes) = match entry {
            Entry::Dir(path) => (path, EntryKind::Directory, None),
            Entry::File(path, size) => (path, EntryKind::File, Some(*size)),
        };
        let total = self
            .path_bytes
            .checked_add(path.bytes().len())
            .ok_or_else(limit)?;
        if self.entries.len() >= MAX_LIST_ENTRIES || total > MAX_LIST_PATH_BYTES {
            return Err(limit());
        }
        self.entries.try_reserve(1).map_err(|_| limit())?;
        self.entries.push(ListEntry {
            path: path.try_duplicate()?,
            kind,
            bytes,
        });
        self.path_bytes = total;
        Ok(())
    }
}

/// DE: Prüft eine v1/v2-Quelle vollständig und liefert erst dann ihre Metadaten.
/// Kein Dateischreiben, kein Temp-Spool, keine vorläufigen Ergebnisse. Nutzdaten werden
/// gestreamt verworfen; Metadaten/Prüfstrukturen wachsen innerhalb der List-Grenzen.
/// EN: Fully verifies one v1/v2 source before returning metadata. No file writes,
/// temporary spool or provisional output. Payload is streamed/discarded; metadata and
/// validation structures grow within listing caps. No constant-total-memory guarantee.
///
/// # Errors
/// DE/EN: wie / as [`super::check`], zusätzlich / additionally
/// [`Error::InvalidInput`] mit / with field `list_limit` bei / for listing limits.
pub fn list(source: &Path, unlock: &Unlock<'_>) -> Result<Listing> {
    let mut pending = Pending::default();
    let report = scan::read(source, unlock, None, |entry| pending.push(entry))?;
    Ok(Listing {
        entries: pending.entries,
        report,
    })
}

#[cfg(test)]
#[path = "list_tests.rs"]
mod tests;

impl std::fmt::Debug for ListEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ListEntry([REDACTED])")
    }
}
impl std::fmt::Debug for Listing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Listing([REDACTED])")
    }
}
