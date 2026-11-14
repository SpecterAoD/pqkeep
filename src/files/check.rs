//! DE: Prüfen ohne Schreiben (#86): derselbe Weg wie beim Entschlüsseln – Header, Schlüssel,
//! alle Blöcke, Endmarke, Prüfsummen, Archivpfade (inkl. Doppel und Konflikte) –, der Klartext
//! läuft aber nur in einen Null-Ausgang. Es entstehen weder Ziel noch Temporärdateien.
//! EN: Checking without writing (#86): the same path as decrypting – header, key, all chunks, last
//! flag, checksums, archive paths (incl. duplicates and conflicts) – but the plaintext only goes
//! into a null sink. Neither a target nor temporary files are created.

use std::io::{Read, sink};
use std::path::Path;

use super::archive::{ArchiveReader, Entry};
use super::decrypt;
use super::format::Content;
use super::paths::{self, PathSet};
use super::{Report, Unlock};
use crate::{Error, Result};

/// DE: Prüft `source` vollständig, ohne etwas zu schreiben; der Bericht zählt wie `decrypt`.
/// EN: Checks `source` completely without writing anything; the report counts like `decrypt`.
///
/// # Errors
/// DE/EN: wie / as [`super::decrypt`]: [`Error::Decrypt`] (falscher Schlüssel/Manipulation /
/// wrong key/tampering), [`Error::InvalidInput`] (Header, Archiv, Pfad, Prüfsumme, Schlüsselart,
/// Faktordatei / header, archive, path, checksum, key kind, factor file), [`Error::Unsupported`],
/// [`Error::Io`].
pub fn check(source: &Path, unlock: &Unlock<'_>) -> Result<Report> {
    let (archive, content) = decrypt::open(source, unlock)?;
    match content {
        Content::File => check_file(archive),
        Content::Directory => check_dir(archive),
    }
}

fn check_file<R: Read>(mut archive: ArchiveReader<R>) -> Result<Report> {
    let Some(Entry::File(name, size)) = archive.next_entry()? else {
        return Err(Error::InvalidInput { field: "archive" });
    };
    paths::validate(&name)?;
    archive.copy_file(size, &mut sink())?;
    if archive.next_entry()?.is_some() {
        return Err(Error::InvalidInput { field: "archive" });
    }
    archive.finish()?;
    Ok(Report {
        files: 1,
        bytes: size,
        ..Report::default()
    })
}

fn check_dir<R: Read>(mut archive: ArchiveReader<R>) -> Result<Report> {
    let mut seen = PathSet::default();
    let mut report = Report::default();
    while let Some(entry) = archive.next_entry()? {
        match entry {
            Entry::Dir(path) => {
                seen.insert(&paths::validate(&path)?, false)?;
                report.directories += 1;
            }
            Entry::File(path, size) => {
                seen.insert(&paths::validate(&path)?, true)?;
                archive.copy_file(size, &mut sink())?;
                report.files += 1;
                report.bytes += size;
            }
        }
    }
    archive.finish()?;
    Ok(report)
}
