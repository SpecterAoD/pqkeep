//! DE: Entschlüsseln nach `ziel`. Klartext gelangt nur in die eigene Temporär-
//! ausgabe; veröffentlicht wird erst, wenn alle Blöcke, die Endmarke, alle
//! Prüfsummen und alle Pfade geprüft sind. Bösartige Archive (auch korrekt für
//! den Empfänger verschlüsselte) werden abgewiesen, ohne etwas zu hinterlassen.
//!
//! EN: Decrypting into `target`. Plaintext only goes into our own temporary
//! output; publishing happens only once all chunks, the last flag, all checksums
//! and all paths have been verified. Malicious archives (even ones correctly
//! encrypted for the recipient) are rejected without leaving anything behind.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read};
use std::path::Path;

use sha3::{Digest, Sha3_256};

use super::archive::{ArchiveReader, Entry};
use super::format::{Content, FileHeader, HeaderMode};
use super::output::{self, TempOutput};
use super::paths::{self, PathSet};
use super::{Report, Unlock};
use crate::crypto::stream::DecryptReader;
use crate::crypto::wrap;
use crate::crypto::{KeyAlgorithm, SecretBytes};
use crate::{Error, Result};

/// DE: Entschlüsselt `source` nach `target` (Datei bzw. Ordner laut Header).
/// EN: Decrypts `source` into `target` (file or directory per header).
///
/// # Errors
/// DE/EN: [`Error::Decrypt`] (falscher Schlüssel/Manipulation / wrong key/tampering),
/// [`Error::InvalidInput`] (Header, Archiv, Pfad, Prüfsumme, Schlüsselart /
/// header, archive, path, checksum, key kind), [`Error::Io`] (u. a. `AlreadyExists`).
pub fn decrypt(source: &Path, target: &Path, unlock: &Unlock<'_>) -> Result<Report> {
    let mut reader = BufReader::new(File::open(source)?);
    let header = FileHeader::read(&mut reader)?;
    let file_key = unwrap_key(&header, unlock)?;
    let dec = DecryptReader::new(
        file_key.expose(),
        header.prefix,
        &header.stream_aad(),
        reader,
    )?;
    drop(file_key);
    let archive = ArchiveReader::new(dec);
    match header.content {
        Content::File => extract_file(archive, target),
        Content::Directory => extract_dir(archive, target),
    }
}

fn unwrap_key(header: &FileHeader, unlock: &Unlock<'_>) -> Result<SecretBytes> {
    let aad = header.wrap_aad();
    match (&header.mode, unlock) {
        (HeaderMode::Passphrase { params, salt }, Unlock::Passphrase(pass)) => {
            wrap::unwrap_with_passphrase(pass, params, salt, &header.wrapped, &aad)
        }
        (
            HeaderMode::Recipient {
                algorithm,
                recipient_id,
                ..
            },
            Unlock::Key(key),
        ) => {
            // DE: Früher, verständlicher Fehler, wenn der Schlüssel offensichtlich nicht passt.
            // EN: Early, clear error if the key obviously does not match.
            let matches = key.algorithm == KeyAlgorithm::Kem(*algorithm)
                && Sha3_256::digest(&key.public_key).as_slice() == recipient_id;
            if !matches {
                return Err(Error::InvalidInput { field: "recipient" });
            }
            let recipient = header
                .recipient_wrap()
                .ok_or(Error::InvalidInput { field: "header" })?;
            wrap::unwrap_for_recipient(
                *algorithm,
                key.secret().expose(),
                recipient_id,
                &recipient,
                &aad,
            )
        }
        _ => Err(Error::InvalidInput { field: "key_kind" }),
    }
}

fn extract_file<R: Read>(mut archive: ArchiveReader<R>, target: &Path) -> Result<Report> {
    let Some(Entry::File(name, size)) = archive.next_entry()? else {
        return Err(Error::InvalidInput { field: "archive" });
    };
    paths::validate(&name)?;
    let (temp, file) = TempOutput::file(target)?;
    let mut out = BufWriter::new(file);
    archive.copy_file(size, &mut out)?;
    if archive.next_entry()?.is_some() {
        return Err(Error::InvalidInput { field: "archive" });
    }
    finish_file(out)?;
    archive.finish()?;
    temp.publish()?;
    Ok(Report {
        files: 1,
        bytes: size,
        ..Report::default()
    })
}

fn extract_dir<R: Read>(mut archive: ArchiveReader<R>, target: &Path) -> Result<Report> {
    let temp = TempOutput::dir(target)?;
    let mut seen = PathSet::default();
    let mut report = Report::default();
    while let Some(entry) = archive.next_entry()? {
        match entry {
            Entry::Dir(path) => {
                let parts = paths::validate(&path)?;
                seen.insert(&parts, false)?;
                output::create_dir(temp.path(), &parts)?;
                report.directories += 1;
            }
            Entry::File(path, size) => {
                let parts = paths::validate(&path)?;
                seen.insert(&parts, true)?;
                let mut out = BufWriter::new(output::create_file(temp.path(), &parts)?);
                archive.copy_file(size, &mut out)?;
                finish_file(out)?;
                report.files += 1;
                report.bytes += size;
            }
        }
    }
    archive.finish()?;
    temp.publish()?;
    Ok(report)
}

fn finish_file(out: BufWriter<File>) -> Result<()> {
    let file = out.into_inner().map_err(|e| Error::from(e.into_error()))?;
    file.sync_all()?;
    Ok(())
}
