//! DE: Verschlüsseln einer Datei oder eines Ordners nach `ziel` (atomar, ohne
//! Überschreiben). Pro Vorgang neuer Dateischlüssel und neues Nonce-Präfix.
//! EN: Encrypting a file or directory into `target` (atomic, no overwriting).
//! Fresh file key and nonce prefix for every operation.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use super::archive::ArchiveWriter;
use super::encrypt_header;
use super::format::Content;
use super::output::TempOutput;
use super::signed_io::{HashingWriter, check_signing_key};
use super::walk::{self, SourceEntry, SourceKind};
use super::{Protection, Report};
use crate::crypto::stream::{EncryptWriter, PREFIX_LEN};
use crate::crypto::{aead, rng};
use crate::envelope::UnlockedKey;
use crate::{Error, Result};

/// DE: Verschlüsselt `source` (Datei oder Ordner) nach `target`.
/// EN: Encrypts `source` (file or directory) into `target`.
///
/// # Errors
/// DE/EN: [`Error::Io`] (u. a. `AlreadyExists`), [`Error::InvalidInput`] (Quelle, Empfänger,
/// geänderte Quelldatei / source, recipient, changed source file), [`Error::KdfParams`].
pub fn encrypt(source: &Path, target: &Path, protection: &Protection<'_>) -> Result<Report> {
    encrypt_with(source, target, protection, None)
}

/// DE: Wie [`encrypt`], zusätzlich mit der Absender-Signatur von `signer` (ML-DSA-87; Format v3,
/// `docs/V3_SIGNED.md`).
/// EN: Like [`encrypt`], additionally with the sender signature of `signer` (ML-DSA-87; format
/// v3, `docs/V3_SIGNED.md`).
///
/// # Errors
/// DE/EN: wie [`encrypt`]; [`Error::Unsupported`] (kein ML-DSA-87-Schlüssel / not ML-DSA-87),
/// [`Error::Crypto`].
pub fn encrypt_signed(
    source: &Path,
    target: &Path,
    protection: &Protection<'_>,
    signer: &UnlockedKey,
) -> Result<Report> {
    check_signing_key(signer)?;
    encrypt_with(source, target, protection, Some(signer))
}

fn encrypt_with(
    source: &Path,
    target: &Path,
    protection: &Protection<'_>,
    signer: Option<&UnlockedKey>,
) -> Result<Report> {
    let is_dir = fs::symlink_metadata(source)?.file_type().is_dir();
    let (entries, skipped, content) = if is_dir {
        let (e, s) = walk::collect_dir(source)?;
        (e, s, Content::Directory)
    } else {
        (vec![walk::collect_file(source)?], Vec::new(), Content::File)
    };
    write_archive(&entries, skipped, content, target, protection, signer)
}

/// DE: Verschlüsselt mehrere Quellen als **einen** Container nach `target` (Inhalt „Ordner“,
/// oberste Einträge = Quellen; kein neues Format). Entschlüsselt entsteht ein Ordner.
/// EN: Encrypts several sources as **one** container into `target` (content "directory",
/// top-level entries = sources; no new format). Decrypting yields a directory.
///
/// # Errors
/// DE/EN: wie [`encrypt`]; zusätzlich [`Error::InvalidInput`] mit `duplicate` (gleiche Namen) /
/// as [`encrypt`]; additionally `duplicate` (equal names).
pub fn encrypt_many(
    sources: &[&Path],
    target: &Path,
    protection: &Protection<'_>,
) -> Result<Report> {
    encrypt_many_with(sources, target, protection, None)
}

/// DE: Wie [`encrypt_many`], zusätzlich mit Absender-Signatur (Format v3).
/// EN: Like [`encrypt_many`], additionally with sender signature (format v3).
///
/// # Errors
/// DE/EN: wie [`encrypt_many`] und [`encrypt_signed`] / as [`encrypt_many`] and [`encrypt_signed`].
pub fn encrypt_many_signed(
    sources: &[&Path],
    target: &Path,
    protection: &Protection<'_>,
    signer: &UnlockedKey,
) -> Result<Report> {
    check_signing_key(signer)?;
    encrypt_many_with(sources, target, protection, Some(signer))
}

fn encrypt_many_with(
    sources: &[&Path],
    target: &Path,
    protection: &Protection<'_>,
    signer: Option<&UnlockedKey>,
) -> Result<Report> {
    let (entries, skipped) = walk::collect_many(sources)?;
    write_archive(
        &entries,
        skipped,
        Content::Directory,
        target,
        protection,
        signer,
    )
}

/// DE: Mehrere Quellen als ein Container, alles unter dem obersten Ordner `root` (#315: der
/// Containername bleibt bei zufälligem äußerem Namen im Archiv erhalten); mit `signer` Format v3.
/// EN: Several sources as one container, everything below the top-level directory `root` (#315:
/// the container name is kept in the archive with a random outer name); with `signer` format v3.
///
/// # Errors
/// DE/EN: wie [`encrypt_many`] und [`encrypt_signed`]; [`Error::InvalidInput`] `path` (`root` kein
/// einzelner portabler Name / not a single portable name).
pub fn encrypt_many_under(
    sources: &[&Path],
    root: &str,
    target: &Path,
    protection: &Protection<'_>,
    signer: Option<&UnlockedKey>,
) -> Result<Report> {
    if let Some(key) = signer {
        check_signing_key(key)?;
    }
    let (entries, skipped) = walk::collect_under(sources, root)?;
    write_archive(
        &entries,
        skipped,
        Content::Directory,
        target,
        protection,
        signer,
    )
}

fn write_archive(
    entries: &[SourceEntry],
    skipped: Vec<super::Skipped>,
    content: Content,
    target: &Path,
    protection: &Protection<'_>,
    signer: Option<&UnlockedKey>,
) -> Result<Report> {
    let file_key = aead::generate_key()?;
    let prefix = rng::array::<PREFIX_LEN>()?;
    let public = signer.map(|key| key.public_key.as_slice());
    let (header, stream_aad) =
        encrypt_header::build(content, prefix, protection, &file_key, public)?;

    let (temp, file) = TempOutput::file(target)?;
    let mut out = BufWriter::new(file);
    out.write_all(&header)?;
    let enc = EncryptWriter::new(
        file_key.expose(),
        prefix,
        &stream_aad,
        HashingWriter::new(out),
    )?;
    drop(file_key);
    let mut archive = ArchiveWriter::new(enc)?;
    let mut report = Report {
        skipped,
        ..Report::default()
    };
    for entry in entries {
        write_entry(&mut archive, entry, &mut report)?;
    }
    let body = archive.finish()?;
    // DE: Ohne Absender bleibt die Datei Byte für Byte wie bisher (`H ‖ C`).
    // EN: Without a sender the file stays byte for byte as before (`H ‖ C`).
    let out = match signer {
        Some(key) => body.append_signature(key, &header)?,
        None => body.into_inner(),
    };
    let file = out.into_inner().map_err(|e| Error::from(e.into_error()))?;
    file.sync_all()?;
    drop(file);
    temp.publish()?;
    Ok(report)
}

fn write_entry<W: Write>(
    archive: &mut ArchiveWriter<W>,
    entry: &SourceEntry,
    report: &mut Report,
) -> Result<()> {
    match entry.kind {
        SourceKind::Dir => {
            archive.dir(&entry.rel)?;
            report.directories += 1;
        }
        SourceKind::File(size) => {
            let mut reader = File::open(&entry.abs)?;
            archive.file(&entry.rel, &mut reader, size)?;
            report.files += 1;
            report.bytes += size;
        }
    }
    Ok(())
}
