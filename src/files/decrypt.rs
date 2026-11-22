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
use std::io::{BufReader, BufWriter, Chain, Cursor, Read};
use std::path::Path;

use sha3::{Digest, Sha3_256};

use super::archive::{ArchiveReader, Entry};
use super::decrypt_v2;
use super::format::{Content, FileHeader, HeaderMode, MAGIC};
use super::format_v2::{self, HeaderV2};
use super::output::{self, TempOutput};
use super::paths::{self, PathSet};
use super::signed_io::{self, Body, SignatureCheck, SignedBody};
use super::signer_v3::{FILE_SIGNATURE_LEN, check_commit};
use super::{Report, Unlock};
use crate::crypto::stream::{DecryptReader, PREFIX_LEN, read_full};
use crate::crypto::wrap;
use crate::crypto::{KeyAlgorithm, SecretBytes};
use crate::envelope::PublicKeyFile;
use crate::{Error, Result};

/// DE: Entschlüsselt `source` nach `target` (Datei bzw. Ordner laut Header).
/// EN: Decrypts `source` into `target` (file or directory per header).
///
/// # Errors
/// DE/EN: [`Error::Decrypt`] (falscher Schlüssel/Manipulation / wrong key/tampering),
/// [`Error::InvalidInput`] (Header, Archiv, Pfad, Prüfsumme, Schlüsselart, Faktordatei /
/// header, archive, path, checksum, key kind, factor file), [`Error::Unsupported`]
/// (Version, Zugangstyp / version, slot type), [`Error::Io`] (u. a. `AlreadyExists`).
pub fn decrypt(source: &Path, target: &Path, unlock: &Unlock<'_>) -> Result<Report> {
    decrypt_with(source, target, unlock, None)
}

/// DE: Wie [`decrypt`]; mit `signer` muss die Datei von genau diesem Absender signiert sein
/// (Format v3, geprüft vor jeder Ableitung). Signierte Dateien werden immer geprüft; der Bericht
/// nennt den Absender.
/// EN: Like [`decrypt`]; with `signer` the file must be signed by exactly this sender (format v3,
/// checked before any derivation). Signed files are always verified; the report names the sender.
///
/// # Errors
/// DE/EN: wie [`decrypt`]; [`Error::InvalidSignature`] (unsigniert, anderer Absender, Signatur
/// ungültig / unsigned, other sender, invalid signature).
pub fn decrypt_with(
    source: &Path,
    target: &Path,
    unlock: &Unlock<'_>,
    signer: Option<&PublicKeyFile>,
) -> Result<Report> {
    let (archive, content, check) = open(source, unlock, signer)?;
    match content {
        Content::File => extract_file(archive, target, check),
        Content::Directory => extract_dir(archive, target, check),
    }
}

/// DE: Quelle nach dem Vorlesen von Magic und Version. EN: Source after pre-reading magic/version.
pub(super) type Source = Body<Chain<Cursor<Vec<u8>>, BufReader<File>>>;

/// DE: Prüft die Signatur (falls vorhanden) – vor dem Veröffentlichen aufrufen.
/// EN: Verifies the signature (if any) – call before publishing.
pub(super) fn verify(check: Option<SignatureCheck>, report: &mut Report) -> Result<()> {
    if let Some(check) = check {
        report.signer = Some(check.verify()?);
    }
    Ok(())
}

/// DE: Öffnet `source`: Header lesen, Dateischlüssel entsperren, Strom vorbereiten. Gemeinsam
/// für `decrypt` und `check`.
/// EN: Opens `source`: read the header, unlock the file key, prepare the stream. Shared by
/// `decrypt` and `check`.
pub(super) fn open(
    source: &Path,
    unlock: &Unlock<'_>,
    signer: Option<&PublicKeyFile>,
) -> Result<(ArchiveReader<Source>, Content, Option<SignatureCheck>)> {
    let mut file = BufReader::new(File::open(source)?);
    let file_len = file.get_ref().metadata()?.len();
    // DE: Magic und Version vorab lesen und dem passenden Parser wieder voranstellen.
    // EN: Read magic and version up front and put them back in front of the matching parser.
    let mut start = [0u8; MAGIC.len() + 2];
    let filled = read_full(&mut file, &mut start)?;
    let is_v2 = is_v2(&start[..filled]);
    let mut reader = Cursor::new(start[..filled].to_vec()).chain(file);
    let mut check = None;
    let opened = if is_v2 {
        let header = HeaderV2::read(&mut reader)?;
        signed_io::require(signer, header.signer.as_ref())?;
        let file_key = decrypt_v2::unwrap_key(&header, unlock)?;
        if let Some(s) = &header.signer {
            check_commit(s, file_key.expose())?;
            let bytes = header.encode()?;
            let fixed = (bytes.len() + FILE_SIGNATURE_LEN) as u64;
            let body_len = file_len.checked_sub(fixed).ok_or(Error::Decrypt)?;
            check = Some((SignatureCheck::new(bytes, s.clone()), body_len));
        }
        Opened {
            file_key,
            stream_aad: header.stream_aad()?,
            prefix: header.prefix,
            content: header.content,
        }
    } else {
        signed_io::require(signer, None)?;
        let header = FileHeader::read(&mut reader)?;
        Opened {
            file_key: unwrap_key(&header, unlock)?,
            stream_aad: header.stream_aad(),
            prefix: header.prefix,
            content: header.content,
        }
    };
    let (body, check) = match check {
        Some((c, len)) => (Body::Signed(SignedBody::new(reader, len, &c)), Some(c)),
        None => (Body::Plain(reader), None),
    };
    let dec = DecryptReader::new(
        opened.file_key.expose(),
        opened.prefix,
        &opened.stream_aad,
        body,
    )?;
    drop(opened.file_key);
    Ok((ArchiveReader::new(dec), opened.content, check))
}

/// DE: Was nach dem Header für den Strom nötig ist. EN: What the stream needs after the header.
struct Opened {
    file_key: SecretBytes,
    stream_aad: Vec<u8>,
    prefix: [u8; PREFIX_LEN],
    content: Content,
}

/// DE: Nur Magic + Version 2 oder 3 führt zum v2-Parser; alles andere prüft der v1-Parser wie
/// bisher (unbekannte Version = „nicht unterstützt“).
/// EN: Only magic + version 2 or 3 leads to the v2 parser; everything else is checked by the v1
/// parser as before (unknown version = "unsupported").
fn is_v2(start: &[u8]) -> bool {
    [format_v2::VERSION, format_v2::VERSION_SIGNED]
        .iter()
        .any(|v| start.strip_prefix(MAGIC) == Some(&v.to_le_bytes()[..]))
}

fn unwrap_key(header: &FileHeader, unlock: &Unlock<'_>) -> Result<SecretBytes> {
    let aad = header.wrap_aad();
    match (&header.mode, unlock) {
        // DE: v1 kennt keine Faktordatei; nie still ignorieren. EN: v1 has no factor file.
        (_, Unlock::PassphraseWithFactor { .. }) => Err(Error::InvalidInput {
            field: "factor_unused",
        }),
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

fn extract_file<R: Read>(
    mut archive: ArchiveReader<R>,
    target: &Path,
    check: Option<SignatureCheck>,
) -> Result<Report> {
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
    let mut report = Report {
        files: 1,
        bytes: size,
        ..Report::default()
    };
    verify(check, &mut report)?;
    temp.publish()?;
    Ok(report)
}

fn extract_dir<R: Read>(
    mut archive: ArchiveReader<R>,
    target: &Path,
    check: Option<SignatureCheck>,
) -> Result<Report> {
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
    verify(check, &mut report)?;
    temp.publish()?;
    Ok(report)
}

fn finish_file(out: BufWriter<crate::fsutil::OutputFile>) -> Result<()> {
    let file = out.into_inner().map_err(|e| Error::from(e.into_error()))?;
    file.sync_all()?;
    Ok(())
}
