//! DE: Verschlüsseln einer Datei oder eines Ordners nach `ziel` (atomar, ohne
//! Überschreiben). Pro Vorgang neuer Dateischlüssel und neues Nonce-Präfix.
//! EN: Encrypting a file or directory into `target` (atomic, no overwriting).
//! Fresh file key and nonce prefix for every operation.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use super::archive::ArchiveWriter;
use super::encrypt_v2;
use super::format::{Content, FileHeader, HeaderMode};
use super::output::TempOutput;
use super::walk::{self, SourceEntry, SourceKind};
use super::{PassphraseAccess, Protection, Report};
use crate::crypto::kdf::KdfParams;
use crate::crypto::kdf::SALT_LEN;
use crate::crypto::stream::{EncryptWriter, PREFIX_LEN};
use crate::crypto::wrap::{self, Wrapped};
use crate::crypto::{KeyAlgorithm, SecretBytes, aead, rng};
use crate::envelope::{KEY_ID_LEN, PublicKeyFile};
use crate::security::StrongPassphrase;
use crate::{Error, Result};

/// DE: Verschlüsselt `source` (Datei oder Ordner) nach `target`.
/// EN: Encrypts `source` (file or directory) into `target`.
///
/// # Errors
/// DE/EN: [`Error::Io`] (u. a. `AlreadyExists`), [`Error::InvalidInput`] (Quelle, Empfänger,
/// geänderte Quelldatei / source, recipient, changed source file), [`Error::KdfParams`].
pub fn encrypt(source: &Path, target: &Path, protection: &Protection<'_>) -> Result<Report> {
    let is_dir = fs::symlink_metadata(source)?.file_type().is_dir();
    let (entries, skipped, content) = if is_dir {
        let (e, s) = walk::collect_dir(source)?;
        (e, s, Content::Directory)
    } else {
        (vec![walk::collect_file(source)?], Vec::new(), Content::File)
    };
    write_archive(&entries, skipped, content, target, protection)
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
    let (entries, skipped) = walk::collect_many(sources)?;
    write_archive(&entries, skipped, Content::Directory, target, protection)
}

fn write_archive(
    entries: &[SourceEntry],
    skipped: Vec<super::Skipped>,
    content: Content,
    target: &Path,
    protection: &Protection<'_>,
) -> Result<Report> {
    let file_key = aead::generate_key()?;
    let prefix = rng::array::<PREFIX_LEN>()?;
    let (header, stream_aad) = build_header(content, prefix, protection, &file_key)?;

    let (temp, file) = TempOutput::file(target)?;
    let mut out = BufWriter::new(file);
    out.write_all(&header)?;
    let enc = EncryptWriter::new(file_key.expose(), prefix, &stream_aad, out)?;
    drop(file_key);
    let mut archive = ArchiveWriter::new(enc);
    let mut report = Report {
        skipped,
        ..Report::default()
    };
    for entry in entries {
        write_entry(&mut archive, entry, &mut report)?;
    }
    let file = archive
        .finish()?
        .into_inner()
        .map_err(|e| Error::from(e.into_error()))?;
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
            let mut reader = BufReader::new(File::open(&entry.abs)?);
            archive.file(&entry.rel, &mut reader, size)?;
            report.files += 1;
            report.bytes += size;
        }
    }
    Ok(())
}

/// DE: Kodierter Header und Strom-AAD. Schreibt v1, wenn ein einzelner Zugang ohne Faktordatei
/// genügt (ältere Versionen bleiben lesefähig), sonst v2.
/// EN: Encoded header and stream AAD. Writes v1 if a single slot without factor file suffices
/// (older versions can still read it), else v2.
fn build_header(
    content: Content,
    prefix: [u8; PREFIX_LEN],
    protection: &Protection<'_>,
    file_key: &SecretBytes,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let v1 = match protection {
        Protection::Passphrase { passphrase, params }
        | Protection::Slots {
            passphrase:
                Some(PassphraseAccess {
                    passphrase,
                    params,
                    factor: None,
                }),
            recipients: [],
        } => passphrase_header(content, prefix, passphrase, params, file_key)?,
        Protection::Recipient(key)
        | Protection::Slots {
            passphrase: None,
            recipients: [key],
        } => recipient_header(content, prefix, key, file_key)?,
        Protection::Slots {
            passphrase,
            recipients,
        } => {
            let header =
                encrypt_v2::build(content, prefix, passphrase.as_ref(), recipients, file_key)?;
            return Ok((header.encode()?, header.stream_aad()?));
        }
    };
    Ok((v1.encode(), v1.stream_aad()))
}

fn placeholder() -> Wrapped {
    Wrapped {
        nonce: [0; 12],
        ciphertext: Vec::new(),
    }
}

fn passphrase_header(
    content: Content,
    prefix: [u8; PREFIX_LEN],
    passphrase: &StrongPassphrase,
    params: &KdfParams,
    file_key: &SecretBytes,
) -> Result<FileHeader> {
    let salt = rng::array::<SALT_LEN>()?.to_vec();
    let mut header = FileHeader {
        content,
        prefix,
        mode: HeaderMode::Passphrase {
            params: *params,
            salt: salt.clone(),
        },
        wrapped: placeholder(),
    };
    let aad = header.wrap_aad();
    header.wrapped =
        wrap::wrap_with_passphrase(passphrase, params, &salt, file_key.expose(), &aad)?;
    Ok(header)
}

fn recipient_header(
    content: Content,
    prefix: [u8; PREFIX_LEN],
    key: &PublicKeyFile,
    file_key: &SecretBytes,
) -> Result<FileHeader> {
    let KeyAlgorithm::Kem(algorithm) = key.algorithm() else {
        return Err(Error::InvalidInput { field: "recipient" });
    };
    let recipient_id: [u8; KEY_ID_LEN] = key
        .key_id()
        .try_into()
        .map_err(|_| Error::InvalidInput { field: "recipient" })?;
    let mut header = FileHeader {
        content,
        prefix,
        mode: HeaderMode::Recipient {
            algorithm,
            recipient_id,
            kem_ciphertext: Vec::new(),
        },
        wrapped: placeholder(),
    };
    // DE: AAD ohne KEM-Chiffrat; dieses ist über HKDF (Salt) gebunden.
    // EN: AAD without the KEM ciphertext; it is bound via HKDF (salt).
    let aad = header.wrap_aad();
    let r = wrap::wrap_for_recipient(
        algorithm,
        key.public_key(),
        &recipient_id,
        file_key.expose(),
        &aad,
    )?;
    header.mode = HeaderMode::Recipient {
        algorithm,
        recipient_id,
        kem_ciphertext: r.kem_ciphertext,
    };
    header.wrapped = r.wrapped;
    Ok(header)
}
