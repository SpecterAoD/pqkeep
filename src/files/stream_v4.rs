//! DE: Inhalt „Strom“ (Format v4, #83): Verschlüsseln aus einem beliebigen Datenstrom unbekannter
//! Länge mit konstantem Speicher, Klartext = Nutzdaten ‖ Trailer (`format_v4`). Beim Lesen hält
//! der Leser die Trailer-Bytes im gesperrten Puffer zurück, sodass sie nie in die Ausgabe gelangen;
//! erst nach Endmarke, Trailer und ggf. Signatur wird veröffentlicht. Entschlüsselt wird nur in
//! eine Datei (keine Teilausgabe, S2b verworfen).
//! EN: Content "stream" (format v4, #83): encrypting from any data stream of unknown length with
//! constant memory, plaintext = payload ‖ trailer (`format_v4`). When reading, the reader holds the
//! trailer bytes back in the locked buffer so they never reach the output; publishing happens only
//! after the last flag, the trailer and any signature. Decryption goes into a file only (no partial
//! output, S2b dropped).

use std::io::{BufWriter, Read, Write};
use std::path::Path;

use super::decrypt::{finish_file, verify};
use super::encrypt_header;
use super::format::Content;
use super::output::TempOutput;
use super::signed_io::{HashingWriter, SignatureCheck, check_signing_key};
use super::tail_v4::{TailRead, TailWrite, copy_payload, push_tail};
use super::{EncryptOptions, Protection, Report};
use crate::crypto::stream::{CHUNK_SIZE, DecryptReader, EncryptWriter, PREFIX_LEN};
use crate::crypto::{SecretBytes, aead, rng};
use crate::envelope::UnlockedKey;
use crate::{Error, Result};

/// DE: Verschlüsselt alles aus `source` bis EOF als Strom (Format v4) nach `target`; mit `signer`
/// zusätzlich sichtbar signiert (Bit SIGNED). Konstanter Speicher; `target` erhält die Bytes
/// direkt (keine Temporärdatei) – bei Abbruch bleibt eine unlesbare, nie still unvollständige Datei.
/// EN: Encrypts everything from `source` until EOF as a stream (format v4) into `target`; with
/// `signer` additionally signed visibly (bit SIGNED). Constant memory; `target` receives the bytes
/// directly (no temporary file) – on abort an unreadable, never silently incomplete file remains.
///
/// # Errors
/// DE/EN: [`Error::Io`] (u. a. `BrokenPipe`), [`Error::InvalidInput`] (Empfänger / recipient),
/// [`Error::Unsupported`] (kein ML-DSA-87 / not ML-DSA-87), [`Error::KdfParams`], [`Error::Crypto`].
pub fn encrypt_stream<W: Write>(
    source: &mut impl Read,
    target: W,
    protection: &Protection<'_>,
    signer: Option<&UnlockedKey>,
    options: EncryptOptions,
) -> Result<Report> {
    if let Some(key) = signer {
        check_signing_key(key)?;
    }
    let hidden = hidden_signer(signer, options)?;
    let file_key = aead::generate_key()?;
    let prefix = rng::array::<PREFIX_LEN>()?;
    let public = signer.map(|key| key.public_key.as_slice());
    let (header, aad) = encrypt_header::build(
        Content::Stream,
        prefix,
        protection,
        &file_key,
        (public, options),
    )?;
    let mut out = BufWriter::new(target);
    out.write_all(&header)?;
    let mut enc = EncryptWriter::new(file_key.expose(), prefix, &aad, HashingWriter::new(out))?;
    drop(file_key);
    if hidden.is_some() {
        enc.start_hash()?;
    }
    let mut buf = SecretBytes::zeroed(CHUNK_SIZE)?;
    let mut total = 0u64;
    loop {
        let n = match source.read(buf.expose_mut()) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        enc.push(&buf.expose()[..n])?;
        total = total.checked_add(n as u64).ok_or(Error::Crypto)?;
    }
    let tail = TailWrite {
        padded: options.pad,
        hidden: hidden.map(|key| (key, header.as_slice())),
    };
    push_tail(&mut enc, &tail)?;
    let body = enc.finish()?.0;
    let mut out = match signer {
        Some(key) if hidden.is_none() => body.append_signature(key, &header)?,
        _ => body.into_inner(),
    };
    out.flush()?;
    Ok(Report {
        files: 1,
        bytes: total,
        ..Report::default()
    })
}

/// DE: Signaturschlüssel für den verborgenen Absender; `hide_sender` ohne Schlüssel ist ein Fehler.
/// EN: Signing key for the hidden sender; `hide_sender` without a key is an error.
pub(super) fn hidden_signer(
    signer: Option<&UnlockedKey>,
    options: EncryptOptions,
) -> Result<Option<&UnlockedKey>> {
    match (options.hide_sender, signer) {
        (false, _) => Ok(None),
        (true, Some(key)) => Ok(Some(key)),
        (true, None) => Err(Error::InvalidInput {
            field: "hide_sender",
        }),
    }
}

/// DE: Wie [`encrypt_stream`], aber atomar in die Datei `target` (Temporärdatei, nie überschreiben).
/// EN: Like [`encrypt_stream`], but atomically into the file `target` (temporary file, never overwrite).
///
/// # Errors
/// DE/EN: wie [`encrypt_stream`]; [`Error::Io`] `AlreadyExists`.
pub fn encrypt_stream_to(
    source: &mut impl Read,
    target: &Path,
    protection: &Protection<'_>,
    signer: Option<&UnlockedKey>,
    options: EncryptOptions,
) -> Result<Report> {
    let (temp, mut file) = TempOutput::file(target)?;
    let report = encrypt_stream(source, &mut file, protection, signer, options)?;
    file.sync_all()?;
    drop(file);
    temp.publish()?;
    Ok(report)
}

/// DE: Entschlüsselt einen Strom in die Datei `target`; Veröffentlichen erst nach allen Prüfungen.
/// EN: Decrypts a stream into the file `target`; publishing only after all checks.
pub(super) fn extract<R: Read>(
    (dec, tail): (DecryptReader<R>, TailRead),
    target: &Path,
    check: Option<SignatureCheck>,
) -> Result<Report> {
    let (temp, file) = TempOutput::file(target)?;
    let mut out = file;
    let (bytes, written) = copy_payload(dec, &mut out, &tail)?;
    if written != bytes {
        out.flush()?;
        out.set_len(bytes)?;
    }
    finish_file(out)?;
    let mut report = Report {
        files: 1,
        bytes,
        ..Report::default()
    };
    verify(check, &mut report)?;
    temp.publish()?;
    Ok(report)
}
