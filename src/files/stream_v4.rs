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
use super::format_v4::{TRAILER_LEN, check_trailer, trailer};
use super::output::TempOutput;
use super::signed_io::{HashingWriter, SignatureCheck, check_signing_key};
use super::{Protection, Report};
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
) -> Result<Report> {
    if let Some(key) = signer {
        check_signing_key(key)?;
    }
    let file_key = aead::generate_key()?;
    let prefix = rng::array::<PREFIX_LEN>()?;
    let public = signer.map(|key| key.public_key.as_slice());
    let (header, aad) =
        encrypt_header::build(Content::Stream, prefix, protection, &file_key, public)?;
    let mut out = BufWriter::new(target);
    out.write_all(&header)?;
    let mut enc = EncryptWriter::new(file_key.expose(), prefix, &aad, HashingWriter::new(out))?;
    drop(file_key);
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
    enc.push(&trailer(total))?;
    let body = enc.finish()?.0;
    let mut out = match signer {
        Some(key) => body.append_signature(key, &header)?,
        None => body.into_inner(),
    };
    out.flush()?;
    Ok(Report {
        files: 1,
        bytes: total,
        ..Report::default()
    })
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
) -> Result<Report> {
    let (temp, mut file) = TempOutput::file(target)?;
    let report = encrypt_stream(source, &mut file, protection, signer)?;
    file.sync_all()?;
    drop(file);
    temp.publish()?;
    Ok(report)
}

/// DE: Kopiert die Nutzdaten nach `out` und hält die letzten [`TRAILER_LEN`] Bytes zurück; prüft
/// danach Endmarke und Trailer. Liefert die Nutzlänge.
/// EN: Copies the payload to `out`, holding back the last [`TRAILER_LEN`] bytes; then checks the
/// last flag and the trailer. Returns the payload length.
pub(super) fn copy_payload<R: Read>(
    mut dec: DecryptReader<R>,
    out: &mut impl Write,
) -> Result<u64> {
    let mut buf = SecretBytes::zeroed(CHUNK_SIZE + TRAILER_LEN)?;
    let (mut held, mut written) = (0usize, 0u64);
    loop {
        let n = dec.read(&mut buf.expose_mut()[held..])?;
        if n == 0 {
            break;
        }
        held += n;
        if held > TRAILER_LEN {
            let ready = held - TRAILER_LEN;
            out.write_all(&buf.expose()[..ready])?;
            written += ready as u64;
            buf.expose_mut().copy_within(ready..held, 0);
            held = TRAILER_LEN;
        }
    }
    dec.finish()?;
    if held != TRAILER_LEN {
        return Err(Error::InvalidInput { field: "trailer" });
    }
    check_trailer(&buf.expose()[..TRAILER_LEN], written)?;
    Ok(written)
}

/// DE: Entschlüsselt einen Strom in die Datei `target`; Veröffentlichen erst nach allen Prüfungen.
/// EN: Decrypts a stream into the file `target`; publishing only after all checks.
pub(super) fn extract<R: Read>(
    dec: DecryptReader<R>,
    target: &Path,
    check: Option<SignatureCheck>,
) -> Result<Report> {
    let (temp, file) = TempOutput::file(target)?;
    let mut out = file;
    let bytes = copy_payload(dec, &mut out)?;
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

#[cfg(test)]
#[path = "stream_v4_tests.rs"]
mod stream_v4_tests;
