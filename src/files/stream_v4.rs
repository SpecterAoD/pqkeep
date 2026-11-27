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
use super::format_v4::{TRAILER_LEN, check_trailer, padding_for, trailer};
use super::output::TempOutput;
use super::signed_io::{HashingWriter, SignatureCheck, check_signing_key};
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
    push_tail(&mut enc, options.pad)?;
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
    options: EncryptOptions,
) -> Result<Report> {
    let (temp, mut file) = TempOutput::file(target)?;
    let report = encrypt_stream(source, &mut file, protection, signer, options)?;
    file.sync_all()?;
    drop(file);
    temp.publish()?;
    Ok(report)
}

/// DE: Hängt Füllung (Nullbytes, PADMÉ bei `padded`) und Trailer an alles bisher Geschriebene an.
/// EN: Appends padding (zero bytes, PADMÉ with `padded`) and the trailer to everything written so far.
pub(super) fn push_tail<W: Write>(enc: &mut EncryptWriter<W>, padded: bool) -> Result<()> {
    let payload = enc.written();
    let mut pad = padding_for(payload, padded)?;
    let zeros = [0u8; 4096];
    while pad > 0 {
        let n = usize::try_from(pad.min(zeros.len() as u64)).unwrap_or(zeros.len());
        enc.push(&zeros[..n])?;
        pad -= n as u64;
    }
    enc.push(&trailer(payload, padding_for(payload, padded)?))
}

/// DE: Liest den Rest nach dem Inhalt: alles vor den letzten [`TRAILER_LEN`] Bytes geht an `out`
/// (beim Archiv nur Füllung); `zeros` zählt die Nullbytes am Ende. Liefert (Bytes vor dem
/// Trailer, Nullbytes am Ende, Trailer).
/// EN: Reads the rest after the content: everything before the last [`TRAILER_LEN`] bytes goes to
/// `out` (for archives padding only); `zeros` counts trailing zero bytes. Returns (bytes before the
/// trailer, trailing zero bytes, trailer).
fn drain<R: Read>(
    dec: &mut DecryptReader<R>,
    out: &mut impl Write,
) -> Result<(u64, u64, SecretBytes)> {
    let mut buf = SecretBytes::zeroed(CHUNK_SIZE + TRAILER_LEN)?;
    let (mut held, mut written, mut zeros) = (0usize, 0u64, 0u64);
    loop {
        let n = dec.read(&mut buf.expose_mut()[held..])?;
        if n == 0 {
            break;
        }
        held += n;
        if held > TRAILER_LEN {
            let ready = held - TRAILER_LEN;
            let part = &buf.expose()[..ready];
            out.write_all(part)?;
            zeros = match part.iter().rposition(|b| *b != 0) {
                Some(last) => (ready - last - 1) as u64,
                None => zeros + ready as u64,
            };
            written += ready as u64;
            buf.expose_mut().copy_within(ready..held, 0);
            held = TRAILER_LEN;
        }
    }
    if held != TRAILER_LEN {
        return Err(Error::InvalidInput { field: "trailer" });
    }
    Ok((
        written,
        zeros,
        SecretBytes::from_slice(&buf.expose()[..TRAILER_LEN])?,
    ))
}

/// DE: Kopiert einen Strom nach `out` (Nutzdaten und ggf. Füllung) und prüft Endmarke, Trailer und
/// Füllung (nur Nullbytes). Liefert (Nutzlänge, geschriebene Bytes); der Aufrufer kürzt auf die
/// Nutzlänge.
/// EN: Copies a stream to `out` (payload and any padding) and checks the last flag, the trailer and
/// the padding (zero bytes only). Returns (payload length, bytes written); the caller truncates to
/// the payload length.
pub(super) fn copy_payload<R: Read>(
    mut dec: DecryptReader<R>,
    out: &mut impl Write,
    padded: bool,
) -> Result<(u64, u64)> {
    let (written, zeros, tail) = drain(&mut dec, out)?;
    dec.finish()?;
    let payload = check_trailer(tail.expose(), written, padded)?;
    if zeros < written - payload {
        return Err(Error::InvalidInput { field: "padding" });
    }
    Ok((payload, written))
}

/// DE: Abschluss eines v4-Archivs: nach dem Archiv-Ende nur Nullbytes (Füllung), dann der Trailer,
/// dessen Nutzlänge genau dem Archiv entspricht.
/// EN: End of a v4 archive: after the archive end only zero bytes (padding), then the trailer whose
/// payload length equals the archive exactly.
pub(super) fn finish_tail<R: Read>(
    mut dec: DecryptReader<R>,
    archive_len: u64,
    padded: bool,
) -> Result<()> {
    let (pad, zeros, tail) = drain(&mut dec, &mut std::io::sink())?;
    dec.finish()?;
    let total = archive_len.checked_add(pad).ok_or(Error::Decrypt)?;
    if zeros != pad || check_trailer(tail.expose(), total, padded)? != archive_len {
        return Err(Error::InvalidInput { field: "padding" });
    }
    Ok(())
}

/// DE: Entschlüsselt einen Strom in die Datei `target`; Veröffentlichen erst nach allen Prüfungen.
/// EN: Decrypts a stream into the file `target`; publishing only after all checks.
pub(super) fn extract<R: Read>(
    (dec, padded): (DecryptReader<R>, bool),
    target: &Path,
    check: Option<SignatureCheck>,
) -> Result<Report> {
    let (temp, file) = TempOutput::file(target)?;
    let mut out = file;
    let (bytes, written) = copy_payload(dec, &mut out, padded)?;
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

#[cfg(test)]
#[path = "stream_v4_tests.rs"]
mod stream_v4_tests;
