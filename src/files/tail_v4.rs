//! DE: Abschluss-Block (Trailer) des Formats v4 (`docs/V4_DRAFT.md`): Füllung nach PADMÉ (`PAD`),
//! optional verborgener Absender (`HIDDEN_SENDER`) und `U64 Nutzlänge ‖ U64 Füllung ‖ PQKFEND`.
//! Beim Schreiben werden Füllung, ggf. Absenderblock und Trailer angehängt; beim Lesen hält der Leser
//! die Trailer-Bytes im gesperrten Puffer zurück, prüft Füllung (nur Nullbytes, kanonische Länge),
//! Längen und – beim verborgenen Absender – die Signatur über Header, Klartext und beide Längen.
//! EN: Trailer of format v4: PADMÉ padding (`PAD`), optional hidden sender (`HIDDEN_SENDER`) and
//! `U64 payload ‖ U64 padding ‖ PQKFEND`. Writing appends padding, the optional sender block and the
//! trailer; reading holds the trailer bytes back in the locked buffer and checks padding (zero bytes,
//! canonical length), lengths and – for a hidden sender – the signature over header, plaintext and
//! both lengths.

use std::io::{Read, Write};

use super::format_v4::{
    HIDDEN_BLOCK_LEN, TRAILER_LEN, check_trailer, hidden_message, padding_for, trailer, trailer_len,
};
use super::signed_io::{HiddenResult, SignedBy};
use super::signer_v3::{FILE_SIG_CONTEXT, SIGNER_DSA, SIGNER_KEY_LEN, SIGNER_ML_DSA_87};
use super::tail_v4_drain::{Drained, drain};
use crate::crypto::dsa;
use crate::crypto::stream::PlainHash;
use crate::crypto::stream::{DecryptReader, EncryptWriter};
use crate::envelope::UnlockedKey;
use crate::{Error, Result};

/// DE: Trailer beim Schreiben. EN: Trailer when writing.
pub(crate) struct TailWrite<'a> {
    /// DE: Füllung nach PADMÉ. EN: PADMÉ padding.
    pub padded: bool,
    /// DE: Verborgener Absender: Schlüssel und kodierter Header. EN: Hidden sender: key and header.
    pub hidden: Option<(&'a UnlockedKey, &'a [u8])>,
}

/// DE: Trailer beim Lesen. EN: Trailer when reading.
#[derive(Default)]
pub(crate) struct TailRead {
    /// DE: Füllung nach PADMÉ erwartet. EN: PADMÉ padding expected.
    pub padded: bool,
    /// DE: Verborgener Absender: kodierter Header und Ergebnis. EN: Hidden sender: header and result.
    pub hidden: Option<(Vec<u8>, HiddenResult)>,
}

/// DE: Füllung, ggf. Absenderblock und Trailer anhängen. Beim verborgenen Absender muss der
/// Schreiber seit dem Anfang hashen (`start_hash`).
/// EN: Append padding, the optional sender block and the trailer. For a hidden sender the writer
/// must hash from the start (`start_hash`).
pub(crate) fn push_tail<W: Write>(enc: &mut EncryptWriter<W>, tail: &TailWrite<'_>) -> Result<()> {
    let payload = enc.written();
    let pad = padding_for(payload, tail.padded, trailer_len(tail.hidden.is_some()))?;
    let zeros = [0u8; 4096];
    let mut left = pad;
    while left > 0 {
        let n = usize::try_from(left.min(zeros.len() as u64)).unwrap_or(zeros.len());
        enc.push(&zeros[..n])?;
        left -= n as u64;
    }
    if let Some((key, header)) = tail.hidden {
        let hash = enc.take_hash().ok_or(Error::Crypto)?.finalize()?;
        let msg = hidden_message(header, hash.expose(), payload, pad)?;
        let sig = dsa::sign_confidential(
            SIGNER_DSA,
            key.secret().expose(),
            msg.expose(),
            FILE_SIG_CONTEXT,
        )?;
        // DE: Gegenprobe wie bei v3. EN: Cross-check as in v3.
        if !dsa::verify_confidential(
            SIGNER_DSA,
            &key.public_key,
            msg.expose(),
            FILE_SIG_CONTEXT,
            sig.expose(),
        )? {
            return Err(Error::Crypto);
        }
        enc.push(&[SIGNER_ML_DSA_87])?;
        enc.push(&key.public_key)?;
        enc.push(sig.expose())?;
    }
    enc.push(trailer(payload, pad)?.expose())
}

/// DE: Prüft Trailer, Füllung und ggf. den verborgenen Absender; liefert die Nutzlänge.
/// EN: Checks trailer, padding and the optional hidden sender; returns the payload length.
fn check_tail(d: &Drained, before: u64, tail: &TailRead, hash: Option<PlainHash>) -> Result<u64> {
    let bytes = d.bytes()?;
    let (block, end) = bytes.split_at(bytes.len() - TRAILER_LEN);
    let total = before.checked_add(d.written()).ok_or(Error::Decrypt)?;
    let payload = check_trailer(end, total, tail.padded, bytes.len())?;
    let pad = total - payload;
    if d.zeros() < pad.min(d.written()) || payload < before {
        return Err(Error::InvalidInput { field: "padding" });
    }
    if let Some((header, result)) = &tail.hidden {
        let hash = hash.ok_or(Error::Crypto)?.finalize()?;
        result.store(hidden_sender(block, header, hash.expose(), payload, pad)?);
    }
    Ok(payload)
}

/// DE: Prüft den verborgenen Absender. EN: Verifies the hidden sender.
fn hidden_sender(
    block: &[u8],
    header: &[u8],
    hash: &[u8],
    payload: u64,
    pad: u64,
) -> Result<SignedBy> {
    if block.len() != HIDDEN_BLOCK_LEN {
        return Err(Error::InvalidInput { field: "trailer" });
    }
    if block[0] != SIGNER_ML_DSA_87 {
        return Err(Error::Unsupported);
    }
    let (key, sig) = block[1..].split_at(SIGNER_KEY_LEN);
    let msg = hidden_message(header, hash, payload, pad)?;
    if !dsa::verify_confidential(SIGNER_DSA, key, msg.expose(), FILE_SIG_CONTEXT, sig)? {
        return Err(Error::InvalidSignature);
    }
    SignedBy::from_public_key(key)
}

/// DE: Strom: Nutzdaten (und Füllung) nach `out`, dann Prüfung. Liefert (Nutzlänge, geschrieben);
/// der Aufrufer kürzt auf die Nutzlänge.
/// EN: Stream: payload (and padding) to `out`, then checks. Returns (payload, written); the caller
/// truncates to the payload length.
pub(crate) fn copy_payload<R: Read>(
    mut dec: DecryptReader<R>,
    out: &mut impl Write,
    tail: &TailRead,
) -> Result<(u64, u64)> {
    let mut hash = dec.take_hash();
    let hold = trailer_len(tail.hidden.is_some());
    let d = drain(&mut dec, out, hold, hash.as_mut())?;
    dec.finish()?;
    let payload = check_tail(&d, 0, tail, hash)?;
    Ok((payload, d.written()))
}

/// DE: Archiv: nach dem Archiv-Ende nur Nullbytes, dann der Trailer mit genau der Archivlänge.
/// EN: Archive: after the archive end only zero bytes, then the trailer with exactly the archive length.
pub(crate) fn finish_tail<R: Read>(
    mut dec: DecryptReader<R>,
    archive_len: u64,
    tail: &TailRead,
) -> Result<()> {
    let mut hash = dec.take_hash();
    let hold = trailer_len(tail.hidden.is_some());
    let d = drain(&mut dec, &mut std::io::sink(), hold, hash.as_mut())?;
    dec.finish()?;
    if d.zeros() != d.written() {
        return Err(Error::InvalidInput { field: "padding" });
    }
    if check_tail(&d, archive_len, tail, hash)? != archive_len {
        return Err(Error::InvalidInput { field: "padding" });
    }
    Ok(())
}

#[cfg(test)]
#[path = "tail_v4_tests.rs"]
mod tail_v4_tests;
