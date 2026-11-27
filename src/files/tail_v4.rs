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
use super::signer_v3::{FILE_SIG_CONTEXT, SIGNER_DSA, SIGNER_KEY_LEN, SIGNER_ML_DSA_87, Signer};
use crate::crypto::stream::PlainHash;
use crate::crypto::stream::{CHUNK_SIZE, DecryptReader, EncryptWriter};
use crate::crypto::{SecretBytes, dsa};
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
        let sig = dsa::sign(
            SIGNER_DSA,
            key.secret().expose(),
            msg.expose(),
            FILE_SIG_CONTEXT,
        )?;
        // DE: Gegenprobe wie bei v3. EN: Cross-check as in v3.
        if !dsa::verify(
            SIGNER_DSA,
            &key.public_key,
            msg.expose(),
            FILE_SIG_CONTEXT,
            &sig,
        ) {
            return Err(Error::Crypto);
        }
        enc.push(&[SIGNER_ML_DSA_87])?;
        enc.push(&key.public_key)?;
        enc.push(&sig)?;
    }
    enc.push(&trailer(payload, pad))
}

/// DE: Was `drain` gelesen hat. EN: What `drain` has read.
struct Drained {
    /// DE: Bytes vor dem Trailer. EN: Bytes before the trailer.
    written: u64,
    /// DE: Nullbytes am Ende davon. EN: Trailing zero bytes of those.
    zeros: u64,
    /// DE: Zurückgehaltener Trailer. EN: Held-back trailer.
    tail: SecretBytes,
}

/// DE: Liest den Rest: alles vor den letzten `hold` Bytes geht an `out` und (falls vorhanden) in
/// `hash`. EN: Reads the rest: everything before the last `hold` bytes goes to `out` and `hash`.
fn drain<R: Read>(
    dec: &mut DecryptReader<R>,
    out: &mut impl Write,
    holdback: usize,
    mut hash: Option<&mut PlainHash>,
) -> Result<Drained> {
    let mut buf = SecretBytes::zeroed(CHUNK_SIZE + holdback)?;
    let (mut held, mut written, mut zeros) = (0usize, 0u64, 0u64);
    loop {
        let n = dec.read(&mut buf.expose_mut()[held..])?;
        if n == 0 {
            break;
        }
        held += n;
        if held > holdback {
            let ready = held - holdback;
            let part = &buf.expose()[..ready];
            out.write_all(part)?;
            if let Some(h) = hash.as_deref_mut() {
                h.update(part);
            }
            zeros = match part.iter().rposition(|b| *b != 0) {
                Some(last) => (ready - last - 1) as u64,
                None => zeros + ready as u64,
            };
            written += ready as u64;
            buf.expose_mut().copy_within(ready..held, 0);
            held = holdback;
        }
    }
    if held != holdback {
        return Err(Error::InvalidInput { field: "trailer" });
    }
    let tail = SecretBytes::from_slice(&buf.expose()[..holdback])?;
    Ok(Drained {
        written,
        zeros,
        tail,
    })
}

/// DE: Prüft Trailer, Füllung und ggf. den verborgenen Absender; liefert die Nutzlänge.
/// EN: Checks trailer, padding and the optional hidden sender; returns the payload length.
fn check_tail(d: &Drained, before: u64, tail: &TailRead, hash: Option<PlainHash>) -> Result<u64> {
    let bytes = d.tail.expose();
    let (block, end) = bytes.split_at(bytes.len() - TRAILER_LEN);
    let total = before.checked_add(d.written).ok_or(Error::Decrypt)?;
    let payload = check_trailer(end, total, tail.padded, bytes.len())?;
    let pad = total - payload;
    if d.zeros < pad.min(d.written) || payload < before {
        return Err(Error::InvalidInput { field: "padding" });
    }
    if let Some((header, result)) = &tail.hidden {
        let hash = hash.ok_or(Error::Crypto)?.finalize()?;
        *result.borrow_mut() = Some(hidden_sender(block, header, hash.expose(), payload, pad)?);
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
    if !dsa::verify(SIGNER_DSA, key, msg.expose(), FILE_SIG_CONTEXT, sig) {
        return Err(Error::InvalidSignature);
    }
    let signer = Signer {
        public_key: key.to_vec(),
        commit: [0; 32],
    };
    Ok(SignedBy {
        key_id: signer.key_id(),
    })
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
    Ok((payload, d.written))
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
    if d.zeros != d.written {
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
