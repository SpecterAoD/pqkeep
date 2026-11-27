//! DE: Format v4 (`docs/V4_DRAFT.md`, #316/#83): v2-Header mit Version 4, U16-Optionsbits nach dem
//! Nonce-Präfix und einer Schlüsselbindung `commit` in jeder v4-Datei; neuer Inhaltstyp 3 „Strom“.
//! Der Klartext eines Stroms endet mit einem Abschluss-Block (Trailer):
//!
//! ```text
//! M = "PQKFENC\0" ‖ U16(4) ‖ U8(inhalt) ‖ U32(65536) ‖ nonce_prefix[7] ‖ U16(optionen) ‖ U8(n)
//!     ‖ zugang_1..n ‖ [absenderblock wie v3, nur SIGNED – endet mit commit] | commit[32]
//! T = U64(länge nutzdaten) ‖ U64(länge füllung = 0) ‖ "PQKFEND\0"
//! commit = SHA3-256("PQKeep/file/v4\0" ‖ "commit\0" ‖ dateischlüssel)
//! ```
//!
//! Umgesetzt sind `SIGNED`, `PAD` (Füllung nach PADMÉ, nur Nullbytes, kanonische Länge) und
//! `ANON` (anonyme ML-KEM-1024-Empfänger, **experimentell**, #340); `HIDDEN_SENDER` ist reserviert
//! und „nicht unterstützt“, ebenso unbekannte Bits. v4 wird nur geschrieben, wenn eine Option es
//! verlangt (Inhalt 3, `PAD` oder `ANON`); sonst ist v4 ungültig (D3 bleibt kanonisch).
//!
//! EN: Format v4 (`docs/V4_DRAFT.md`, #316/#83): v2 header with version 4, U16 option bits after
//! the nonce prefix and a key commitment `commit` in every v4 file; new content type 3 "stream". A
//! stream's plaintext ends with a trailer (layout above). `SIGNED`, `PAD` (PADMÉ padding, zero bytes
//! only, canonical length) and `ANON` (anonymous ML-KEM-1024 recipients, **experimental**, #340) are
//! implemented; `HIDDEN_SENDER` is reserved and "unsupported", like unknown bits. v4 is only written
//! when an option requires it (content 3, `PAD` or `ANON`); otherwise v4 is invalid (D3 stays
//! canonical).

use sha3::Sha3_256;

use super::format::{Content, bad};
use super::signer_v3::{COMMIT_LEN, FILE_SIGNATURE_LEN, SIGNER_KEY_LEN, Signer};
use super::slot_v2::Slot;
use crate::crypto::locked_hash::LockedHash;
use crate::{Error, Result};

/// DE: Formatversion. EN: Format version.
pub const VERSION_V4: u16 = 4;
/// DE: Domäne für Hüllen-AAD und Schlüsselbindung. EN: Domain for wrap AAD and key commitment.
pub const DOMAIN_V4: &[u8] = b"PQKeep/file/v4\0";

/// DE: Füllung (reserviert). EN: Padding (reserved).
pub const OPT_PAD: u16 = 0x0001;
/// DE: Anonyme Empfänger (reserviert). EN: Anonymous recipients (reserved).
pub const OPT_ANON: u16 = 0x0002;
/// DE: Sichtbarer Absender wie v3. EN: Visible sender as in v3.
pub const OPT_SIGNED: u16 = 0x0004;
/// DE: Verborgener Absender (reserviert). EN: Hidden sender (reserved).
pub const OPT_HIDDEN_SENDER: u16 = 0x0008;

/// DE: Kennung am Ende des Trailers. EN: Marker at the end of the trailer.
pub const TRAILER_MAGIC: &[u8; 8] = b"PQKFEND\0";
/// DE: Länge des Trailers ohne verborgenen Absender. EN: Trailer length without hidden sender.
pub const TRAILER_LEN: usize = 8 + 8 + TRAILER_MAGIC.len();
/// DE: Verborgener Absender im Trailer: Algorithmus ‖ Schlüssel ‖ Signatur.
/// EN: Hidden sender in the trailer: algorithm ‖ key ‖ signature.
pub const HIDDEN_BLOCK_LEN: usize = 1 + SIGNER_KEY_LEN + FILE_SIGNATURE_LEN;

/// DE: Trailerlänge je nach verborgenem Absender. EN: Trailer length depending on hidden sender.
#[must_use]
pub const fn trailer_len(hidden: bool) -> usize {
    if hidden {
        HIDDEN_BLOCK_LEN + TRAILER_LEN
    } else {
        TRAILER_LEN
    }
}

/// DE: Signierte Nachricht des verborgenen Absenders: Domäne ‖ SHA3-512(H) ‖ SHA3-512(N) ‖ beide
/// Längen (Grenze Nutzdaten/Füllung, Codex-Fund #324).
/// EN: Signed message of the hidden sender: domain ‖ SHA3-512(H) ‖ SHA3-512(N) ‖ both lengths
/// (payload/padding boundary, Codex finding #324).
#[must_use]
pub fn hidden_message(header: &[u8], plain_hash: &[u8], payload: u64, pad: u64) -> Vec<u8> {
    let mut out = [DOMAIN_V4, b"sig/hidden\0"].concat();
    out.extend_from_slice(&<sha3::Sha3_512 as sha3::Digest>::digest(header));
    out.extend_from_slice(plain_hash);
    out.extend_from_slice(&payload.to_le_bytes());
    out.extend_from_slice(&pad.to_le_bytes());
    out
}

/// DE: v4-Zusatzfelder des Headers. EN: v4 extra fields of the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V4 {
    /// DE: Optionsbits. EN: Option bits.
    pub options: u16,
    /// DE: Schlüsselbindung (bei SIGNED identisch mit der im Absenderblock).
    /// EN: Key commitment (with SIGNED identical to the one in the sender block).
    pub commit: [u8; COMMIT_LEN],
}

/// DE: Schlüsselbindung v4. EN: Key commitment v4.
///
/// # Errors
/// DE/EN: [`Error::MemoryLock`], [`Error::Crypto`].
pub fn commit_v4(file_key: &[u8]) -> Result<[u8; COMMIT_LEN]> {
    let mut hasher = LockedHash::<Sha3_256>::new()?;
    hasher.update(DOMAIN_V4);
    hasher.update(b"commit\0");
    hasher.update(file_key);
    hasher
        .finalize()?
        .expose()
        .try_into()
        .map_err(|_| Error::Crypto)
}

/// DE: Prüft die Schlüsselbindung ohne frühen Abbruch; Abweichung = [`Error::Decrypt`].
/// EN: Checks the key commitment without early exit; mismatch = [`Error::Decrypt`].
///
/// # Errors
/// DE/EN: [`Error::Decrypt`], [`Error::MemoryLock`].
pub fn check_commit_v4(v4: &V4, file_key: &[u8]) -> Result<()> {
    let expected = commit_v4(file_key)?;
    let diff = expected
        .iter()
        .zip(v4.commit.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff == 0 {
        Ok(())
    } else {
        Err(Error::Decrypt)
    }
}

/// DE: Prüft Optionsbits, Inhalt und Absender eines v4-Headers (vor jeder Ableitung).
/// EN: Checks option bits, content and sender of a v4 header (before any derivation).
///
/// # Errors
/// DE/EN: [`Error::Unsupported`] (reservierte/unbekannte Bits / reserved/unknown bits),
/// [`Error::InvalidInput`] (Feld `header`).
pub fn check_v4(content: Content, v4: &V4, signer: Option<&Signer>) -> Result<()> {
    if v4.options & !(OPT_SIGNED | OPT_PAD | OPT_ANON | OPT_HIDDEN_SENDER) != 0 {
        return Err(Error::Unsupported);
    }
    let has_signed_bit = v4.options & OPT_SIGNED != 0;
    let hidden = v4.options & OPT_HIDDEN_SENDER != 0;
    if has_signed_bit != signer.is_some()
        || (hidden && has_signed_bit)
        || signer.is_some_and(|s| s.commit != v4.commit)
    {
        return Err(bad());
    }
    // DE: v4 braucht einen Grund: Strom, PAD, ANON oder verborgener Absender.
    // EN: v4 needs a reason: stream, PAD, ANON or hidden sender.
    if content != Content::Stream && v4.options & (OPT_PAD | OPT_ANON | OPT_HIDDEN_SENDER) == 0 {
        return Err(bad());
    }
    Ok(())
}

/// DE: ANON gesetzt ⇔ es gibt anonyme Zugänge (Typ 5); ohne v4 nie Typ 5.
/// EN: ANON set ⇔ there are anonymous slots (type 5); never type 5 without v4.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (Feld `header`).
pub fn check_anon(slots: &[Slot], v4: Option<&V4>) -> Result<()> {
    let anon = v4.is_some_and(|v| v.options & OPT_ANON != 0);
    let has_anonymous = slots.iter().any(|s| matches!(s, Slot::Anonymous { .. }));
    if anon == has_anonymous {
        Ok(())
    } else {
        Err(bad())
    }
}

/// DE: v4-Felder beim Verschlüsseln: nur für Ströme (sonst `None`), `commit` mit v4-Domäne.
/// EN: v4 fields when encrypting: streams only (else `None`), `commit` with the v4 domain.
///
/// # Errors
/// DE/EN: [`Error::MemoryLock`], [`Error::Crypto`].
pub fn for_encrypt(
    content: Content,
    signed: bool,
    opts: super::EncryptOptions,
    file_key: &[u8],
) -> Result<Option<V4>> {
    if content != Content::Stream && !opts.pad && !opts.anonymous && !opts.hide_sender {
        return Ok(None);
    }
    let mut options = 0;
    for (on, bit) in [
        (signed, OPT_SIGNED),
        (opts.pad, OPT_PAD),
        (opts.anonymous, OPT_ANON),
        (opts.hide_sender, OPT_HIDDEN_SENDER),
    ] {
        if on {
            options |= bit;
        }
    }
    Ok(Some(V4 {
        options,
        commit: commit_v4(file_key)?,
    }))
}

/// DE: PADMÉ (Nikitin u. a. 2019): gepolsterte Gesamtlänge für `len` Bytes (Nutzdaten + Trailer);
/// verrät nur O(log log L) Bit, höchstens ~12 % Mehrgröße.
/// EN: PADMÉ (Nikitin et al. 2019): padded total length for `len` bytes (payload + trailer); leaks
/// only O(log log L) bits, at most ~12 % overhead.
///
/// # Errors
/// DE/EN: [`Error::Crypto`] bei Überlauf / on overflow.
pub fn padme(len: u64) -> Result<u64> {
    if len < 2 {
        return Ok(len);
    }
    let e = 63 - u64::from(len.leading_zeros());
    let s = 64 - u64::from(e.leading_zeros());
    let mask = (1u64 << (e - s)) - 1;
    len.checked_add(mask)
        .map(|v| v & !mask)
        .ok_or(Error::Crypto)
}

/// DE: Füllung für `payload` Nutzbytes (mit `padded`, sonst 0). EN: Padding for `payload` bytes.
///
/// # Errors
/// DE/EN: [`Error::Crypto`] bei Überlauf / on overflow.
pub fn padding_for(payload: u64, padded: bool) -> Result<u64> {
    if !padded {
        return Ok(0);
    }
    let base = payload
        .checked_add(TRAILER_LEN as u64)
        .ok_or(Error::Crypto)?;
    Ok(padme(base)? - base)
}

/// DE: Trailer für `payload_len` Nutzbytes und `pad_len` Füllbytes.
/// EN: Trailer for `payload_len` payload bytes and `pad_len` padding bytes.
#[must_use]
pub fn trailer(payload_len: u64, pad_len: u64) -> [u8; TRAILER_LEN] {
    let mut out = [0u8; TRAILER_LEN];
    out[..8].copy_from_slice(&payload_len.to_le_bytes());
    out[8..16].copy_from_slice(&pad_len.to_le_bytes());
    out[16..].copy_from_slice(TRAILER_MAGIC);
    out
}

fn trailer_error() -> Error {
    Error::InvalidInput { field: "trailer" }
}

/// DE: Prüft den Trailer: `total` = gelesene Bytes vor dem Trailer (Nutzdaten + Füllung); die
/// Füllung muss mit `padded` genau PADMÉ sein, sonst 0. Liefert die Nutzlänge. Dass die Füllung aus
/// Nullbytes besteht, prüft der Aufrufer.
/// EN: Checks the trailer: `total` = bytes read before the trailer (payload + padding); with
/// `padded` the padding must be exactly PADMÉ, else 0. Returns the payload length. The caller checks
/// that the padding consists of zero bytes.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (Feld `trailer`).
pub fn check_trailer(bytes: &[u8], total: u64, padded: bool) -> Result<u64> {
    if bytes.len() != TRAILER_LEN || &bytes[16..] != TRAILER_MAGIC {
        return Err(trailer_error());
    }
    let word = |i: usize| -> Result<u64> {
        let raw: [u8; 8] = bytes[i..i + 8].try_into().map_err(|_| trailer_error())?;
        Ok(u64::from_le_bytes(raw))
    };
    let (payload, pad) = (word(0)?, word(8)?);
    let canonical = padding_for(payload, padded).map_err(|_| trailer_error())?;
    if payload.checked_add(pad) != Some(total) || pad != canonical {
        return Err(trailer_error());
    }
    Ok(payload)
}

#[cfg(test)]
#[path = "format_v4_tests.rs"]
mod format_v4_tests;
