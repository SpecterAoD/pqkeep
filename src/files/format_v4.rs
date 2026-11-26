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
//! Umgesetzt ist bisher nur `SIGNED`; `PAD`, `ANON` und `HIDDEN_SENDER` sind reserviert und „nicht
//! unterstützt“, ebenso unbekannte Bits. v4 wird nur geschrieben, wenn eine Option es verlangt –
//! derzeit also nur für Inhalt 3; v4 mit Inhalt 1/2 ist ungültig (D3 bleibt kanonisch).
//!
//! EN: Format v4 (`docs/V4_DRAFT.md`, #316/#83): v2 header with version 4, U16 option bits after
//! the nonce prefix and a key commitment `commit` in every v4 file; new content type 3 "stream". A
//! stream's plaintext ends with a trailer (layout above). Only `SIGNED` is implemented; `PAD`,
//! `ANON` and `HIDDEN_SENDER` are reserved and "unsupported", like unknown bits. v4 is only written when an
//! option requires it – currently only for content 3; v4 with content 1/2 is invalid (D3 stays
//! canonical).

use sha3::Sha3_256;

use super::format::{Content, bad};
use super::signer_v3::{COMMIT_LEN, Signer};
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
    if v4.options & !OPT_SIGNED != 0 {
        return Err(Error::Unsupported);
    }
    let has_signed_bit = v4.options & OPT_SIGNED != 0;
    if has_signed_bit != signer.is_some() || signer.is_some_and(|s| s.commit != v4.commit) {
        return Err(bad());
    }
    // DE: Ohne PAD/ANON/HIDDEN gibt es v4 nur für Ströme. EN: Without PAD/ANON/HIDDEN v4 is stream-only.
    if content != Content::Stream {
        return Err(bad());
    }
    Ok(())
}

/// DE: v4-Felder beim Verschlüsseln: nur für Ströme (sonst `None`), `commit` mit v4-Domäne.
/// EN: v4 fields when encrypting: streams only (else `None`), `commit` with the v4 domain.
///
/// # Errors
/// DE/EN: [`Error::MemoryLock`], [`Error::Crypto`].
pub fn for_encrypt(content: Content, signed: bool, file_key: &[u8]) -> Result<Option<V4>> {
    if content != Content::Stream {
        return Ok(None);
    }
    Ok(Some(V4 {
        options: if signed { OPT_SIGNED } else { 0 },
        commit: commit_v4(file_key)?,
    }))
}

/// DE: Trailer für `payload_len` Nutzbytes ohne Füllung. EN: Trailer for `payload_len` bytes, no padding.
#[must_use]
pub fn trailer(payload_len: u64) -> [u8; TRAILER_LEN] {
    let mut out = [0u8; TRAILER_LEN];
    out[..8].copy_from_slice(&payload_len.to_le_bytes());
    out[16..].copy_from_slice(TRAILER_MAGIC);
    out
}

/// DE: Prüft den Trailer gegen die tatsächlich gelesene Nutzlänge.
/// EN: Checks the trailer against the payload length actually read.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (Feld `trailer`).
pub fn check_trailer(bytes: &[u8], payload_len: u64) -> Result<()> {
    let ok = bytes.len() == TRAILER_LEN
        && bytes[..8] == payload_len.to_le_bytes()
        && bytes[8..16] == [0u8; 8]
        && &bytes[16..] == TRAILER_MAGIC;
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidInput { field: "trailer" })
    }
}

#[cfg(test)]
#[path = "format_v4_tests.rs"]
mod format_v4_tests;
