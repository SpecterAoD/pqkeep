//! DE: Anonyme Empfänger (Format v4, Bit `ANON`, Zugangstyp 5) – **experimentell** (#316, #340):
//! Zugänge ohne Empfänger-ID, nur ML-KEM-1024. Zum Öffnen wird jeder anonyme Zugang probiert
//! (höchstens 64 Entkapselungen); ML-KEM liefert bei falschem Schlüssel durch implizite Ablehnung
//! nur Zufall, die Hülle scheitert dann an der Authentisierung. Erst nach allen Versuchen gibt es die
//! Meldung „kein Zugang für diesen Schlüssel“. Die Anonymität stützt sich auf ANO-CCA von ML-KEM –
//! für Kyber (Runde 3) bewiesen, für FIPS 203 noch nicht belegt (#340).
//! EN: Anonymous recipients (format v4, bit `ANON`, slot type 5) – **experimental** (#316, #340):
//! slots without recipient ID, ML-KEM-1024 only. To open, every anonymous slot is tried (at most 64
//! decapsulations); with a wrong key ML-KEM's implicit rejection yields only randomness and the wrap
//! fails authentication. Only after all attempts comes "no slot for this key". Anonymity relies on
//! ML-KEM's ANO-CCA – proven for Kyber (round 3), not yet established for FIPS 203 (#340).

use super::format_v2::HeaderV2;
use super::slot_v2::{ANONYMOUS_KEM, Slot};
use crate::crypto::aead::NONCE_LEN;
use crate::crypto::{KemAlgorithm, KeyAlgorithm, SecretBytes, aead, kem, rng, v2};
use crate::envelope::UnlockedKey;
use crate::{Error, Result};

/// DE: Anonymer Zugang für `recipient` (muss ML-KEM-1024 sein) samt Packschlüssel.
/// EN: Anonymous slot for `recipient` (must be ML-KEM-1024) including the wrapping key.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] `anonymous_kem` (kein ML-KEM-1024 / not ML-KEM-1024),
/// [`Error::Crypto`], [`Error::Rng`].
pub(super) fn slot(algorithm: KemAlgorithm, public_key: &[u8]) -> Result<(Slot, SecretBytes)> {
    if algorithm != ANONYMOUS_KEM {
        return Err(Error::InvalidInput {
            field: "anonymous_kem",
        });
    }
    let enc = kem::encapsulate(ANONYMOUS_KEM, public_key)?;
    let kek = v2::anonymous_kek(enc.shared_secret.expose(), &enc.ciphertext)?;
    let slot = Slot::Anonymous {
        kem_ciphertext: enc.ciphertext,
        nonce: rng::array::<NONCE_LEN>()?,
    };
    Ok((slot, kek))
}

/// DE: Packt den Dateischlüssel mit `key` aus einem der anonymen Zugänge aus.
/// EN: Unwraps the file key with `key` from one of the anonymous slots.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] `key_kind` (kein ML-KEM-1024-Schlüssel / not an ML-KEM-1024 key)
/// bzw. `anonymous_recipient` (kein Zugang passt / no slot matches), [`Error::Crypto`].
pub(super) fn open(header: &HeaderV2, key: &UnlockedKey) -> Result<SecretBytes> {
    if key.algorithm != KeyAlgorithm::Kem(ANONYMOUS_KEM) {
        return Err(Error::InvalidInput { field: "key_kind" });
    }
    for (index, slot) in header.slots.iter().enumerate() {
        let Slot::Anonymous {
            kem_ciphertext,
            nonce,
        } = slot
        else {
            continue;
        };
        let shared = kem::decapsulate(ANONYMOUS_KEM, key.secret().expose(), kem_ciphertext)?;
        let kek = v2::anonymous_kek(shared.expose(), kem_ciphertext)?;
        let wrap = header.wraps.get(index).ok_or(Error::Decrypt)?;
        match aead::open(kek.expose(), nonce, wrap, &header.wrap_aad(index)?) {
            Ok(file_key) => return Ok(file_key),
            Err(Error::Decrypt) => {}
            Err(other) => return Err(other),
        }
    }
    Err(Error::InvalidInput {
        field: "anonymous_recipient",
    })
}
