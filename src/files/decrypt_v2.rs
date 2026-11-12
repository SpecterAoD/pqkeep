//! DE: Dateischlüssel aus einem v2-Header gewinnen (`docs/V2_DRAFT.md`). Der eigene Zugang wird
//! über öffentliche Daten gefunden (Passphrase-Zugang an erster Stelle bzw. sichtbare
//! Empfänger-ID, D1). Alles, was ohne Geheimnis prüfbar ist, wird **vor** der Ableitung
//! geprüft: Faktordatei verlangt, aber nicht angegeben (oder umgekehrt); eigener Schlüssel
//! nicht unter den Empfängern. Danach gibt es nur noch einheitlich [`Error::Decrypt`].
//!
//! EN: Obtaining the file key from a v2 header (`docs/V2_DRAFT.md`). The own slot is found via
//! public data (passphrase slot in first place or visible recipient ID, D1). Everything that can
//! be checked without a secret is checked **before** deriving: factor file required but not
//! given (or vice versa); own key not among the recipients. After that there is only the
//! uniform [`Error::Decrypt`].

use sha3::{Digest, Sha3_256};

use super::Unlock;
use super::format_v2::{HeaderV2, Slot};
use crate::crypto::factor::Factor;
use crate::crypto::v2::{self, Domain};
use crate::crypto::{KeyAlgorithm, SecretBytes, aead, kem};
use crate::envelope::UnlockedKey;
use crate::security::Passphrase;
use crate::{Error, Result};

/// DE: Packt den Dateischlüssel mit dem passenden Zugang aus.
/// EN: Unwraps the file key with the matching slot.
///
/// # Errors
/// DE/EN: [`Error::Decrypt`] (falsche Passphrase/Faktordatei/Schlüssel, Manipulation / wrong
/// passphrase/factor file/key, tampering), [`Error::InvalidInput`] mit `key_kind` (Datei hat
/// keinen solchen Zugang / file has no such slot), `factor_required`, `factor_unused`,
/// `recipient` (eigener Schlüssel nicht dabei / own key not included), [`Error::KdfParams`].
pub(super) fn unwrap_key(header: &HeaderV2, unlock: &Unlock<'_>) -> Result<SecretBytes> {
    match unlock {
        Unlock::Passphrase(passphrase) => with_passphrase(header, passphrase, None),
        Unlock::PassphraseWithFactor { passphrase, factor } => {
            with_passphrase(header, passphrase, Some(factor))
        }
        Unlock::Key(key) => with_key(header, key),
    }
}

fn open(header: &HeaderV2, index: usize, kek: &SecretBytes, nonce: &[u8]) -> Result<SecretBytes> {
    let wrap = header.wraps.get(index).ok_or(Error::Decrypt)?;
    aead::open(kek.expose(), nonce, wrap, &header.wrap_aad(index)?)
}

fn with_passphrase(
    header: &HeaderV2,
    passphrase: &Passphrase,
    given: Option<&Factor>,
) -> Result<SecretBytes> {
    // DE: Der Passphrase-Zugang steht laut Formatregel immer an erster Stelle.
    // EN: By the format rules the passphrase slot is always first.
    let Some(Slot::Passphrase {
        factor,
        params,
        salt,
        nonce,
    }) = header.slots.first()
    else {
        return Err(Error::InvalidInput { field: "key_kind" });
    };
    // DE: Vor Argon2id; der Faktor wird weder still ignoriert noch erraten.
    // EN: Before Argon2id; the factor is neither silently ignored nor guessed.
    match (*factor, given.is_some()) {
        (true, false) => {
            return Err(Error::InvalidInput {
                field: "factor_required",
            });
        }
        (false, true) => {
            return Err(Error::InvalidInput {
                field: "factor_unused",
            });
        }
        _ => {}
    }
    let kek = v2::passphrase_kek(Domain::File, passphrase, given, salt, params)?;
    open(header, 0, &kek, nonce)
}

fn with_key(header: &HeaderV2, key: &UnlockedKey) -> Result<SecretBytes> {
    let own_id = Sha3_256::digest(&key.public_key);
    let mut any = false;
    for (index, slot) in header.slots.iter().enumerate() {
        let Slot::Recipient {
            algorithm,
            recipient_id,
            kem_ciphertext,
            nonce,
        } = slot
        else {
            continue;
        };
        any = true;
        if key.algorithm != KeyAlgorithm::Kem(*algorithm) || own_id.as_slice() != recipient_id {
            continue;
        }
        let shared = kem::decapsulate(*algorithm, key.secret().expose(), kem_ciphertext)?;
        let kek = v2::recipient_kek(shared.expose(), kem_ciphertext, recipient_id)?;
        return open(header, index, &kek, nonce);
    }
    // DE: Klare Meldung vor jeder Entkapselung (IDs sind sichtbar, D1).
    // EN: Clear message before any decapsulation (IDs are visible, D1).
    let field = if any { "recipient" } else { "key_kind" };
    Err(Error::InvalidInput { field })
}
