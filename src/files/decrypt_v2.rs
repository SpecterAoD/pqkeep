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
use super::format::Content;
use super::format_v2::{HeaderV2, Slot};
use super::format_v4::{OPT_HIDDEN_SENDER, OPT_PAD, check_commit_v4};
use super::signed_io::{self, SignatureCheck};
use super::signer_v3::{FILE_SIGNATURE_LEN, check_commit};
use super::tail_v4::TailRead;
use crate::crypto::factor::Factor;
use crate::crypto::stream::PREFIX_LEN;
use crate::crypto::v2::{self, Domain};
use crate::crypto::{KeyAlgorithm, SecretBytes, aead, kem};
use crate::envelope::PublicKeyFile;
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
    // DE: Anonyme Zugänge (experimentell, #340): alle probieren. EN: Anonymous slots: try all.
    if header
        .slots
        .iter()
        .any(|s| matches!(s, Slot::Anonymous { .. }))
    {
        return super::anon_v4::open(header, key);
    }
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

/// DE: Signaturprüfung samt Länge des Chiffrats (nur sichtbarer Absender).
/// EN: Signature check including the ciphertext length (visible sender only).
pub(super) type Check = Option<(SignatureCheck, Option<u64>)>;

/// DE: Was nach dem Header für den Strom nötig ist. EN: What the stream needs after the header.
pub(super) struct Opened {
    pub file_key: SecretBytes,
    pub stream_aad: Vec<u8>,
    pub prefix: [u8; PREFIX_LEN],
    pub content: Content,
    /// DE: Format v4: Füllung, ggf. verborgener Absender und Trailer folgen.
    /// EN: Format v4: padding, optional hidden sender and trailer follow.
    pub tail: Option<TailRead>,
}

/// DE: v2/v3/v4 öffnen: verlangter Absender, Dateischlüssel, Schlüsselbindung (v4 immer), bei
/// Signatur die Prüfung samt Länge des Chiffrats.
/// EN: Opening v2/v3/v4: required sender, file key, key commitment (always for v4), with a signature
/// the check including the ciphertext length.
pub(super) fn open_header(
    header: &HeaderV2,
    unlock: &Unlock<'_>,
    signer: Option<&PublicKeyFile>,
    file_len: u64,
) -> Result<(Opened, Check)> {
    let options = header.v4.as_ref().map_or(0, |v4| v4.options);
    let hidden = options & OPT_HIDDEN_SENDER != 0;
    // DE: Verborgener Absender: Identität erst nach dem Entschlüsseln prüfbar.
    // EN: Hidden sender: identity can only be checked after decrypting.
    if hidden {
        signed_io::require_kind(signer)?;
    } else {
        signed_io::require(signer, header.signer.as_ref())?;
    }
    let file_key = unwrap_key(header, unlock)?;
    match (&header.v4, &header.signer) {
        (Some(v4), _) => check_commit_v4(v4, file_key.expose())?,
        (None, Some(s)) => check_commit(s, file_key.expose())?,
        (None, None) => {}
    }
    let mut tail = header.v4.as_ref().map(|_| TailRead {
        padded: options & OPT_PAD != 0,
        hidden: None,
    });
    let check = match &header.signer {
        Some(s) => {
            let bytes = header.encode()?;
            let fixed = (bytes.len() + FILE_SIGNATURE_LEN) as u64;
            let body_len = file_len.checked_sub(fixed).ok_or(Error::Decrypt)?;
            Some((SignatureCheck::new(bytes, s.clone()), Some(body_len)))
        }
        None if hidden => {
            let (check, result) = SignatureCheck::hidden(signer);
            if let Some(t) = tail.as_mut() {
                t.hidden = Some((header.encode()?, result));
            }
            Some((check, None))
        }
        None => None,
    };
    let opened = Opened {
        file_key,
        stream_aad: header.stream_aad()?,
        prefix: header.prefix,
        content: header.content,
        tail,
    };
    Ok((opened, check))
}
