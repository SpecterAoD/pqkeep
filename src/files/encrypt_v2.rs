//! DE: Header für Format v2 beim Verschlüsseln (`docs/V2_DRAFT.md`): ein Dateischlüssel, je
//! Zugang (Passphrase mit optionaler Faktordatei, ML-KEM-Empfänger) einmal eingepackt. Erst
//! stehen alle öffentlichen Zugangsdaten fest (`M`), dann wird jede Hülle mit
//! `WrapAAD(i)` = Domäne ‖ ganzes `M` ‖ Index erzeugt. Empfänger werden nach ID sortiert
//! (kanonische Reihenfolge); Doppel sind ein Fehler.
//!
//! EN: Header for format v2 when encrypting (`docs/V2_DRAFT.md`): one file key, wrapped once per
//! slot (passphrase with optional factor file, ML-KEM recipient). First all public slot data is
//! fixed (`M`), then every wrap is created with `WrapAAD(i)` = domain ‖ complete `M` ‖ index.
//! Recipients are sorted by ID (canonical order); duplicates are an error.

use super::PassphraseAccess;
use super::format::Content;
use super::format_v2::{HeaderV2, MAX_RECIPIENTS, Slot};
use crate::crypto::aead::{self, NONCE_LEN};
use crate::crypto::kdf::SALT_LEN;
use crate::crypto::stream::PREFIX_LEN;
use crate::crypto::v2::{self, Domain, RECIPIENT_ID_LEN};
use crate::crypto::wrap::{FILE_KEY_LEN, WRAPPED_LEN};
use crate::crypto::{KemAlgorithm, KeyAlgorithm, SecretBytes, kem, rng};
use crate::envelope::PublicKeyFile;
use crate::{Error, Result};

const RECIPIENT: Error = Error::InvalidInput { field: "recipient" };

/// DE: Geprüfter Empfänger. EN: Checked recipient.
struct Target<'a> {
    id: [u8; RECIPIENT_ID_LEN],
    algorithm: KemAlgorithm,
    public_key: &'a [u8],
}

/// DE: Prüft und sortiert die Empfänger – vor jeder teuren Ableitung.
/// EN: Checks and sorts the recipients – before any expensive derivation.
fn targets<'a>(recipients: &[&'a PublicKeyFile]) -> Result<Vec<Target<'a>>> {
    if recipients.len() > MAX_RECIPIENTS {
        return Err(RECIPIENT);
    }
    let mut out = Vec::with_capacity(recipients.len());
    for key in recipients {
        let KeyAlgorithm::Kem(algorithm) = key.algorithm() else {
            return Err(RECIPIENT);
        };
        out.push(Target {
            id: key.key_id().try_into().map_err(|_| RECIPIENT)?,
            algorithm,
            public_key: key.public_key(),
        });
    }
    out.sort_by_key(|t| t.id);
    if out.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(Error::InvalidInput { field: "duplicate" });
    }
    Ok(out)
}

fn passphrase_slot(access: &PassphraseAccess<'_>) -> Result<(Slot, SecretBytes)> {
    let salt = rng::array::<SALT_LEN>()?.to_vec();
    let kek = v2::passphrase_kek(
        Domain::File,
        access.passphrase.as_ref(),
        access.factor,
        &salt,
        &access.params,
    )?;
    let slot = Slot::Passphrase {
        factor: access.factor.is_some(),
        params: access.params,
        salt,
        nonce: rng::array::<NONCE_LEN>()?,
    };
    Ok((slot, kek))
}

fn recipient_slot(target: &Target<'_>) -> Result<(Slot, SecretBytes)> {
    let enc = kem::encapsulate(target.algorithm, target.public_key)?;
    let kek = v2::recipient_kek(enc.shared_secret.expose(), &enc.ciphertext, &target.id)?;
    let slot = Slot::Recipient {
        algorithm: target.algorithm,
        recipient_id: target.id,
        kem_ciphertext: enc.ciphertext,
        nonce: rng::array::<NONCE_LEN>()?,
    };
    Ok((slot, kek))
}

fn nonce_of(slot: &Slot) -> [u8; NONCE_LEN] {
    match slot {
        Slot::Passphrase { nonce, .. } | Slot::Recipient { nonce, .. } => *nonce,
    }
}

/// DE: Baut den vollständigen v2-Header für `file_key`.
/// EN: Builds the complete v2 header for `file_key`.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (`recipient`, `duplicate`, `file_key`, `header`),
/// [`Error::KdfParams`], [`Error::Rng`], [`Error::Crypto`].
pub(super) fn build(
    content: Content,
    prefix: [u8; PREFIX_LEN],
    passphrase: Option<&PassphraseAccess<'_>>,
    recipients: &[&PublicKeyFile],
    file_key: &SecretBytes,
) -> Result<HeaderV2> {
    if file_key.expose().len() != FILE_KEY_LEN {
        return Err(Error::InvalidInput { field: "file_key" });
    }
    let targets = targets(recipients)?;
    if passphrase.is_none() && targets.is_empty() {
        return Err(RECIPIENT);
    }
    let mut slots = Vec::with_capacity(targets.len() + 1);
    let mut keks = Vec::with_capacity(targets.len() + 1);
    let passphrase = passphrase.map(passphrase_slot).transpose()?;
    let recipients = targets.iter().map(recipient_slot);
    for pair in passphrase.map(Ok).into_iter().chain(recipients) {
        let (slot, kek) = pair?;
        slots.push(slot);
        keks.push(kek);
    }
    let mut header = HeaderV2 {
        content,
        prefix,
        slots,
        wraps: Vec::with_capacity(keks.len()),
    };
    let metadata = header.metadata()?;
    for (index, kek) in keks.iter().enumerate() {
        let aad = super::format_v2::wrap_aad(Domain::File, &metadata, index)?;
        let nonce = nonce_of(&header.slots[index]);
        let wrap = aead::seal_with_nonce(kek.expose(), nonce, file_key.expose(), &aad)?;
        let wrap: [u8; WRAPPED_LEN] = wrap.try_into().map_err(|_| Error::Crypto)?;
        header.wraps.push(wrap);
    }
    Ok(header)
}
