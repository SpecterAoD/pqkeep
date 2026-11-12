//! DE: Zugänge des Dateiformats v2 (`docs/V2_DRAFT.md`, Aufbau siehe [`super::format_v2`]):
//! Passphrase-Zugang (optional mit Faktordatei) und ML-KEM-Empfänger, jeweils nur öffentliche
//! Daten, sowie die Regeln für die Zugangsliste. Typ 3/4 (TPM/FIDO2) ist reserviert und wie
//! jeder unbekannte Typ „nicht unterstützt“.
//!
//! EN: Access slots of file format v2 (`docs/V2_DRAFT.md`, layout see [`super::format_v2`]):
//! passphrase slot (optional factor file) and ML-KEM recipient, public data only, plus the rules
//! for the slot list. Types 3/4 (TPM/FIDO2) are reserved and, like any unknown type, "unsupported".

use std::io::Read;

use super::format::{Reader, bad, kem_code, kem_from_code};
use crate::crypto::KemAlgorithm;
use crate::crypto::aead::NONCE_LEN;
use crate::crypto::kdf::{KdfParams, MAX_SALT_LEN, MIN_SALT_LEN};
use crate::crypto::v2::RECIPIENT_ID_LEN;
use crate::{Error, Result};

/// DE: Höchstzahl der Empfänger-Zugänge. EN: Maximum number of recipient slots.
pub const MAX_RECIPIENTS: usize = 64;
/// DE: Höchstzahl aller Zugänge (ein Passphrase-Zugang + Empfänger). EN: Maximum number of slots.
pub const MAX_SLOTS: usize = MAX_RECIPIENTS + 1;

const SLOT_PASSPHRASE: u8 = 1;
const SLOT_RECIPIENT: u8 = 2;

/// DE: Ein Zugang mit seinen öffentlichen Daten (keine Geheimnisse).
/// EN: One access slot with its public data (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    /// DE: Passphrase (Argon2id), optional mit Faktordatei. EN: Passphrase, optional factor file.
    Passphrase {
        /// DE: Faktordatei nötig. EN: Factor file required.
        factor: bool,
        /// DE: KDF-Parameter. EN: KDF parameters.
        params: KdfParams,
        /// DE: Salt (16–64 Byte). EN: Salt (16–64 bytes).
        salt: Vec<u8>,
        /// DE: Nonce der Hülle. EN: Nonce of the wrap.
        nonce: [u8; NONCE_LEN],
    },
    /// DE: ML-KEM-Empfänger. EN: ML-KEM recipient.
    Recipient {
        /// DE: Parametersatz. EN: Parameter set.
        algorithm: KemAlgorithm,
        /// DE: Schlüssel-ID des Empfängers (sichtbar, D1). EN: Recipient key ID (visible, D1).
        recipient_id: [u8; RECIPIENT_ID_LEN],
        /// DE: KEM-Chiffrat. EN: KEM ciphertext.
        kem_ciphertext: Vec<u8>,
        /// DE: Nonce der Hülle. EN: Nonce of the wrap.
        nonce: [u8; NONCE_LEN],
    },
}

impl Slot {
    /// DE: Kodierung des Zugangs; prüft KDF-Grenzen, Salt- und Chiffratlänge.
    /// EN: Encoding of the slot; checks KDF bounds, salt and ciphertext length.
    ///
    /// # Errors
    /// DE/EN: [`Error::KdfParams`], [`Error::InvalidInput`] (Feld `header`), [`Error::Unsupported`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::Passphrase {
                factor,
                params,
                salt,
                nonce,
            } => {
                params.validate()?;
                if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()) {
                    return Err(bad());
                }
                out.extend_from_slice(&[SLOT_PASSPHRASE, u8::from(*factor)]);
                for v in [params.memory_kib, params.iterations, params.parallelism] {
                    out.extend_from_slice(&v.to_le_bytes());
                }
                out.push(u8::try_from(salt.len()).map_err(|_| bad())?);
                out.extend_from_slice(salt);
                out.extend_from_slice(nonce);
            }
            Self::Recipient {
                algorithm,
                recipient_id,
                kem_ciphertext,
                nonce,
            } => {
                let code = kem_code(*algorithm);
                if kem_ciphertext.len() != kem_from_code(code)?.1 {
                    return Err(bad());
                }
                out.extend_from_slice(&[SLOT_RECIPIENT, code]);
                out.extend_from_slice(recipient_id);
                out.extend_from_slice(kem_ciphertext);
                out.extend_from_slice(nonce);
            }
        }
        Ok(out)
    }

    /// DE: Liest einen Zugang; unbekannte Typen sind „nicht unterstützt“.
    /// EN: Reads one slot; unknown types are "unsupported".
    pub(super) fn read(r: &mut Reader<'_, impl Read>) -> Result<Self> {
        match r.byte()? {
            SLOT_PASSPHRASE => read_passphrase(r),
            SLOT_RECIPIENT => {
                let (algorithm, ct_len) = kem_from_code(r.byte()?)?;
                Ok(Self::Recipient {
                    algorithm,
                    recipient_id: r.array()?,
                    kem_ciphertext: r.bytes(ct_len)?,
                    nonce: r.array()?,
                })
            }
            // DE: 3/4 reserviert (TPM/FIDO2), alles andere unbekannt. EN: 3/4 reserved, rest unknown.
            _ => Err(Error::Unsupported),
        }
    }
}

fn read_passphrase(r: &mut Reader<'_, impl Read>) -> Result<Slot> {
    let factor = match r.byte()? {
        0 => false,
        1 => true,
        _ => return Err(bad()),
    };
    let params = KdfParams {
        memory_kib: u32::from_le_bytes(r.array()?),
        iterations: u32::from_le_bytes(r.array()?),
        parallelism: u32::from_le_bytes(r.array()?),
    };
    params.validate()?;
    let salt_len = usize::from(r.byte()?);
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt_len) {
        return Err(bad());
    }
    Ok(Slot::Passphrase {
        factor,
        params,
        salt: r.bytes(salt_len)?,
        nonce: r.array()?,
    })
}

/// DE: Prüft die Regeln für die Zugangsliste (Anzahl, Passphrase nur zuerst, Empfänger-IDs
/// streng aufsteigend und damit ohne Doppel).
/// EN: Checks the rules for the slot list (count, passphrase first only, recipient IDs strictly
/// ascending and therefore without duplicates).
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (Feld `header`).
pub fn check_slots(slots: &[Slot]) -> Result<()> {
    if slots.is_empty() || slots.len() > MAX_SLOTS {
        return Err(bad());
    }
    let mut previous: Option<&[u8; RECIPIENT_ID_LEN]> = None;
    let mut recipients = 0;
    for (index, slot) in slots.iter().enumerate() {
        match slot {
            Slot::Passphrase { .. } if index == 0 => {}
            Slot::Passphrase { .. } => return Err(bad()),
            Slot::Recipient { recipient_id, .. } => {
                if previous.is_some_and(|p| recipient_id <= p) {
                    return Err(bad());
                }
                previous = Some(recipient_id);
                recipients += 1;
            }
        }
    }
    if recipients > MAX_RECIPIENTS {
        return Err(bad());
    }
    Ok(())
}
