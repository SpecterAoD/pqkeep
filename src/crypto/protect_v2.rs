//! DE: Schutz eines privaten Schlüssels (Seed) mit Passphrase **und Faktordatei** für die
//! Schlüsseldatei v2 (`docs/V2_DRAFT.md`): `Wpass` aus [`v2::passphrase_kek`] mit der Domäne
//! `PQKeep/key/v2\0` → AES-256-GCM. Pro Vorgang neuer Salt und neue Nonce.
//!
//! ```text
//! AAD = "PQKeep/key/v2\0" ‖ "aad/key\0" ‖ L(Algorithmus) ‖ U32(m) U32(t) U32(p) ‖ L(Salt) ‖ L(Header)
//! ```
//!
//! `L(x)` = U64-Länge (Little Endian) und Bytes, wie in Version 1; nur die Domäne ist eine
//! andere, damit sich AAD und Schlüssel beider Versionen nie decken.
//!
//! EN: Protection of a private key (seed) with passphrase **and factor file** for key file v2
//! (`docs/V2_DRAFT.md`): `Wpass` from [`v2::passphrase_kek`] with domain `PQKeep/key/v2\0` →
//! AES-256-GCM. Fresh salt and nonce every time. AAD as above; `L(x)` = U64 length (little
//! endian) and bytes as in version 1; only the domain differs so that AAD and key of the two
//! versions never coincide.

use crate::crypto::factor::Factor;
use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::protect::ProtectedKey;
use crate::crypto::v2::{self, Domain};
use crate::crypto::{KeyAlgorithm, SecretBytes, aead, rng};
use crate::security::{Passphrase, StrongPassphrase};
use crate::{Error, Result};

/// DE: Baut die AAD eindeutig (Längenpräfixe, feste Reihenfolge).
/// EN: Builds the AAD unambiguously (length prefixes, fixed order).
#[must_use]
pub fn associated_data(
    algorithm: KeyAlgorithm,
    params: &KdfParams,
    salt: &[u8],
    metadata: &[u8],
) -> Vec<u8> {
    let mut aad = [Domain::Key.tag(), b"aad/key\0"].concat();
    push_field(&mut aad, algorithm.id().as_bytes());
    for value in [params.memory_kib, params.iterations, params.parallelism] {
        aad.extend_from_slice(&value.to_le_bytes());
    }
    push_field(&mut aad, salt);
    push_field(&mut aad, metadata);
    aad
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    // DE: u64-Längenpräfix: kein Überlauf möglich. EN: u64 length prefix: cannot overflow.
    out.extend_from_slice(&(field.len() as u64).to_le_bytes());
    out.extend_from_slice(field);
}

/// DE: Verschlüsselt `secret` (Seed bzw. AES-Schlüssel) mit Passphrase und Faktordatei.
/// EN: Encrypts `secret` (seed or AES key) with passphrase and factor file.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`], [`Error::KdfParams`], [`Error::Rng`], [`Error::Crypto`].
pub fn protect(
    passphrase: &StrongPassphrase,
    factor: &Factor,
    algorithm: KeyAlgorithm,
    secret: &[u8],
    params: &KdfParams,
    metadata: &[u8],
) -> Result<ProtectedKey> {
    if secret.len() != algorithm.secret_len() {
        return Err(Error::InvalidInput { field: "secret" });
    }
    let salt = rng::array::<{ kdf::SALT_LEN }>()?.to_vec();
    let key = v2::passphrase_kek(
        Domain::Key,
        passphrase.as_ref(),
        Some(factor),
        &salt,
        params,
    )?;
    let aad = associated_data(algorithm, params, &salt, metadata);
    let sealed = aead::seal(key.expose(), secret, &aad);
    // DE: Abgeleiteten Schlüssel sofort nach der Nutzung freigeben (nullen + entsperren).
    // EN: Release the derived key right after use (zero + unlock).
    drop(key);
    let sealed = sealed?;
    Ok(ProtectedKey {
        algorithm,
        kdf: *params,
        salt,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
    })
}

/// DE: Entschlüsselt den geschützten Schlüssel. Falsche Passphrase, falsche Faktordatei oder
/// jede Manipulation ergibt [`Error::Decrypt`]; unzulässige Parameter [`Error::KdfParams`]
/// (geprüft **vor** der teuren Ableitung).
/// EN: Decrypts the protected key. A wrong passphrase, a wrong factor file or any tampering
/// yields [`Error::Decrypt`]; inadmissible parameters [`Error::KdfParams`] (checked **before**
/// the expensive derivation).
///
/// # Errors
/// DE/EN: [`Error::KdfParams`], [`Error::InvalidInput`], [`Error::Decrypt`].
pub fn unprotect(
    passphrase: &Passphrase,
    factor: &Factor,
    protected: &ProtectedKey,
    metadata: &[u8],
) -> Result<SecretBytes> {
    protected.kdf.validate()?;
    let expected = protected.algorithm.secret_len() + aead::TAG_LEN;
    if protected.ciphertext.len() != expected {
        return Err(Error::Decrypt);
    }
    let salt = &protected.salt;
    let key = v2::passphrase_kek(Domain::Key, passphrase, Some(factor), salt, &protected.kdf)?;
    let aad = associated_data(protected.algorithm, &protected.kdf, salt, metadata);
    let opened = aead::open(key.expose(), &protected.nonce, &protected.ciphertext, &aad);
    drop(key);
    opened
}
