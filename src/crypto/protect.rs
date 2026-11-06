//! DE: Schutz eines privaten Schlüssels (Seed) mit Passphrase:
//! Argon2id → AES-256-GCM. Pro Vorgang neuer Salt, neuer Schlüssel und neue Nonce.
//! Algorithmus, KDF-Parameter, Salt und die Metadaten des Aufrufers werden als
//! AAD mitauthentifiziert; die Nonce ist über GCM selbst gebunden.
//! Schützen verlangt eine geprüfte `StrongPassphrase`, Öffnen nur eine normalisierte
//! `Passphrase` (vorhandene Daten bleiben lesbar). Das Dateiformat folgt in Schritt 3.
//!
//! EN: Protection of a private key (seed) with a passphrase:
//! Argon2id → AES-256-GCM. Fresh salt, fresh key and fresh nonce every time.
//! Algorithm, KDF parameters, salt and the caller's metadata are authenticated
//! as AAD; the nonce is bound by GCM itself.
//! Protecting requires a checked `StrongPassphrase`, opening only a normalised
//! `Passphrase` (existing data stays readable). The file format follows in step 3.

use crate::crypto::aead::{self, NONCE_LEN};
use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::{KeyAlgorithm, SecretBytes, rng};
use crate::security::{Passphrase, StrongPassphrase};
use crate::{Error, Result};

/// DE: Domänen-Tag der AAD (Version 1). EN: AAD domain tag (version 1).
pub const AAD_DOMAIN: &[u8] = b"PQC-KeyForge/protect/v1\0";

/// DE: Geschützter Schlüssel; alle Felder sind öffentlich speicherbar.
/// EN: Protected key; all fields are safe to store publicly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedKey {
    /// DE: Algorithmus des Geheimnisses. EN: Algorithm of the secret.
    pub algorithm: KeyAlgorithm,
    /// DE: Argon2id-Parameter. EN: Argon2id parameters.
    pub kdf: KdfParams,
    /// DE: Salt der Ableitung. EN: Derivation salt.
    pub salt: Vec<u8>,
    /// DE: AES-GCM-Nonce. EN: AES-GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// DE: Chiffrat inkl. Tag. EN: Ciphertext incl. tag.
    pub ciphertext: Vec<u8>,
}

/// DE: Baut die AAD eindeutig (Längenpräfixe, feste Reihenfolge).
/// EN: Builds the AAD unambiguously (length prefixes, fixed order).
#[must_use]
pub fn associated_data(
    algorithm: KeyAlgorithm,
    params: &KdfParams,
    salt: &[u8],
    metadata: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 64 + salt.len() + metadata.len());
    aad.extend_from_slice(AAD_DOMAIN);
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

/// DE: Verschlüsselt `secret` (Seed bzw. AES-Schlüssel) mit der Passphrase.
/// EN: Encrypts `secret` (seed or AES key) with the passphrase.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`], [`Error::KdfParams`], [`Error::Rng`], [`Error::Crypto`].
pub fn protect(
    passphrase: &StrongPassphrase,
    algorithm: KeyAlgorithm,
    secret: &[u8],
    params: &KdfParams,
    metadata: &[u8],
) -> Result<ProtectedKey> {
    if secret.len() != algorithm.secret_len() {
        return Err(Error::InvalidInput { field: "secret" });
    }
    let salt = rng::array::<{ kdf::SALT_LEN }>()?.to_vec();
    let key = kdf::derive(passphrase.as_ref().expose(), &salt, params)?;
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

/// DE: Entschlüsselt den geschützten Schlüssel. Falsche Passphrase oder jede
/// Manipulation ergibt [`Error::Decrypt`]; unzulässige Parameter [`Error::KdfParams`]
/// (geprüft **vor** der teuren Ableitung).
/// EN: Decrypts the protected key. A wrong passphrase or any tampering yields
/// [`Error::Decrypt`]; inadmissible parameters [`Error::KdfParams`]
/// (checked **before** the expensive derivation).
///
/// # Errors
/// DE/EN: [`Error::KdfParams`], [`Error::InvalidInput`], [`Error::Decrypt`].
pub fn unprotect(
    passphrase: &Passphrase,
    protected: &ProtectedKey,
    metadata: &[u8],
) -> Result<SecretBytes> {
    protected.kdf.validate()?;
    let expected = protected.algorithm.secret_len() + aead::TAG_LEN;
    if protected.ciphertext.len() != expected {
        return Err(Error::Decrypt);
    }
    let key = kdf::derive(passphrase.expose(), &protected.salt, &protected.kdf)?;
    let aad = associated_data(
        protected.algorithm,
        &protected.kdf,
        &protected.salt,
        metadata,
    );
    let opened = aead::open(key.expose(), &protected.nonce, &protected.ciphertext, &aad);
    drop(key);
    opened
}
