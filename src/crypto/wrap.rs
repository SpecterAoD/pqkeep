//! DE: Einpacken des zufälligen Dateischlüssels (AES-256-GCM) mit einem
//! Packschlüssel aus
//! - **Passphrase:** Argon2id(Passphrase, Salt) oder
//! - **Empfänger:** ML-KEM-Kapselung an dessen öffentlichen Schlüssel, danach
//!   HKDF-SHA3-256 (Salt = KEM-Chiffrat, Info = Domänen-Tag ‖ Empfänger-ID).
//!
//! Ein falscher Empfängerschlüssel liefert wegen der impliziten Ablehnung von
//! ML-KEM ein anderes Geheimnis; das Auspacken scheitert dann sicher mit
//! [`Error::Decrypt`]. Die AAD (Header-Felder) legt der Aufrufer fest.
//!
//! EN: Wrapping the random file key (AES-256-GCM) with a wrapping key from
//! - **passphrase:** Argon2id(passphrase, salt), or
//! - **recipient:** ML-KEM encapsulation to their public key, then HKDF-SHA3-256
//!   (salt = KEM ciphertext, info = domain tag ‖ recipient ID).
//!
//! A wrong recipient key yields a different secret due to ML-KEM's implicit
//! rejection; unwrapping then reliably fails with [`Error::Decrypt`]. The AAD
//! (header fields) is chosen by the caller.

use hkdf::SimpleHkdf;
use sha3::Sha3_256;

use crate::crypto::aead::{self, NONCE_LEN, TAG_LEN};
use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::{KemAlgorithm, SecretBytes, kem};
use crate::security::{Passphrase, StrongPassphrase};
use crate::{Error, Result};

#[cfg(test)]
#[path = "wrap_tests.rs"]
mod wrap_tests;

/// DE: Länge des Dateischlüssels. EN: Length of the file key.
pub const FILE_KEY_LEN: usize = 32;
/// DE: Länge des eingepackten Schlüssels (inkl. Tag). EN: Wrapped key length (incl. tag).
pub const WRAPPED_LEN: usize = FILE_KEY_LEN + TAG_LEN;
/// DE: Domänen-Tag für HKDF. EN: Domain tag for HKDF.
pub const HKDF_INFO: &[u8] = b"PQKeep/file/v1/kek\0";

/// DE: Eingepackter Dateischlüssel (öffentlich speicherbar).
/// EN: Wrapped file key (safe to store publicly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapped {
    /// DE: Nonce. EN: Nonce.
    pub nonce: [u8; NONCE_LEN],
    /// DE: Chiffrat inkl. Tag (48 Byte). EN: Ciphertext incl. tag (48 bytes).
    pub ciphertext: Vec<u8>,
}

/// DE: Ergebnis der Empfänger-Variante. EN: Result of the recipient variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientWrap {
    /// DE: KEM-Chiffrat für den Empfänger. EN: KEM ciphertext for the recipient.
    pub kem_ciphertext: Vec<u8>,
    /// DE: Eingepackter Dateischlüssel. EN: Wrapped file key.
    pub wrapped: Wrapped,
}

fn seal(kek: &SecretBytes, file_key: &[u8], aad: &[u8]) -> Result<Wrapped> {
    if file_key.len() != FILE_KEY_LEN {
        return Err(Error::InvalidInput { field: "file_key" });
    }
    let sealed = aead::seal(kek.expose(), file_key, aad)?;
    Ok(Wrapped {
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
    })
}

fn open(kek: &SecretBytes, wrapped: &Wrapped, aad: &[u8]) -> Result<SecretBytes> {
    if wrapped.ciphertext.len() != WRAPPED_LEN {
        return Err(Error::Decrypt);
    }
    aead::open(kek.expose(), &wrapped.nonce, &wrapped.ciphertext, aad)
}

/// DE: Packschlüssel aus dem ML-KEM-Geheimnis. EN: Wrapping key from the ML-KEM secret.
pub(crate) fn kek_from_shared(
    shared: &[u8],
    kem_ciphertext: &[u8],
    recipient_id: &[u8],
) -> Result<SecretBytes> {
    // DE: `SimpleHkdf`, da SHA3 (Sponge) keine Block-Kern-Schnittstelle für `Hmac` bietet.
    // EN: `SimpleHkdf` because SHA3 (sponge) offers no block-core interface for `Hmac`.
    let hk = SimpleHkdf::<Sha3_256>::new(Some(kem_ciphertext), shared);
    let mut info = Vec::with_capacity(HKDF_INFO.len() + recipient_id.len());
    info.extend_from_slice(HKDF_INFO);
    info.extend_from_slice(recipient_id);
    let mut kek = SecretBytes::new(vec![0u8; aead::KEY_LEN]);
    hk.expand(&info, kek.expose_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(kek)
}

/// DE: Packt mit einer Passphrase ein. EN: Wraps with a passphrase.
///
/// # Errors
/// DE/EN: [`Error::KdfParams`], [`Error::InvalidInput`], [`Error::Rng`], [`Error::Crypto`].
pub fn wrap_with_passphrase(
    passphrase: &StrongPassphrase,
    params: &KdfParams,
    salt: &[u8],
    file_key: &[u8],
    aad: &[u8],
) -> Result<Wrapped> {
    let kek = kdf::derive(passphrase.as_ref().expose(), salt, params)?;
    seal(&kek, file_key, aad)
}

/// DE: Packt mit einer Passphrase aus. EN: Unwraps with a passphrase.
///
/// # Errors
/// DE/EN: [`Error::Decrypt`], [`Error::KdfParams`], [`Error::InvalidInput`].
pub fn unwrap_with_passphrase(
    passphrase: &Passphrase,
    params: &KdfParams,
    salt: &[u8],
    wrapped: &Wrapped,
    aad: &[u8],
) -> Result<SecretBytes> {
    let kek = kdf::derive(passphrase.expose(), salt, params)?;
    open(&kek, wrapped, aad)
}

/// DE: Packt für einen Empfänger (öffentlicher ML-KEM-Schlüssel) ein.
/// EN: Wraps for a recipient (public ML-KEM key).
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (Schlüssel / key), [`Error::Rng`], [`Error::Crypto`].
pub fn wrap_for_recipient(
    algorithm: KemAlgorithm,
    public_key: &[u8],
    recipient_id: &[u8],
    file_key: &[u8],
    aad: &[u8],
) -> Result<RecipientWrap> {
    let enc = kem::encapsulate(algorithm, public_key)?;
    let kek = kek_from_shared(enc.shared_secret.expose(), &enc.ciphertext, recipient_id)?;
    let wrapped = seal(&kek, file_key, aad)?;
    Ok(RecipientWrap {
        kem_ciphertext: enc.ciphertext,
        wrapped,
    })
}

/// DE: Packt mit dem privaten Schlüssel (Seed) des Empfängers aus.
/// EN: Unwraps with the recipient's private key (seed).
///
/// # Errors
/// DE/EN: [`Error::Decrypt`] (falscher Schlüssel/Manipulation / wrong key/tampering),
/// [`Error::InvalidInput`] (Längen / lengths).
pub fn unwrap_for_recipient(
    algorithm: KemAlgorithm,
    seed: &[u8],
    recipient_id: &[u8],
    recipient: &RecipientWrap,
    aad: &[u8],
) -> Result<SecretBytes> {
    let shared = kem::decapsulate(algorithm, seed, &recipient.kem_ciphertext)?;
    let kek = kek_from_shared(shared.expose(), &recipient.kem_ciphertext, recipient_id)?;
    open(&kek, &recipient.wrapped, aad)
}
