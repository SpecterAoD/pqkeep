//! DE: AES-256-GCM (authentifizierte Verschlüsselung) und Erzeugung von
//! AES-256-Schlüsseln. Nonce: 96 Bit, pro Verschlüsselung neu aus dem OS-CSPRNG.
//! Der Tag-Vergleich erfolgt in der Crate in konstanter Zeit.
//!
//! EN: AES-256-GCM (authenticated encryption) and generation of AES-256 keys.
//! Nonce: 96 bits, freshly drawn from the OS CSPRNG for every encryption.
//! The tag comparison is constant-time inside the crate.

use aes_gcm::aead::{Aead, Nonce, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};

use crate::crypto::{SecretBytes, rng};
use crate::{Error, Result};

/// DE: Schlüssellänge (256 Bit). EN: Key length (256 bits).
pub const KEY_LEN: usize = 32;
/// DE: Nonce-Länge (96 Bit). EN: Nonce length (96 bits).
pub const NONCE_LEN: usize = 12;
/// DE: Länge des Authentifizierungs-Tags. EN: Authentication tag length.
pub const TAG_LEN: usize = 16;

/// DE: Ergebnis einer Verschlüsselung (beide Teile sind öffentlich).
/// EN: Result of an encryption (both parts are public).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// DE: Zufällige Nonce. EN: Random nonce.
    pub nonce: [u8; NONCE_LEN],
    /// DE: Chiffrat inklusive 16-Byte-Tag am Ende. EN: Ciphertext incl. trailing 16-byte tag.
    pub ciphertext: Vec<u8>,
}

/// DE: Erzeugt einen neuen AES-256-Schlüssel aus dem OS-CSPRNG.
/// EN: Generates a new AES-256 key from the OS CSPRNG.
///
/// # Errors
/// DE/EN: [`Error::Rng`].
pub fn generate_key() -> Result<SecretBytes> {
    rng::secret(KEY_LEN)
}

fn cipher(key: &[u8]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidInput { field: "key" })
}

/// DE: Verschlüsselt `plaintext` und authentifiziert zusätzlich `aad`.
/// EN: Encrypts `plaintext` and additionally authenticates `aad`.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (Schlüssellänge / key length), [`Error::Rng`], [`Error::Crypto`].
pub fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let cipher = cipher(key)?;
    let nonce = rng::array::<NONCE_LEN>()?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::<Aes256Gcm>::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    Ok(Sealed { nonce, ciphertext })
}

/// DE: Entschlüsselt und prüft den Tag. Jede Abweichung (Schlüssel, Nonce,
/// Chiffrat, Tag, AAD, Länge) führt zu [`Error::Decrypt`] ohne Klartext.
/// EN: Decrypts and verifies the tag. Any mismatch (key, nonce, ciphertext,
/// tag, AAD, length) results in [`Error::Decrypt`] without plaintext.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`], [`Error::Decrypt`].
pub fn open(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<SecretBytes> {
    let cipher = cipher(key)?;
    let nonce = <[u8; NONCE_LEN]>::try_from(nonce).map_err(|_| Error::Decrypt)?;
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Decrypt);
    }
    let plaintext = cipher
        .decrypt(
            &Nonce::<Aes256Gcm>::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(SecretBytes::new(plaintext))
}
