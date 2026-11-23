//! DE: AES-256-GCM (authentifizierte Verschlüsselung) und Erzeugung von
//! AES-256-Schlüsseln. Nonce: 96 Bit, pro Verschlüsselung neu aus dem OS-CSPRNG.
//! Der Tag-Vergleich erfolgt in der Crate in konstanter Zeit.
//!
//! EN: AES-256-GCM (authenticated encryption) and generation of AES-256 keys.
//! Nonce: 96 bits, freshly drawn from the OS CSPRNG for every encryption.
//! The tag comparison is constant-time inside the crate.

use aes_gcm::aead::{AeadInOut, Nonce, consts};

use super::secret_state::SecretState;
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

// DE: Ausschließlich öffentlicher Initialzustand vor dem Sperren.
// EN: Public initial state only, before locking.
fn public_cipher() -> Aes256Gcm {
    Aes256Gcm::new(&aes_gcm::Key::<Aes256Gcm>::default())
}

pub(crate) fn cipher(key: &[u8]) -> Result<SecretState<Aes256Gcm>> {
    let mut state = SecretState::new(public_cipher())?;
    *state.get_mut() =
        Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidInput { field: "key" })?;
    Ok(state)
}

/// DE: Verschlüsselt `plaintext` und authentifiziert zusätzlich `aad`.
/// EN: Encrypts `plaintext` and additionally authenticates `aad`.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (Schlüssellänge / key length), [`Error::Rng`], [`Error::Crypto`].
pub fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let cipher = cipher(key)?;
    let nonce = rng::array::<NONCE_LEN>()?;
    let ciphertext = seal_locked(cipher.get(), nonce, plaintext, aad)?;
    Ok(Sealed { nonce, ciphertext })
}

/// DE: Wie [`seal`], aber mit vorgegebener Nonce (Format v2: die Nonce steht im Header und ist
/// Teil der AAD, muss also vorher feststehen). Der Aufrufer muss die Nonce frisch und zufällig
/// wählen und darf sie je Schlüssel nur einmal verwenden.
/// EN: Like [`seal`] but with a given nonce (format v2: the nonce is part of the header and of
/// the AAD, so it must be fixed beforehand). The caller must pick a fresh random nonce and use
/// it only once per key.
pub(crate) fn seal_with_nonce(
    key: &[u8],
    nonce: [u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    seal_locked(cipher(key)?.get(), nonce, plaintext, aad)
}

// DE: Keine ungesperrte Klartextkopie im allokierenden AEAD-Komfortadapter.
// EN: Never pass plaintext through the allocating AEAD convenience adapter.
pub(crate) fn seal_locked<C>(
    cipher: &C,
    nonce: [u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>>
where
    C: AeadInOut<NonceSize = consts::U12, TagSize = consts::U16>,
{
    let mut work = SecretBytes::from_slice(plaintext)?;
    let tag = cipher
        .encrypt_inout_detached(&Nonce::<C>::from(nonce), aad, work.expose_mut().into())
        .map_err(|_| Error::Crypto)?;
    // DE: Erst nach erfolgreicher Verschlüsselung in öffentlichen Speicher kopieren.
    // EN: Copy to public storage only after successful encryption.
    let mut ciphertext = Vec::new();
    ciphertext
        .try_reserve_exact(work.len().checked_add(TAG_LEN).ok_or(Error::Crypto)?)
        .map_err(|_| Error::Crypto)?;
    ciphertext.extend_from_slice(work.expose());
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
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
    let n = ciphertext.len() - TAG_LEN;
    let mut plaintext = SecretBytes::from_slice(&ciphertext[..n])?;
    let tag = <[u8; TAG_LEN]>::try_from(&ciphertext[n..]).map_err(|_| Error::Decrypt)?;
    cipher
        .get()
        .decrypt_inout_detached(
            &Nonce::<Aes256Gcm>::from(nonce),
            aad,
            plaintext.expose_mut().into(),
            &tag.into(),
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(plaintext)
}

#[cfg(test)]
#[path = "aead_locked_tests.rs"]
mod tests;
