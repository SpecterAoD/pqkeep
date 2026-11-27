//! DE: Zugangstoken der API. Ein Token besteht aus 256 Bit Zufall (Präfix `pqk1_`,
//! Base64url). Gespeichert wird nur der SHA3-256-Hash in einer Datei (Linux 0600);
//! das Token selbst wird genau einmal angezeigt. Der Vergleich erfolgt in konstanter
//! Zeit über die Hashes. Tokens aus Umgebungsvariablen werden bewusst nicht unterstützt.
//!
//! EN: API access token. A token consists of 256 bits of randomness (prefix `pqk1_`,
//! base64url). Only the SHA3-256 hash is stored in a file (Linux 0600); the token
//! itself is shown exactly once. Comparison is done in constant time on the hashes.
//! Tokens from environment variables are deliberately not supported.

use std::path::Path;

use sha3::Sha3_256;
use subtle::ConstantTimeEq;

use crate::crypto::{SecretBytes, locked_hash::LockedHash, rng};
use crate::envelope::{Overwrite, hex_decode, hex_encode, read_limited, write_atomic};
use crate::{Error, Result};

/// DE: Präfix jedes Tokens (erleichtert Secret-Scannern das Erkennen).
/// EN: Prefix of every token (helps secret scanners recognise it).
pub const TOKEN_PREFIX: &str = "pqk1_";
/// DE: Kennung am Anfang der Hash-Datei. EN: Tag at the start of the hash file.
const FILE_TAG: &str = "pqkeep-token-v1 sha3-256 ";
/// DE: Länge des Hashes in Byte. EN: Hash length in bytes.
const HASH_LEN: usize = 32;
/// DE: Höchstlänge eines vorgelegten Tokens. EN: Maximum length of a presented token.
const MAX_TOKEN_CHARS: usize = 128;

/// DE: Gespeicherter Hash eines Tokens (kein Geheimnis im engeren Sinn).
/// EN: Stored hash of a token (not a secret in the strict sense).
#[derive(Clone)]
pub struct TokenHash([u8; HASH_LEN]);

impl TokenHash {
    /// DE: Hash eines Tokens. EN: Hash of a token.
    /// # Errors
    /// DE/EN: [`Error::MemoryLock`] bei fehlender Sperre / unavailable lock.
    pub fn of(token: &str) -> Result<Self> {
        let mut hash = LockedHash::<Sha3_256>::new()?;
        hash.update(token.as_bytes());
        Ok(Self(
            hash.finalize()?
                .expose()
                .try_into()
                .map_err(|_| Error::Crypto)?,
        ))
    }

    /// DE: Prüft ein vorgelegtes Token in konstanter Zeit (bezogen auf den Hash).
    /// EN: Checks a presented token in constant time (with respect to the hash).
    /// # Errors
    /// DE/EN: [`Error::MemoryLock`] bei fehlender Sperre / unavailable lock.
    pub fn verify(&self, presented: &str) -> Result<bool> {
        if presented.len() > MAX_TOKEN_CHARS {
            return Ok(false);
        }
        let candidate = Self::of(presented)?;
        Ok(bool::from(self.0.ct_eq(&candidate.0)))
    }

    /// DE: Liest den Hash aus einer Token-Datei.
    /// EN: Reads the hash from a token file.
    ///
    /// # Errors
    /// DE/EN: [`Error::Io`], [`Error::InvalidInput`] (`token-file`).
    pub fn load(path: &Path) -> Result<Self> {
        let text = read_limited(path)?;
        let invalid = Error::InvalidInput {
            field: "token-file",
        };
        let hex = text
            .trim_end()
            .strip_prefix(FILE_TAG)
            .ok_or(invalid.clone())?;
        let bytes = hex_decode(hex, HASH_LEN, "token-file")?;
        let hash: [u8; HASH_LEN] = bytes.try_into().map_err(|_| invalid)?;
        Ok(Self(hash))
    }
}

/// DE: Gesperrter Token, nur bewusstes Ausleihen für Prüfung/einmalige Anzeige.
/// EN: Locked token, explicit borrowing only for verification/one-time display.
pub struct SecretToken(SecretBytes);

impl SecretToken {
    /// DE: Nur am beabsichtigten Ausgabepunkt verwenden; nicht loggen.
    /// EN: Use only at the intended disclosure boundary; never log.
    /// # Errors
    /// DE/EN: [`Error::Crypto`] bei ungültiger interner UTF-8 / invalid internal UTF-8.
    pub fn expose(&self) -> Result<&str> {
        // DE: Nur gültiges ASCII-Präfix und Base64 werden intern geschrieben.
        // EN: Only valid ASCII prefix and Base64 are written internally.
        std::str::from_utf8(self.0.expose()).map_err(|_| Error::Crypto)
    }
}

/// DE: Erzeugt ein neues Token und speichert dessen Hash unter `path`.
/// Rückgabe: das Token (nur zur einmaligen Anzeige, wird beim Drop genullt).
/// EN: Creates a new token and stores its hash at `path`.
/// Returns the token (for one-time display only, zeroed on drop).
///
/// # Errors
/// DE/EN: [`Error::Rng`], [`Error::Io`] (u. a. `AlreadyExists` ohne / without `Overwrite::Yes`).
pub fn create(path: &Path, overwrite: Overwrite) -> Result<SecretToken> {
    let raw = rng::secret(32)?;
    let mut bytes = SecretBytes::zeroed(TOKEN_PREFIX.len() + 43)?;
    bytes.expose_mut()[..TOKEN_PREFIX.len()].copy_from_slice(TOKEN_PREFIX.as_bytes());
    super::token_encoding::encode(raw.expose(), &mut bytes.expose_mut()[TOKEN_PREFIX.len()..])?;
    let token = SecretToken(bytes);
    let hash = TokenHash::of(token.expose()?)?;
    let line = format!("{FILE_TAG}{}\n", hex_encode(&hash.0));
    write_atomic(path, line.as_bytes(), overwrite)?;
    Ok(token)
}
