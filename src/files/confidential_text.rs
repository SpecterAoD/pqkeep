//! DE: Gesperrte UTF-8-Metadaten mit expliziter, fallibler Weitergabe.
//! EN: Locked UTF-8 metadata with explicit fallible disclosure.

use crate::{Error, Result, crypto::SecretBytes};
use std::{borrow::Borrow, cmp::Ordering, fmt};
use zeroize::Zeroize;

/// DE: Vertraulicher Archivtext; kein Clone/Display/Serialize, Debug bleibt redigiert.
/// EN: Confidential archive text; no Clone/Display/Serialize, Debug stays redacted.
pub struct ConfidentialText(SecretBytes);

impl Zeroize for ConfidentialText {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ConfidentialText {
    /// DE: Ziel vor der Kopie sperren; Quell-Ownership bleibt beim Caller.
    /// EN: Lock before copying; the caller retains source ownership.
    /// # Errors
    /// DE/EN: [`Error::MemoryLock`].
    pub fn from_text(text: &str) -> Result<Self> {
        Ok(Self(SecretBytes::from_slice(text.as_bytes())?))
    }

    pub(crate) fn from_locked(bytes: SecretBytes) -> Result<Self> {
        std::str::from_utf8(bytes.expose()).map_err(|_| Error::InvalidInput { field: "path" })?;
        Ok(Self(bytes))
    }

    /// DE: Nur für bewusst angeforderte Ausgabe ausleihen, nicht loggen.
    /// EN: Borrow only for requested disclosure, never log.
    /// # Errors
    /// DE/EN: [`Error::Crypto`] bei ungültigem internem UTF-8 / invalid internal UTF-8.
    pub fn expose(&self) -> Result<&str> {
        std::str::from_utf8(self.0.expose()).map_err(|_| Error::Crypto)
    }

    /// DE: Explizite Kopie erst nach bestätigter Zielsperre.
    /// EN: Explicit duplication only after destination lock confirmation.
    /// # Errors
    /// DE/EN: [`Error::MemoryLock`].
    pub fn try_duplicate(&self) -> Result<Self> {
        Ok(Self(SecretBytes::from_slice(self.0.expose())?))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.expose()
    }
}

impl Borrow<[u8]> for ConfidentialText {
    fn borrow(&self) -> &[u8] {
        self.bytes()
    }
}
impl PartialEq for ConfidentialText {
    fn eq(&self, other: &Self) -> bool {
        self.bytes() == other.bytes()
    }
}
impl Eq for ConfidentialText {}
impl PartialOrd for ConfidentialText {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ConfidentialText {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes().cmp(other.bytes())
    }
}
impl fmt::Debug for ConfidentialText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
