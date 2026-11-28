//! DE: Gesperrte UTF-8-Metadaten mit expliziter, fallibler Weitergabe.
//! EN: Locked UTF-8 metadata with explicit fallible disclosure.

use crate::crypto::secret_state::SecretState;
use crate::{Error, Result, crypto::SecretBytes};
use std::{borrow::Borrow, cmp::Ordering, fmt};
use zeroize::Zeroize;

/// DE: Vertraulicher Archivtext; kein Clone/Display/Serialize, Debug bleibt redigiert.
/// EN: Confidential archive text; no Clone/Display/Serialize, Debug stays redacted.
pub struct ConfidentialText(SecretState<SecretBytes>);

impl Zeroize for ConfidentialText {
    fn zeroize(&mut self) {
        self.0.get_mut().zeroize();
    }
}

impl ConfidentialText {
    pub(crate) fn joined(left: &str, right: &str) -> Result<Self> {
        let len = left
            .len()
            .checked_add(right.len())
            .ok_or(Error::MemoryLock)?;
        let mut bytes = SecretBytes::zeroed(len)?;
        bytes.expose_mut()[..left.len()].copy_from_slice(left.as_bytes());
        bytes.expose_mut()[left.len()..].copy_from_slice(right.as_bytes());
        Self::from_locked(bytes)
    }

    pub(crate) fn prepare() -> Result<Self> {
        Ok(Self(SecretState::new(SecretBytes::zeroed(0)?)?))
    }

    pub(crate) fn copy_from(&mut self, source: &Self) -> Result<()> {
        *self.0.get_mut() = SecretBytes::from_slice(source.bytes())?;
        Ok(())
    }

    /// DE: Ziel vor der Kopie sperren; Quell-Ownership bleibt beim Caller.
    /// EN: Lock before copying; the caller retains source ownership.
    /// # Errors
    /// DE/EN: [`Error::MemoryLock`].
    pub fn from_text(text: &str) -> Result<Self> {
        let mut out = Self::prepare()?;
        *out.0.get_mut() = SecretBytes::from_slice(text.as_bytes())?;
        Ok(out)
    }

    pub(crate) fn from_locked(bytes: SecretBytes) -> Result<Self> {
        let mut out = Self::prepare()?;
        *out.0.get_mut() = bytes;
        std::str::from_utf8(out.bytes()).map_err(|_| Error::InvalidInput { field: "path" })?;
        Ok(out)
    }

    /// DE: Nur für bewusst angeforderte Ausgabe ausleihen, nicht loggen.
    /// EN: Borrow only for requested disclosure, never log.
    /// # Errors
    /// DE/EN: [`Error::Crypto`] bei ungültigem internem UTF-8 / invalid internal UTF-8.
    pub fn expose(&self) -> Result<&str> {
        std::str::from_utf8(self.bytes()).map_err(|_| Error::Crypto)
    }

    /// DE: Explizite Kopie erst nach bestätigter Zielsperre.
    /// EN: Explicit duplication only after destination lock confirmation.
    /// # Errors
    /// DE/EN: [`Error::MemoryLock`].
    pub fn try_duplicate(&self) -> Result<Self> {
        let mut out = Self::prepare()?;
        out.copy_from(self)?;
        Ok(out)
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.get().expose()
    }
}

#[cfg(test)]
#[path = "confidential_text_tests.rs"]
mod tests;

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
