//! DE: Geprüfte Identität ohne ungesperrte Hash-/Descriptor-Kopie.
//! EN: Verified identity without an unlocked hash or descriptor copy.

use crate::Result;
use crate::crypto::{SecretBytes, locked_hash::LockedHash, secret_state::SecretState};
use sha3::Sha3_256;
use std::fmt;

/// DE: Geprüfter Absender; Identität nur ausdrücklich ausleihen.
/// EN: Verified sender; borrow identity only by explicit disclosure.
pub struct SignedBy(SecretState<SecretBytes>);

impl SignedBy {
    pub(super) fn from_public_key(key: &[u8]) -> Result<Self> {
        let mut out = Self::prepare()?;
        let mut hash = LockedHash::<Sha3_256>::new()?;
        hash.update(key);
        *out.0.get_mut() = hash.finalize()?;
        Ok(out)
    }

    pub(super) fn from_key_id(id: &[u8]) -> Result<Self> {
        let mut out = Self::prepare()?;
        *out.0.get_mut() = SecretBytes::from_slice(id)?;
        Ok(out)
    }

    fn prepare() -> Result<Self> {
        Ok(Self(SecretState::new(SecretBytes::zeroed(0)?)?))
    }

    /// DE: SHA3-256 des Absenderschlüssels; nur für angeforderte Ausgabe.
    /// EN: Sender key SHA3-256; only for requested disclosure.
    #[must_use]
    pub fn key_id(&self) -> &[u8] {
        self.0.get().expose()
    }

    /// DE: Ziel vor der expliziten Kopie sperren; kein Clone-Fallback.
    /// EN: Lock before explicit duplication; no Clone fallback.
    /// # Errors
    /// DE/EN: [`crate::Error::MemoryLock`].
    pub fn try_duplicate(&self) -> Result<Self> {
        Self::from_key_id(self.key_id())
    }
}

impl PartialEq for SignedBy {
    fn eq(&self, other: &Self) -> bool {
        self.key_id() == other.key_id()
    }
}
impl Eq for SignedBy {}

impl fmt::Debug for SignedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedBy([REDACTED])")
    }
}

#[cfg(test)]
#[path = "signed_by_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "signed_by_denial_tests.rs"]
mod denial_tests;
