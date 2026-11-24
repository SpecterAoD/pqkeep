//! DE: Container für geheime Bytes (Seeds, abgeleitete Schlüssel, Passphrasen).
//! Die Speicherseiten werden gesperrt (kein ungesperrter Fallback) und der Inhalt
//! beim Freigeben überschrieben. Reihenfolge: nullen → entsperren → freigeben.
//! Siehe `docs/MEMORY_HARDENING.md`.
//! Bewusst **kein** `Debug`, `Display`, `Clone` oder `Serialize`.
//!
//! EN: Container for secret bytes (seeds, derived keys, passphrases).
//! The memory pages are locked (no unlocked fallback) and the content is
//! overwritten on drop. Order: zero → unlock → free.
//! See `docs/MEMORY_HARDENING.md`.
//! Deliberately **no** `Debug`, `Display`, `Clone` or `Serialize`.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::secret_buffer::SecretBuffer;
use super::secret_state::SecretState;
use crate::Result;

/// DE: Geheime Bytefolge, die beim Drop genullt wird.
/// EN: Secret byte sequence that is zeroed on drop.
///
/// DE: Die folgenden Beispiele dürfen **nicht** kompilieren (kein `Debug`/`Clone`).
/// EN: The following examples must **not** compile (no `Debug`/`Clone`).
///
/// ```compile_fail
/// let s = pqkeep::crypto::SecretBytes::new(vec![1, 2, 3]).unwrap();
/// println!("{s:?}");
/// ```
///
/// ```compile_fail
/// let s = pqkeep::crypto::SecretBytes::new(vec![1, 2, 3]).unwrap();
/// let t = s.clone();
/// ```
pub struct SecretBytes {
    inner: SecretState<SecretBuffer<u8>>,
}

impl SecretBytes {
    /// DE: Übernimmt ohne Kopie, verweigert ungesperrten Speicher.
    /// EN: Takes ownership without copying; refuses unlocked memory.
    /// # Errors
    /// DE/EN: [`crate::Error::MemoryLock`].
    pub fn new(mut bytes: Vec<u8>) -> Result<Self> {
        let mut out = match Self::prepare() {
            Ok(out) => out,
            Err(error) => {
                bytes.zeroize();
                bytes.spare_capacity_mut().zeroize();
                return Err(error);
            }
        };
        out.inner.get_mut().adopt_locked(bytes)?;
        Ok(out)
    }

    fn prepare() -> Result<Self> {
        Ok(Self {
            inner: SecretState::new(SecretBuffer::new(Vec::new())?)?,
        })
    }

    /// DE: Reserviert und sperrt vor dem Schreiben geheimer Daten.
    /// EN: Allocates and locks before writing secret data.
    /// # Errors
    /// DE/EN: [`crate::Error::MemoryLock`].
    pub fn zeroed(len: usize) -> Result<Self> {
        let mut out = Self::prepare()?;
        out.inner.get_mut().initialize_zeroed(len)?;
        Ok(out)
    }

    /// DE: Existierende Instanzen sind stets vollständig gesperrt.
    /// EN: Existing instances are always fully locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        true
    }

    /// DE: Sperrt das Ziel vor dem Kopieren; Quelle bleibt beim Aufrufer.
    /// EN: Locks the destination before copying; caller owns the source.
    /// # Errors
    /// DE/EN: [`crate::Error::MemoryLock`].
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut out = Self::zeroed(bytes.len())?;
        out.expose_mut().copy_from_slice(bytes);
        Ok(out)
    }

    /// DE: Kürzt und löscht den entfernten Teil ohne Reallokation.
    /// EN: Truncates and wipes the removed tail without reallocating.
    pub fn truncate(&mut self, len: usize) {
        self.inner.get_mut().truncate(len);
    }

    /// DE: Lesender Zugriff auf die geheimen Bytes. Nicht loggen!
    /// EN: Read access to the secret bytes. Do not log!
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.inner.get().expose()
    }

    /// DE: Schreibender Zugriff auf den bereits gesperrten Speicher.
    /// EN: Write access to already locked storage.
    pub fn expose_mut(&mut self) -> &mut [u8] {
        self.inner.get_mut().expose_mut()
    }

    /// DE: Länge in Bytes. EN: Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.get().expose().len()
    }

    /// DE: `true`, wenn leer. EN: `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.get().expose().is_empty()
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.inner.get_mut().zeroize();
    }
}

impl ZeroizeOnDrop for SecretBytes {}

#[cfg(test)]
#[path = "secret_tests.rs"]
mod tests;
