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
use crate::{Error, Result};

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
    inner: SecretBuffer<u8>,
}

impl SecretBytes {
    /// DE: Übernimmt ohne Kopie, verweigert ungesperrten Speicher.
    /// EN: Takes ownership without copying; refuses unlocked memory.
    /// # Errors
    /// DE/EN: [`Error::MemoryLock`].
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self {
            inner: SecretBuffer::new(bytes)?,
        })
    }

    /// DE: Reserviert und sperrt vor dem Schreiben geheimer Daten.
    /// EN: Allocates and locks before writing secret data.
    /// # Errors
    /// DE/EN: [`Error::MemoryLock`].
    pub fn zeroed(len: usize) -> Result<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| Error::MemoryLock)?;
        bytes.resize(len, 0);
        Self::new(bytes)
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
    /// DE/EN: [`Error::MemoryLock`].
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut out = Self::zeroed(bytes.len())?;
        out.expose_mut().copy_from_slice(bytes);
        Ok(out)
    }

    /// DE: Kürzt und löscht den entfernten Teil ohne Reallokation.
    /// EN: Truncates and wipes the removed tail without reallocating.
    pub fn truncate(&mut self, len: usize) {
        self.inner.truncate(len);
    }

    /// DE: Lesender Zugriff auf die geheimen Bytes. Nicht loggen!
    /// EN: Read access to the secret bytes. Do not log!
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.inner.expose()
    }

    /// DE: Schreibender Zugriff auf den bereits gesperrten Speicher.
    /// EN: Write access to already locked storage.
    pub fn expose_mut(&mut self) -> &mut [u8] {
        self.inner.expose_mut()
    }

    /// DE: Länge in Bytes. EN: Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.expose().len()
    }

    /// DE: `true`, wenn leer. EN: `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.expose().is_empty()
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl ZeroizeOnDrop for SecretBytes {}
