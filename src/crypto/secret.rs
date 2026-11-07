//! DE: Container für geheime Bytes (Seeds, abgeleitete Schlüssel, Passphrasen).
//! Die Speicherseiten werden gesperrt (kein Swap, best effort) und der Inhalt
//! beim Freigeben überschrieben. Reihenfolge: nullen → entsperren → freigeben.
//! Siehe `docs/MEMORY_HARDENING.md`.
//! Bewusst **kein** `Debug`, `Display`, `Clone` oder `Serialize`.
//!
//! EN: Container for secret bytes (seeds, derived keys, passphrases).
//! The memory pages are locked (no swap, best effort) and the content is
//! overwritten on drop. Order: zero → unlock → free.
//! See `docs/MEMORY_HARDENING.md`.
//! Deliberately **no** `Debug`, `Display`, `Clone` or `Serialize`.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hardening::memlock::{self, LockedRange};

/// DE: Geheime Bytefolge, die beim Drop genullt wird.
/// EN: Secret byte sequence that is zeroed on drop.
///
/// DE: Die folgenden Beispiele dürfen **nicht** kompilieren (kein `Debug`/`Clone`).
/// EN: The following examples must **not** compile (no `Debug`/`Clone`).
///
/// ```compile_fail
/// let s = pqkeep::crypto::SecretBytes::new(vec![1, 2, 3]);
/// println!("{s:?}");
/// ```
///
/// ```compile_fail
/// let s = pqkeep::crypto::SecretBytes::new(vec![1, 2, 3]);
/// let t = s.clone();
/// ```
pub struct SecretBytes {
    inner: Zeroizing<Vec<u8>>,
    lock: Option<LockedRange>,
}

impl SecretBytes {
    /// DE: Übernimmt den Vektor (ohne Kopie).
    /// EN: Takes ownership of the vector (no copy).
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        let lock = (bytes.capacity() > 0)
            .then(|| memlock::lock_range(bytes.as_ptr().addr(), bytes.capacity()));
        Self {
            inner: Zeroizing::new(bytes),
            lock,
        }
    }

    /// DE: `true`, wenn alle Seiten des Puffers gesperrt sind (leer zählt als gesperrt).
    /// EN: `true` if all pages of the buffer are locked (empty counts as locked).
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.lock
            .as_ref()
            .is_none_or(|l| l.complete(self.inner.as_ptr().addr(), self.inner.capacity()))
    }

    /// DE: Kopiert aus einem Slice; die Quelle muss der Aufrufer selbst löschen.
    /// EN: Copies from a slice; the caller is responsible for wiping the source.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    /// DE: Lesender Zugriff auf die geheimen Bytes. Nicht loggen!
    /// EN: Read access to the secret bytes. Do not log!
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    /// DE: Schreibender Zugriff, nur innerhalb der Bibliothek.
    /// EN: Write access, library-internal only.
    pub(crate) fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// DE: Länge in Bytes. EN: Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// DE: `true`, wenn leer. EN: `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // DE: Erst nullen, dann entsperren; freigegeben wird danach beim Drop von `inner`.
        // EN: Zero first, then unlock; `inner` is freed afterwards when it is dropped.
        self.inner.zeroize();
        self.lock.take();
    }
}

impl ZeroizeOnDrop for SecretBytes {}
