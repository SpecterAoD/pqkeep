//! DE: Container für geheime Bytes (Seeds, abgeleitete Schlüssel, Passphrasen).
//! Der Inhalt wird beim Freigeben überschrieben (best effort, siehe docs/CRYPTO.md).
//! Bewusst **kein** `Debug`, `Display`, `Clone` oder `Serialize`.
//!
//! EN: Container for secret bytes (seeds, derived keys, passphrases).
//! The content is overwritten on drop (best effort, see docs/CRYPTO.md).
//! Deliberately **no** `Debug`, `Display`, `Clone` or `Serialize`.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// DE: Geheime Bytefolge, die beim Drop genullt wird.
/// EN: Secret byte sequence that is zeroed on drop.
pub struct SecretBytes {
    inner: Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    /// DE: Übernimmt den Vektor (ohne Kopie).
    /// EN: Takes ownership of the vector (no copy).
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Zeroizing::new(bytes),
        }
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

// DE: `Zeroizing<Vec<u8>>` nullt beim Drop; damit ist die Zusicherung erfüllt.
// EN: `Zeroizing<Vec<u8>>` zeroes on drop, which satisfies the guarantee.
impl ZeroizeOnDrop for SecretBytes {}
