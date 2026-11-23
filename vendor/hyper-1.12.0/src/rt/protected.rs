//! DE: Injizierbare Ownership für vor dem Lesen geschützte Puffer.
//! EN: Injectable ownership for buffers protected before reading.

use bytes::{Buf, Bytes, BytesMut};
use std::{fmt, io, ops::{Deref, DerefMut}};

/// DE: Der Host sperrt vor Read/Kopie und löscht vor Unlock/Free.
/// EN: The host locks before read/copy and wipes before unlock/free.
pub trait ProtectedReadBuffer: Send {
    /// DE/EN: Aktuell belegte Bytes / currently filled bytes.
    fn bytes(&self) -> &[u8];
    /// DE/EN: Veränderbare belegte Bytes / mutable filled bytes.
    fn bytes_mut(&mut self) -> &mut [u8];
    /// DE/EN: Vorab geschützte Gesamtkapazität / protected total capacity.
    fn capacity(&self) -> usize;
    /// DE/EN: Zusätzlichen Platz vor jeder Kopie schützen / protect before any copy.
    fn reserve(&mut self, additional: usize) -> io::Result<()>;
    /// DE/EN: Geschütztes initialisiertes Leseziel / protected initialized read target.
    fn spare_mut(&mut self) -> &mut [u8];
    /// DE/EN: Nach erfolgreichem Read gültige Länge erhöhen / commit successful read.
    fn commit(&mut self, count: usize);
    /// DE/EN: Präfix verwerfen und löschen / discard and wipe prefix.
    fn discard(&mut self, count: usize);
    /// DE/EN: Präfix nur in vorab geschütztes Ziel übertragen / protected prefix split.
    fn split(&mut self, count: usize) -> io::Result<Box<dyn ProtectedReadBuffer>>;
    /// DE/EN: Leeren gleichartig geschützten Puffer anlegen / protected sibling buffer.
    fn sibling(&self, capacity: usize) -> io::Result<Box<dyn ProtectedReadBuffer>>;
    /// DE/EN: Guard bleibt Teil des Bytes-Owners / retain guard in Bytes owner.
    fn freeze(self: Box<Self>) -> Bytes;
}

pub(crate) enum ReadBuffer {
    Standard { storage: BytesMut, filled: usize },
    Protected(Box<dyn ProtectedReadBuffer>),
}

impl ReadBuffer {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        let mut storage = BytesMut::with_capacity(capacity);
        storage.resize(storage.capacity(), 0);
        Self::Standard { storage, filled: 0 }
    }

    pub(crate) fn capacity(&self) -> usize {
        match self {
            Self::Standard { storage, .. } => storage.capacity(),
            Self::Protected(inner) => inner.capacity(),
        }
    }

    pub(crate) fn reserve(&mut self, additional: usize) -> io::Result<()> {
        match self {
            Self::Standard { storage, filled } => {
                if storage.capacity() - *filled < additional {
                    storage.truncate(*filled);
                    storage.reserve(additional);
                    storage.resize(storage.capacity(), 0);
                }
                Ok(())
            }
            Self::Protected(inner) => inner.reserve(additional),
        }
    }

    pub(crate) fn spare_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Standard { storage, filled } => &mut storage[*filled..],
            Self::Protected(inner) => inner.spare_mut(),
        }
    }

    pub(crate) fn commit(&mut self, count: usize) {
        match self {
            Self::Standard { storage, filled } => {
                assert!(count <= storage.len() - *filled);
                *filled += count;
            }
            Self::Protected(inner) => inner.commit(count),
        }
    }

    pub(crate) fn advance(&mut self, count: usize) {
        match self {
            Self::Standard { storage, filled } => {
                assert!(count <= *filled);
                storage.advance(count);
                *filled -= count;
            }
            Self::Protected(inner) => inner.discard(count),
        }
    }

    pub(crate) fn split_to(&mut self, count: usize) -> io::Result<Self> {
        match self {
            Self::Standard { storage, filled } => {
                assert!(count <= *filled);
                let part = storage.split_to(count);
                *filled -= count;
                Ok(Self::Standard { storage: part, filled: count })
            }
            Self::Protected(inner) => inner.split(count).map(Self::Protected),
        }
    }

    pub(crate) fn sibling(&self, capacity: usize) -> io::Result<Self> {
        match self {
            Self::Standard { .. } => Ok(Self::with_capacity(capacity)),
            Self::Protected(inner) => inner.sibling(capacity).map(Self::Protected),
        }
    }

    pub(crate) fn freeze(self) -> Bytes {
        match self {
            Self::Standard { mut storage, filled } => {
                storage.truncate(filled);
                storage.freeze()
            }
            Self::Protected(inner) => inner.freeze(),
        }
    }

    pub(crate) fn try_put_u8(&mut self, byte: u8) -> io::Result<()> {
        self.reserve(1)?;
        self.spare_mut()[0] = byte;
        self.commit(1);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len()).unwrap();
        self.spare_mut()[..bytes.len()].copy_from_slice(bytes);
        self.commit(bytes.len());
    }

    #[cfg(test)]
    pub(crate) fn reset_fixture(&mut self, bytes: &[u8]) {
        self.advance(self.len());
        self.extend_from_slice(bytes);
    }

}

impl Deref for ReadBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Standard { storage, filled } => &storage[..*filled],
            Self::Protected(inner) => inner.bytes(),
        }
    }
}

impl DerefMut for ReadBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Standard { storage, filled } => &mut storage[..*filled],
            Self::Protected(inner) => inner.bytes_mut(),
        }
    }
}

impl AsRef<[u8]> for ReadBuffer {
    fn as_ref(&self) -> &[u8] { self }
}

impl fmt::Debug for ReadBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadBuffer").field("len", &self.len())
            .field("capacity", &self.capacity()).finish()
    }
}

impl From<&[u8]> for ReadBuffer {
    fn from(bytes: &[u8]) -> Self {
        let mut out = Self::with_capacity(bytes.len());
        out.spare_mut()[..bytes.len()].copy_from_slice(bytes);
        out.commit(bytes.len());
        out
    }
}

impl From<&str> for ReadBuffer {
    fn from(text: &str) -> Self { Self::from(text.as_bytes()) }
}

impl From<BytesMut> for ReadBuffer {
    fn from(mut storage: BytesMut) -> Self {
        let filled = storage.len();
        storage.resize(storage.capacity(), 0);
        Self::Standard { storage, filled }
    }
}

impl PartialEq for ReadBuffer {
    fn eq(&self, other: &Self) -> bool { self.as_ref() == other.as_ref() }
}
