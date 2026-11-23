//! DE: Gesperrte Ownership bis zum letzten HTTP-Bytes-Owner.
//! EN: Locked ownership through the last HTTP Bytes owner.

use crate::crypto::SecretBytes;
use hyper::body::Bytes;
use hyper::rt::ProtectedReadBuffer;
use std::io;
use zeroize::Zeroize;

pub(super) const MAX_CAPACITY: usize = 16 * 1024;

pub(super) struct ProtectedBuffer {
    storage: SecretBytes,
    filled: usize,
}

#[cfg(test)]
#[path = "protected_buffer_tests.rs"]
mod tests;

fn failure() -> io::Error {
    io::Error::other("protected HTTP buffer unavailable")
}

impl ProtectedBuffer {
    pub(super) fn new(capacity: usize) -> io::Result<Self> {
        if capacity > MAX_CAPACITY {
            return Err(failure());
        }
        Ok(Self {
            storage: SecretBytes::zeroed(capacity).map_err(|_| failure())?,
            filled: 0,
        })
    }
}

struct Owner(SecretBytes);
impl AsRef<[u8]> for Owner {
    fn as_ref(&self) -> &[u8] {
        self.0.expose()
    }
}

impl ProtectedReadBuffer for ProtectedBuffer {
    fn bytes(&self) -> &[u8] {
        &self.storage.expose()[..self.filled]
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.storage.expose_mut()[..self.filled]
    }
    fn capacity(&self) -> usize {
        self.storage.len()
    }

    fn reserve(&mut self, additional: usize) -> io::Result<()> {
        let needed = self.filled.checked_add(additional).ok_or_else(failure)?;
        if needed > MAX_CAPACITY {
            return Err(failure());
        }
        if needed > self.capacity() {
            let capacity = needed
                .max(self.capacity().saturating_mul(2))
                .min(MAX_CAPACITY);
            let mut next = SecretBytes::zeroed(capacity).map_err(|_| failure())?;
            next.expose_mut()[..self.filled].copy_from_slice(self.bytes());
            self.storage = next;
        }
        Ok(())
    }

    fn spare_mut(&mut self) -> &mut [u8] {
        &mut self.storage.expose_mut()[self.filled..]
    }

    fn commit(&mut self, count: usize) {
        assert!(count <= self.capacity() - self.filled);
        self.filled += count;
    }

    fn discard(&mut self, count: usize) {
        assert!(count <= self.filled);
        self.storage.expose_mut().copy_within(count..self.filled, 0);
        let remaining = self.filled - count;
        self.storage.expose_mut()[remaining..self.filled].zeroize();
        self.filled = remaining;
    }

    fn split(&mut self, count: usize) -> io::Result<Box<dyn ProtectedReadBuffer>> {
        if count > self.filled {
            return Err(failure());
        }
        let storage = SecretBytes::from_slice(&self.bytes()[..count]).map_err(|_| failure())?;
        self.discard(count);
        Ok(Box::new(Self {
            storage,
            filled: count,
        }))
    }

    fn sibling(&self, capacity: usize) -> io::Result<Box<dyn ProtectedReadBuffer>> {
        Ok(Box::new(Self::new(capacity)?))
    }

    fn freeze(self: Box<Self>) -> Bytes {
        let Self {
            mut storage,
            filled,
        } = *self;
        storage.truncate(filled);
        Bytes::from_owner(Owner(storage))
    }
}
