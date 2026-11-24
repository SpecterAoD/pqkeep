//! DE: Fester, typisierter Secret-Puffer; Sperre vor Benutzung, Löschen vor Entsperren.
//! EN: Fixed typed secret buffer; lock before use, wipe before unlocking.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::secret_state::SecretState;
use crate::hardening::memlock::{self, LockedRange};
use crate::{Error, Result};

pub(crate) struct SecretBuffer<T: Zeroize> {
    inner: Vec<T>,
    lock: Option<LockedRange>,
}

impl<T: Zeroize> SecretBuffer<T> {
    pub(crate) fn new(mut inner: Vec<T>) -> Result<Self> {
        let lock = Self::lock_allocation(&mut inner)?;
        Ok(Self {
            inner,
            lock: Some(lock),
        })
    }

    fn lock_allocation(inner: &mut Vec<T>) -> Result<LockedRange> {
        let bytes = inner
            .capacity()
            .checked_mul(size_of::<T>())
            .ok_or(Error::MemoryLock)?;
        let lock = memlock::lock_range(inner.as_ptr().addr(), bytes);
        if !lock.complete(inner.as_ptr().addr(), bytes) {
            inner.zeroize();
            inner.spare_capacity_mut().zeroize();
            return Err(Error::MemoryLock);
        }
        Ok(lock)
    }

    pub(crate) fn expose(&self) -> &[T] {
        &self.inner
    }

    pub(crate) fn expose_mut(&mut self) -> &mut [T] {
        &mut self.inner
    }

    pub(crate) fn push_preallocated(&mut self, mut value: T) -> Result<()> {
        if self.inner.len() == self.inner.capacity() {
            value.zeroize();
            return Err(Error::MemoryLock);
        }
        self.inner.push(value);
        Ok(())
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        if len < self.inner.len() {
            self.inner[len..].iter_mut().for_each(Zeroize::zeroize);
            self.inner.truncate(len);
        }
    }

    // DE: Der Aufrufer hält den Descriptor bereits im gesperrten SecretState.
    // EN: The caller already holds the descriptor in a locked SecretState.
    pub(super) fn reserve_empty(&mut self, len: usize) -> Result<()> {
        if self.inner.capacity() != 0 {
            return Err(Error::MemoryLock);
        }
        self.inner
            .try_reserve_exact(len)
            .map_err(|_| Error::MemoryLock)?;
        match Self::lock_allocation(&mut self.inner) {
            Ok(lock) => self.lock = Some(lock),
            Err(error) => {
                // DE: Helper hat vor Unlock gelöscht; erst danach Allokation freigeben.
                // EN: Helper wiped before unlocking; only now release the allocation.
                self.inner = Vec::new();
                return Err(error);
            }
        }
        Ok(())
    }

    pub(super) fn adopt_locked(&mut self, mut bytes: Vec<T>) -> Result<()> {
        if self.inner.capacity() != 0 {
            bytes.zeroize();
            bytes.spare_capacity_mut().zeroize();
            return Err(Error::MemoryLock);
        }
        let lock = Self::lock_allocation(&mut bytes)?;
        self.inner = bytes;
        self.lock = Some(lock);
        Ok(())
    }
}

impl<T: Zeroize + Default> SecretBuffer<T> {
    pub(super) fn initialize_defaults(&mut self, len: usize) -> Result<()> {
        self.reserve_empty(len)?;
        self.inner.resize_with(len, T::default);
        Ok(())
    }
}

impl<T: Zeroize> SecretBuffer<T>
where
    Self: ZeroizeOnDrop,
{
    pub(super) fn prepare_state() -> Result<SecretState<Self>> {
        SecretState::new(Self::new(Vec::new())?)
    }

    // DE: Quelle nur ausleihen; keinen zusätzlichen privaten Vec-Descriptor bewegen.
    // EN: Borrow the source; do not move another private Vec descriptor.
    pub(super) fn prepare_state_or_wipe(source: &mut Vec<T>) -> Result<SecretState<Self>> {
        let state = Self::prepare_state();
        if state.is_err() {
            source.zeroize();
            source.spare_capacity_mut().zeroize();
        }
        state
    }
}

impl SecretBuffer<u8> {
    pub(super) fn initialize_zeroed(&mut self, len: usize) -> Result<()> {
        self.initialize_defaults(len)
    }
}

// DE: Konkrete primitive Werte: Drop löscht Elemente und volle frühere Kapazität.
// EN: Concrete primitive values: Drop wipes elements and the full former allocation.
impl ZeroizeOnDrop for SecretBuffer<u8> {}
impl ZeroizeOnDrop for SecretBuffer<char> {}
impl ZeroizeOnDrop for SecretBuffer<usize> {}
impl ZeroizeOnDrop for SecretBuffer<bool> {}
impl ZeroizeOnDrop for SecretBuffer<u16> {}

impl<T: Zeroize> Zeroize for SecretBuffer<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
        // DE: Erst Owner zerstören, dann sämtliche früheren Datensatzbytes löschen.
        // EN: Destroy owners first, then wipe all previously occupied record bytes.
        self.inner.spare_capacity_mut().zeroize();
    }
}

impl<T: Zeroize> Drop for SecretBuffer<T> {
    fn drop(&mut self) {
        self.zeroize();
        self.lock.take();
    }
}
