//! DE: Fester, typisierter Secret-Puffer; Sperre vor Benutzung, Löschen vor Entsperren.
//! EN: Fixed typed secret buffer; lock before use, wipe before unlocking.

use zeroize::Zeroize;

use crate::hardening::memlock::{self, LockedRange};
use crate::{Error, Result};

pub(crate) struct SecretBuffer<T: Zeroize> {
    inner: Vec<T>,
    lock: Option<LockedRange>,
}

impl<T: Zeroize> SecretBuffer<T> {
    pub(crate) fn new(mut inner: Vec<T>) -> Result<Self> {
        let bytes = inner
            .capacity()
            .checked_mul(size_of::<T>())
            .ok_or(Error::MemoryLock)?;
        let lock = memlock::lock_range(inner.as_ptr().addr(), bytes);
        if !lock.complete(inner.as_ptr().addr(), bytes) {
            inner.zeroize();
            return Err(Error::MemoryLock);
        }
        Ok(Self {
            inner,
            lock: Some(lock),
        })
    }

    pub(crate) fn expose(&self) -> &[T] {
        &self.inner
    }

    pub(crate) fn expose_mut(&mut self) -> &mut [T] {
        &mut self.inner
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        if len < self.inner.len() {
            self.inner[len..].iter_mut().for_each(Zeroize::zeroize);
            self.inner.truncate(len);
        }
    }
}

impl<T: Zeroize> Zeroize for SecretBuffer<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> Drop for SecretBuffer<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
        self.lock.take();
    }
}
