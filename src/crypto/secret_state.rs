//! DE: Stabile gesperrte Adresse für Provider-Zustände mit sicherem Drop.
//! EN: Stable locked address for provider state with wiping destructors.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hardening::memlock::{self, LockedRange};
use crate::{Error, Result};

#[cfg(test)]
#[path = "secret_state_tests.rs"]
mod tests;

pub(crate) struct SecretState<T: ZeroizeOnDrop> {
    inner: Vec<T>,
    lock: Option<LockedRange>,
}

struct WipeAllocation<'a, T>(&'a mut Vec<T>);

impl<T> Drop for WipeAllocation<'_, T> {
    fn drop(&mut self) {
        self.0.spare_capacity_mut().zeroize();
    }
}

impl<T: ZeroizeOnDrop> SecretState<T> {
    pub(crate) fn new(public_value: T) -> Result<Self> {
        let mut inner = Vec::new();
        inner.try_reserve_exact(1).map_err(|_| Error::MemoryLock)?;
        inner.push(public_value);
        let bytes = inner
            .capacity()
            .checked_mul(size_of::<T>())
            .ok_or(Error::MemoryLock)?;
        let addr = inner.as_ptr().addr();
        let lock = memlock::lock_range(addr, bytes);
        if !lock.complete(addr, bytes) {
            drop(inner);
            return Err(Error::MemoryLock);
        }
        Ok(Self {
            inner,
            lock: Some(lock),
        })
    }

    pub(crate) fn get(&self) -> &T {
        &self.inner[0]
    }

    pub(crate) fn get_mut(&mut self) -> &mut T {
        &mut self.inner[0]
    }

    fn wipe(&mut self) {
        // DE: Owner zuerst an Ort und Stelle zerstören, danach auch Padding löschen.
        // Vec::clear setzt die Länge vor Drop; der Guard läuft auch bei dessen Unwind.
        // EN: Destroy owners in place first, then wipe padding and the full allocation.
        // Vec::clear removes the length before Drop; the guard also runs on its unwind.
        let allocation = WipeAllocation(&mut self.inner);
        allocation.0.clear();
    }
}

impl<T: ZeroizeOnDrop> Drop for SecretState<T> {
    fn drop(&mut self) {
        // DE: Speicher bis nach Wipe und Unlock behalten, keinen Ersatzkonstruktor aufrufen.
        // EN: Retain storage through wiping and unlocking; never invoke a replacement constructor.
        let lock = self.lock.take();
        self.wipe();
        drop(lock);
    }
}
