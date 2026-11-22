//! DE: Stabile gesperrte Adresse für Provider-Zustände mit sicherem Drop.
//! EN: Stable locked address for provider state with wiping destructors.

use zeroize::ZeroizeOnDrop;

use crate::hardening::memlock::{self, LockedRange};
use crate::{Error, Result};

#[cfg(test)]
#[path = "secret_state_tests.rs"]
mod tests;

pub(crate) struct SecretState<T: ZeroizeOnDrop> {
    inner: Box<T>,
    lock: Option<LockedRange>,
    public_state: fn() -> T,
}

impl<T: ZeroizeOnDrop> SecretState<T> {
    pub(crate) fn new(value: T, public_state: fn() -> T) -> Result<Self> {
        let inner = Box::new(value);
        let addr = std::ptr::from_ref(&*inner).addr();
        let lock = memlock::lock_range(addr, size_of::<T>());
        if !lock.complete(addr, size_of::<T>()) {
            drop(inner);
            return Err(Error::MemoryLock);
        }
        Ok(Self {
            inner,
            lock: Some(lock),
            public_state,
        })
    }

    pub(crate) fn get(&self) -> &T {
        &self.inner
    }

    pub(crate) fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: ZeroizeOnDrop> Drop for SecretState<T> {
    fn drop(&mut self) {
        // DE: Zuweisung zerstört den Secret-Zustand an Ort und Stelle, noch gesperrt.
        // Die Box bleibt bis nach dem Entsperren allokiert (VirtualFree entsperrt implizit).
        // EN: Assignment drops secret state in place while locked. Keep the Box allocated
        // until after unlocking; VirtualFree would otherwise implicitly remove the lock.
        *self.inner = (self.public_state)();
        self.lock.take();
    }
}
