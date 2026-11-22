//! DE: Stabile gesperrte Adresse für Provider-Zustände mit sicherem Drop.
//! EN: Stable locked address for provider state with wiping destructors.

use zeroize::ZeroizeOnDrop;

use crate::hardening::memlock::{self, LockedRange};
use crate::{Error, Result};

pub(crate) struct SecretState<T: ZeroizeOnDrop> {
    inner: Option<Box<T>>,
    lock: Option<LockedRange>,
}

impl<T: ZeroizeOnDrop> SecretState<T> {
    pub(crate) fn new(value: T) -> Result<Self> {
        let inner = Box::new(value);
        let addr = std::ptr::from_ref(&*inner).addr();
        let lock = memlock::lock_range(addr, size_of::<T>());
        if !lock.complete(addr, size_of::<T>()) {
            drop(inner);
            return Err(Error::MemoryLock);
        }
        Ok(Self {
            inner: Some(inner),
            lock: Some(lock),
        })
    }

    pub(crate) fn get(&self) -> &T {
        // DE: Nur Drop nimmt den Wert heraus. EN: Only Drop removes the value.
        match &self.inner {
            Some(value) => value,
            None => unreachable_state(),
        }
    }

    pub(crate) fn get_mut(&mut self) -> &mut T {
        match &mut self.inner {
            Some(value) => value,
            None => unreachable_state(),
        }
    }
}

// DE: Unerreichbarer verletzter interner Zustand: niemals ungesichert fortfahren.
// EN: Unreachable invalid internal state: never continue without protection.
fn unreachable_state() -> ! {
    std::process::abort()
}

impl<T: ZeroizeOnDrop> Drop for SecretState<T> {
    fn drop(&mut self) {
        drop(self.inner.take());
        self.lock.take();
    }
}
