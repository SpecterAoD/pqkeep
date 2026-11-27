//! DE: KEM-Zustand und seine privaten Payloads vor Seed-Verarbeitung sperren.
//! EN: Lock KEM state and its private payloads before processing seeds.

use ml_kem::{Seed, SeedKeyInPlace};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{
    secret_buffer::SecretBuffer, secret_state::SecretState, secret_workspace::SecretWorkspace,
};
use crate::hardening::memlock::LockedRange;
use crate::{Error, Result};

impl ZeroizeOnDrop for SecretBuffer<LockedRange> {}

pub(super) struct KeyState<T: SeedKeyInPlace> {
    key: SecretState<T>,
    locks: SecretWorkspace<LockedRange>,
}

impl<T: SeedKeyInPlace> KeyState<T> {
    pub(super) fn new(seed: &Seed) -> Result<Self> {
        let mut out = Self::prepare()?;
        let mut workspace = SecretState::new(T::Workspace::default())?;
        out.key
            .get_mut()
            .initialize_seed_with_workspace(seed, workspace.get_mut())
            .map_err(|_| Error::Crypto)?;
        Ok(out)
    }

    fn prepare() -> Result<Self> {
        let mut out = Self {
            key: SecretState::new(T::public_state())?,
            locks: SecretWorkspace::zeroed(3)?,
        };
        let mut count = 0;
        let complete = out.key.get().visit_private_storage(|addr, len| {
            let Some(slot) = out.locks.expose_mut().get_mut(count) else {
                return false;
            };
            count += 1;
            len > 0 && slot.acquire(addr, len)
        });
        if !complete || count != 3 {
            return Err(Error::MemoryLock);
        }
        Ok(out)
    }

    pub(super) fn get(&self) -> &T {
        self.key.get()
    }
}

impl<T: SeedKeyInPlace> Drop for KeyState<T> {
    fn drop(&mut self) {
        // DE: Payloads noch lebend/gesperrt löschen, dann ihre Guards freigeben;
        // erst der anschließende key-Drop darf Box-Allokationen freigeben.
        // EN: Wipe live locked payloads, release guards, then allow key drop to free boxes.
        self.key.get_mut().zeroize();
        self.locks.zeroize();
    }
}

#[cfg(test)]
#[path = "kem_key_state_tests.rs"]
mod tests;
