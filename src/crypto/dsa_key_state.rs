//! DE: DSA-Schlüssel und beide Payloads vor privater Konstruktion sperren.
//! EN: Lock DSA key and both payloads before private construction.

use ml_dsa::{MlDsaParams, Seed, SeedKeyInPlace, SigningKey};
use zeroize::Zeroize;

use crate::crypto::{secret_state::SecretState, secret_workspace::SecretWorkspace};
use crate::{Error, Result, hardening::memlock::LockedRange};

#[cfg(test)]
#[path = "dsa_workspace_tests.rs"]
mod tests;

pub(super) struct KeyState<P: MlDsaParams> {
    key: SecretState<SigningKey<P>>,
    locks: SecretWorkspace<LockedRange>,
}

impl<P: MlDsaParams> KeyState<P> {
    pub(super) fn new(seed: &Seed) -> Result<Self> {
        let mut out = Self::prepare()?;
        let mut work = SecretState::new(ml_dsa::KeyGenerationWorkspace::<P>::default())?;
        out.key
            .get_mut()
            .initialize_seed_with_workspace(seed, work.get_mut());
        Ok(out)
    }

    fn prepare() -> Result<Self> {
        let mut out = Self {
            key: SecretState::new(SigningKey::<P>::public_state())?,
            locks: SecretWorkspace::zeroed(2)?,
        };
        let mut count = 0;
        let complete = out.key.get().visit_private_storage(|addr, len| {
            let Some(slot) = out.locks.expose_mut().get_mut(count) else {
                return false;
            };
            count += 1;
            len > 0 && slot.acquire(addr, len)
        });
        if !complete || count != 2 {
            return Err(Error::MemoryLock);
        }
        Ok(out)
    }

    pub(super) fn get(&self) -> &SigningKey<P> {
        self.key.get()
    }
}

impl<P: MlDsaParams> Drop for KeyState<P> {
    fn drop(&mut self) {
        // DE/EN: Private Felder vor Unlock/Free löschen / wipe private fields before unlock/free.
        self.key.get_mut().zeroize();
        self.locks.zeroize();
    }
}
