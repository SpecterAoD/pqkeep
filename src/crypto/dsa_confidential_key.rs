//! DE: Verborgenen Signierschlüssel samt Identitätsmatrix vor Befüllung sperren.
//! EN: Prelock hidden signing key including its identity-derived matrix.

use crate::{
    Error, Result,
    crypto::{secret_state::SecretState, secret_workspace::SecretWorkspace},
    hardening::memlock::LockedRange,
};
use ml_dsa::{ConfidentialKeyGenerationWorkspace, ExpandedSigningKey, MlDsaParams, Seed};
use zeroize::Zeroize;

pub(super) struct KeyState<P: MlDsaParams> {
    key: SecretState<ExpandedSigningKey<P>>,
    rows: SecretWorkspace<LockedRange>,
}

impl<P: MlDsaParams> KeyState<P> {
    pub(super) fn new(seed: &Seed) -> Result<Self> {
        let mut out = Self::prepare()?;
        let mut work = SecretState::new(ConfidentialKeyGenerationWorkspace::<P>::default())?;
        out.key
            .get_mut()
            .initialize_confidential_seed(seed, work.get_mut())
            .map_err(|_| Error::Crypto)?;
        Ok(out)
    }

    pub(super) fn prepare() -> Result<Self> {
        let key = SecretState::new(ExpandedSigningKey::<P>::public_confidential_state())?;
        let expected = key.get().confidential_storage_count();
        let mut out = Self {
            key,
            rows: SecretWorkspace::zeroed(expected)?,
        };
        let mut count = 0;
        let complete = out.key.get().visit_confidential_storage(|addr, len| {
            let Some(slot) = out.rows.expose_mut().get_mut(count) else {
                return false;
            };
            count += 1;
            len > 0 && slot.acquire(addr, len)
        });
        if !complete || count != expected {
            return Err(Error::MemoryLock);
        }
        Ok(out)
    }

    pub(super) fn get(&self) -> &ExpandedSigningKey<P> {
        self.key.get()
    }
}

impl<P: MlDsaParams> Drop for KeyState<P> {
    fn drop(&mut self) {
        // DE/EN: Auch Identitätsmatrix vor Guardfreigabe löschen / wipe identity matrix before unlocking.
        self.key.get_mut().zeroize_confidential();
        self.rows.zeroize();
    }
}
