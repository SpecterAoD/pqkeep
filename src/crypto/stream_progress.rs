//! DE: Private STREAM-Längen vor Klartexteingang sperren und vor Freigabe löschen.
//! EN: Lock private STREAM lengths before plaintext ingress and wipe before release.

use crate::{Error, Result, crypto::secret_state::SecretState};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(super) struct Progress {
    pub(super) cursor: usize,
    pub(super) total: u64,
}

impl Zeroize for Progress {
    fn zeroize(&mut self) {
        self.cursor.zeroize();
        self.total.zeroize();
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for Progress {}

impl Progress {
    pub(super) fn prepare() -> Result<SecretState<Self>> {
        SecretState::new(Self {
            cursor: 0,
            total: 0,
        })
    }

    pub(super) fn check_advance(&self, bytes: usize) -> Result<()> {
        self.cursor.checked_add(bytes).ok_or(Error::Crypto)?;
        self.total
            .checked_add(u64::try_from(bytes).map_err(|_| Error::Crypto)?)
            .ok_or(Error::Crypto)?;
        Ok(())
    }

    pub(super) fn advance(&mut self, bytes: usize) -> Result<()> {
        self.check_advance(bytes)?;
        self.cursor += bytes;
        self.total += u64::try_from(bytes).map_err(|_| Error::Crypto)?;
        Ok(())
    }
}
