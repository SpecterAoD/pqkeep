//! DE: Hashzustand und Ausgabe vor privater Verarbeitung sperren.
//! EN: Lock hash state and output before processing private input.

use super::{SecretBytes, secret_state::SecretState};
use crate::{Error, Result};
use sha3::digest::{Digest, FixedOutputReset, Output, OutputSizeUser};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(test)]
#[path = "locked_hash_tests.rs"]
mod tests;

pub(crate) struct LockedHash<D: ZeroizeOnDrop> {
    state: SecretState<D>,
}

impl<D> LockedHash<D>
where
    D: Digest + FixedOutputReset + ZeroizeOnDrop,
    Output<D>: Zeroize,
{
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            state: SecretState::new(D::new())?,
        })
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        Digest::update(self.state.get_mut(), input);
    }

    pub(crate) fn finalize(mut self) -> Result<SecretBytes> {
        let mut output = SecretBytes::zeroed(size_of::<Output<D>>())?;
        FixedOutputReset::finalize_into_reset(self.state.get_mut(), output_view::<D>(&mut output)?);
        Ok(output)
    }
}

// DE: Geprüfte mutable Leihsicht; kein zusätzlicher Owner und keine private Wertkopie.
// EN: Checked mutable borrow; no additional owner or private value copy.
pub(super) fn output_view<D: OutputSizeUser>(bytes: &mut SecretBytes) -> Result<&mut Output<D>> {
    bytes.expose_mut().try_into().map_err(|_| Error::Crypto)
}
