//! DE: Hashzustand und Ausgabe vor privater Verarbeitung sperren.
//! EN: Lock hash state and output before processing private input.

use super::{SecretBytes, secret_buffer::SecretBuffer, secret_state::SecretState};
use crate::Result;
use sha3::digest::{Digest, FixedOutputReset, Output};
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
            state: SecretState::new(D::new(), D::new)?,
        })
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        Digest::update(self.state.get_mut(), input);
    }

    pub(crate) fn finalize(mut self) -> Result<SecretBytes> {
        let mut output = SecretBuffer::new(vec![Output::<D>::default()])?;
        FixedOutputReset::finalize_into_reset(self.state.get_mut(), &mut output.expose_mut()[0]);
        SecretBytes::from_slice(&output.expose()[0])
    }
}
