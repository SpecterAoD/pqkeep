//! DE: Typisierte Caller-Seeds direkt aus vorab gesperrten Bytes ausleihen.
//! EN: Borrow typed caller seeds directly from prelocked bytes.

use super::SecretBytes;
use crate::{Error, Result};
use ml_kem::array::{Array, ArraySize};

pub(super) fn parse(seed: &[u8], expected: usize) -> Result<SecretBytes> {
    if seed.len() != expected {
        return Err(Error::InvalidInput { field: "seed" });
    }
    SecretBytes::from_slice(seed)
}

// DE: Geprüfte Leihsicht statt privater Arraykopie; Lebensdauer an den Owner binden.
// EN: Checked borrowed view instead of a private array copy; tie lifetime to its owner.
pub(super) fn view<N: ArraySize>(seed: &SecretBytes) -> Result<&Array<u8, N>> {
    seed.expose()
        .try_into()
        .map_err(|_| Error::InvalidInput { field: "seed" })
}

#[cfg(test)]
#[path = "seed_state_tests.rs"]
mod tests;
