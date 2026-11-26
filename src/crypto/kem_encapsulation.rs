//! DE: Kapselungsentropie und K || r vor Providerzugriff sperren.
//! EN: Lock encapsulation entropy and K || r before provider access.

use super::{Encapsulated, SecretBytes, rng, seed_state};
use crate::crypto::secret_state::SecretState;
use crate::{Error, Result};
use ml_kem::{B32, EncapsulationWorkspace};
use sha3::{Digest, Sha3_512};

pub(super) fn run(
    encapsulate: impl FnOnce(&B32, &mut EncapsulationWorkspace, &mut Sha3_512) -> Vec<u8>,
) -> Result<Encapsulated> {
    let mut shared_secret = SecretBytes::zeroed(32)?;
    let mut derived = SecretBytes::zeroed(64)?;
    // DE: Öffentlichen Anfangszustand vor frischer Entropie und privatem Absorb sperren.
    // EN: Lock public initial hash state before fresh entropy and private absorption.
    let mut hash = SecretState::new(Sha3_512::new())?;
    let entropy = rng::secret(32)?;
    let workspace = derived
        .expose_mut()
        .try_into()
        .map_err(|_| Error::InvalidInput {
            field: "kem_workspace",
        })?;
    let ciphertext = encapsulate(seed_state::view(&entropy)?, workspace, hash.get_mut());
    // DE: Nur zwischen gesperrten Flächen kopieren; K || r bleibt bis Drop geschützt.
    // EN: Copy only between locked buffers; K || r remains protected until drop.
    shared_secret
        .expose_mut()
        .copy_from_slice(&derived.expose()[..32]);
    Ok(Encapsulated {
        ciphertext,
        shared_secret,
    })
}

#[cfg(test)]
#[path = "kem_encapsulation_tests.rs"]
mod tests;
