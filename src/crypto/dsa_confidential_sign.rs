//! DE: Verborgene Signaturen ohne gewöhnlichen Signature-/Ausgabe-Owner.
//! EN: Hidden signatures without ordinary Signature/output ownership.

use super::{MAX_CONTEXT_LEN, confidential_key::KeyState};
use crate::{
    Error, Result,
    crypto::{DsaAlgorithm, SecretBytes, secret_state::SecretState},
};
use getrandom::SysRng;
use ml_dsa::{EncodedSignature, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, SigningWorkspace};
use zeroize::Zeroize;

pub(crate) fn sign(
    algorithm: DsaAlgorithm,
    seed: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<SecretBytes> {
    if context.len() > MAX_CONTEXT_LEN {
        return Err(Error::InvalidInput { field: "context" });
    }
    match algorithm {
        DsaAlgorithm::MlDsa44 => sign_with::<MlDsa44>(seed, message, context),
        DsaAlgorithm::MlDsa65 => sign_with::<MlDsa65>(seed, message, context),
        DsaAlgorithm::MlDsa87 => sign_with::<MlDsa87>(seed, message, context),
    }
}

fn sign_with<P: MlDsaParams>(seed: &[u8], message: &[u8], context: &[u8]) -> Result<SecretBytes> {
    let mut out = SecretBytes::zeroed(size_of::<EncodedSignature<P>>())?;
    let mut work = SecretState::new(SigningWorkspace::<P>::default())?;
    let mut seed = crate::crypto::seed_state::parse(seed, super::SEED_LEN)?;
    let key = KeyState::<P>::new(crate::crypto::seed_state::view(&seed)?)?;
    seed.zeroize();
    let encoded: &mut EncodedSignature<P> =
        out.expose_mut().try_into().map_err(|_| Error::Crypto)?;
    key.get()
        .sign_randomized_encoded_with_workspace(
            message,
            context,
            &mut SysRng,
            work.get_mut(),
            encoded,
        )
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}

#[cfg(test)]
#[path = "dsa_confidential_sign_tests.rs"]
mod tests;
