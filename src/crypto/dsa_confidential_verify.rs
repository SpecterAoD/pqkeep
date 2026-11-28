//! DE: Auch verborgene Verifikationsschlüssel/-signaturen vor Dekodierung schützen.
//! EN: Protect hidden verification keys/signatures before decoding as well.

use crate::{
    Error, Result,
    crypto::{DsaAlgorithm, secret_state::SecretState, secret_workspace::SecretWorkspace},
    hardening::memlock::LockedRange,
};
use ml_dsa::{
    ConfidentialVerificationWorkspace, EncodedSignature, EncodedVerifyingKey, MlDsa44, MlDsa65,
    MlDsa87, MlDsaParams,
};
use zeroize::Zeroize;

struct State<P: MlDsaParams> {
    work: SecretState<ConfidentialVerificationWorkspace<P>>,
    rows: SecretWorkspace<LockedRange>,
}

impl<P: MlDsaParams> State<P> {
    fn new() -> Result<Self> {
        let work = SecretState::new(ConfidentialVerificationWorkspace::<P>::default())?;
        let expected = work.get().private_storage_count();
        let mut out = Self {
            work,
            rows: SecretWorkspace::zeroed(expected)?,
        };
        let mut count = 0;
        let complete = out.work.get().visit_private_storage(|addr, len| {
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
}

impl<P: MlDsaParams> Drop for State<P> {
    fn drop(&mut self) {
        // DE: Alle verschachtelten Zeilen unter ihrer Sperre löschen.
        // EN: Wipe every nested row while its lock is still held.
        self.work.get_mut().zeroize();
        self.rows.zeroize();
    }
}

pub(crate) fn verify(
    algorithm: DsaAlgorithm,
    key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<bool> {
    if context.len() > super::MAX_CONTEXT_LEN {
        return Ok(false);
    }
    match algorithm {
        DsaAlgorithm::MlDsa44 => verify_with::<MlDsa44>(key, message, context, signature),
        DsaAlgorithm::MlDsa65 => verify_with::<MlDsa65>(key, message, context, signature),
        DsaAlgorithm::MlDsa87 => verify_with::<MlDsa87>(key, message, context, signature),
    }
}

fn verify_with<P: MlDsaParams>(
    key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let (Ok(key), Ok(signature)) = (
        <&EncodedVerifyingKey<P>>::try_from(key),
        <&EncodedSignature<P>>::try_from(signature),
    ) else {
        return Ok(false);
    };
    let mut state = State::<P>::new()?;
    Ok(state
        .work
        .get_mut()
        .verify_encoded(key, message, context, signature))
}

#[cfg(test)]
#[path = "dsa_confidential_verify_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "dsa_confidential_denial_tests.rs"]
mod denial_tests;
