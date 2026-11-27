//! DE: Verborgene Signatur direkt in das vorab gesperrte Caller-Ziel kodieren.
//! EN: Encode hidden signatures directly into prelocked caller output.

use super::{ExpandedSigningKey, workspace::SigningWorkspace};
use crate::{EncodedSignature, MlDsaParams, param::EncodedZ};
use hybrid_array::typenum::Unsigned;
use module_lattice::Truncate;
use signature::{Error, rand_core::TryCryptoRng};

impl<P: MlDsaParams> ExpandedSigningKey<P> {
    /// DE: Caller muss work und out vor Aufruf vollständig sperren.
    /// EN: Caller must fully lock work and out before calling.
    /// # Errors
    /// DE/EN: Wie sign_randomized_with_workspace; keine Ersatzkodierung.
    /// Same failures as sign_randomized_with_workspace; no fallback encoding.
    pub fn sign_randomized_encoded_with_workspace<R: TryCryptoRng + ?Sized>(
        &self,
        message: &[u8],
        context: &[u8],
        rng: &mut R,
        work: &mut SigningWorkspace<P>,
        out: &mut EncodedSignature<P>,
    ) -> Result<(), Error> {
        self.accept_candidate(message, context, rng, work)?;
        // DE: Identische kanonische Koeffizienten wie accepted_signature.
        // EN: Same canonical coefficients as accepted_signature.
        Self::canonicalize(work);
        let (challenge, rest) = out.as_mut_slice().split_at_mut(P::Lambda::USIZE);
        let (z, hint) = rest.split_at_mut(P::ZSize::USIZE);
        let z: &mut EncodedZ<P> = z.try_into().map_err(|_| Error::new())?;
        challenge.copy_from_slice(&work.challenge);
        P::encode_z_into(&mut work.z, z).map_err(|_| Error::new())?;
        encode_hints(work, hint)
    }
}

fn encode_hints<P: MlDsaParams>(work: &SigningWorkspace<P>, out: &mut [u8]) -> Result<(), Error> {
    let omega = P::Omega::USIZE;
    if out.len() != omega + P::K::USIZE {
        return Err(Error::new());
    }
    out.fill(0);
    let mut index = 0;
    // DE: Ursprüngliche Hint::bit_pack-Reihenfolge und Schnittkodierung beibehalten.
    // EN: Preserve original Hint::bit_pack order and cut encoding.
    for (i, hints) in work.hints.iter().enumerate() {
        for (j, hint) in hints.iter().enumerate() {
            if *hint {
                if index == omega {
                    return Err(Error::new());
                }
                out[index] = Truncate::truncate(j);
                index += 1;
            }
        }
        out[omega + i] = Truncate::truncate(index);
    }
    Ok(())
}
