//! DE: Auch beim Prüfen können Nachricht und Vergleichs-Challenge privat sein.
//! EN: Verification messages and recomputed challenges may also be confidential.

use super::VerifyingKey;
use crate::{B64, MlDsaParams, Signature, hash_workspace::HashWorkspace};
use ctutils::CtEq;
use hybrid_array::Array;
use module_lattice::Truncate;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DE: Gesamten Workspace vor Nachrichtenverarbeitung sperren.
/// EN: Prelock the entire workspace before processing messages.
pub struct VerificationWorkspace<P: MlDsaParams> {
    hash: HashWorkspace,
    mu: B64,
    candidate: Array<u8, P::Lambda>,
}

impl<P: MlDsaParams> Default for VerificationWorkspace<P> {
    fn default() -> Self {
        Self {
            hash: Default::default(),
            mu: Default::default(),
            candidate: Default::default(),
        }
    }
}
impl<P: MlDsaParams> Zeroize for VerificationWorkspace<P> {
    fn zeroize(&mut self) {
        self.hash.zeroize();
        self.mu.zeroize();
        self.candidate.zeroize();
    }
}
impl<P: MlDsaParams> Drop for VerificationWorkspace<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl<P: MlDsaParams> ZeroizeOnDrop for VerificationWorkspace<P> {}
impl<P: MlDsaParams> core::fmt::Debug for VerificationWorkspace<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerificationWorkspace")
            .finish_non_exhaustive()
    }
}

impl<P: MlDsaParams> VerifyingKey<P> {
    /// DE: Caller muss work vor privater Nachricht/Kontext vollständig sperren.
    /// EN: Caller must prelock work before any confidential message/context.
    #[must_use]
    pub fn verify_with_workspace(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &Signature<P>,
        work: &mut VerificationWorkspace<P>,
    ) -> bool {
        if context.len() > 255 {
            return false;
        }
        let length: u8 = Truncate::truncate(context.len());
        work.hash.start(&[
            &self.precomputed_values.tr,
            &[0],
            &[length],
            context,
            message,
        ]);
        work.hash.read(&mut work.mu);
        // DE: Nur öffentlicher Schlüssel und bereits öffentliche Signatur gehen hier ein.
        // EN: This arithmetic uses only the public key and already public signature.
        let encoded = self.reconstruct_w1(signature);
        work.hash.start(&[&work.mu, &encoded]);
        work.hash.read(&mut work.candidate);
        signature.c_tilde.ct_eq(&work.candidate).into()
    }
}
