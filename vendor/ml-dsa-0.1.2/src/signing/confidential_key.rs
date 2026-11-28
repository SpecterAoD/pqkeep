//! DE: Auch Absender-Schlüsselaufbau ohne gewöhnliche öffentliche Cache-Kopien.
//! EN: Sender key construction without ordinary public-cache copies as well.

use super::in_place::KeyGenerationWorkspace;
use crate::{EncodedVerifyingKey, MlDsaParams, sampling::matrix_workspace::MatrixWorkspace};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DE: Gesamtes Objekt vor Seed-Eintritt sperren; kein öffentlicher Cache-Export.
/// EN: Lock the whole object before seed ingress; no public cache export.
pub struct ConfidentialKeyGenerationWorkspace<P: MlDsaParams> {
    pub(super) inner: KeyGenerationWorkspace<P>,
    pub(super) matrix_sampling: MatrixWorkspace,
    pub(super) encoded: EncodedVerifyingKey<P>,
}

impl<P: MlDsaParams> Default for ConfidentialKeyGenerationWorkspace<P> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            matrix_sampling: Default::default(),
            encoded: Default::default(),
        }
    }
}
impl<P: MlDsaParams> Zeroize for ConfidentialKeyGenerationWorkspace<P> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
        self.matrix_sampling.zeroize();
        self.encoded.zeroize();
    }
}
impl<P: MlDsaParams> Drop for ConfidentialKeyGenerationWorkspace<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl<P: MlDsaParams> ZeroizeOnDrop for ConfidentialKeyGenerationWorkspace<P> {}
impl<P: MlDsaParams> core::fmt::Debug for ConfidentialKeyGenerationWorkspace<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfidentialKeyGenerationWorkspace")
            .finish_non_exhaustive()
    }
}
