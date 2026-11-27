//! DE: Feste geliehene Keygen-Flächen vor privater Verarbeitung sperren.
//! EN: Prelock fixed borrowed key-generation storage before private processing.

use crate::{
    EncapsulationWorkspace, ParameterSet,
    algebra::{NttPolynomial, NttVector, Vector},
    crypto::PrfOutput,
};
use sha3::{Digest, Sha3_512};

/// DE: Inline-Arbeitsfläche; keine inneren privaten Heap-Allokationen.
/// EN: Inline workspace without nested private heap allocations.
/// DE: Caller vor privater Befüllung sperren; interne Hash-/XOF-Flächen separat prüfen.
/// EN: Caller must prelock before population; audit internal hash/XOF scratch separately.
pub struct KeyGenerationWorkspace<P: ParameterSet> {
    pub(crate) sampled: Vector<P::K>,
    pub(crate) error: NttVector<P::K>,
    pub(crate) product: NttPolynomial,
    pub(crate) public: NttVector<P::K>,
    pub(crate) g: EncapsulationWorkspace,
    pub(crate) hash: Sha3_512,
    pub(crate) prf: PrfOutput<P::Eta1>,
    pub(crate) xof: shake::Shake256,
    pub(crate) reader: shake::Shake256Reader,
}

impl<P: ParameterSet> core::fmt::Debug for KeyGenerationWorkspace<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyGenerationWorkspace")
            .finish_non_exhaustive()
    }
}

impl<P: ParameterSet> Default for KeyGenerationWorkspace<P> {
    fn default() -> Self {
        Self {
            sampled: Vector::default(),
            error: NttVector::default(),
            product: NttPolynomial::default(),
            public: NttVector::default(),
            g: EncapsulationWorkspace::default(),
            hash: Sha3_512::new(),
            prf: PrfOutput::<P::Eta1>::default(),
            xof: shake::Shake256::default(),
            reader: shake::Shake256Reader::default(),
        }
    }
}

#[cfg(feature = "zeroize")]
impl<P: ParameterSet> zeroize::Zeroize for KeyGenerationWorkspace<P> {
    fn zeroize(&mut self) {
        self.sampled.zeroize();
        self.error.zeroize();
        self.product.zeroize();
        self.public.zeroize();
        self.g.zeroize();
        self.prf.zeroize();
        self.hash.zeroize();
        self.xof.zeroize();
        self.reader.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<P: ParameterSet> zeroize::ZeroizeOnDrop for KeyGenerationWorkspace<P> {}

#[cfg(feature = "zeroize")]
impl<P: ParameterSet> Drop for KeyGenerationWorkspace<P> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
        // DE: Anschließender Hash-Drop zeroisiert zusätzlich dessen gesamten Zustand.
        // EN: Subsequent hash field drop also zeroizes its complete state.
    }
}

impl<P: ParameterSet> KeyGenerationWorkspace<P> {
    pub(crate) fn compute_public(
        &mut self,
        matrix: &crate::algebra::NttMatrix<P::K>,
        secret: &NttVector<P::K>,
    ) {
        for ((row, target), error) in matrix
            .0
            .iter()
            .zip(self.public.0.iter_mut())
            .zip(self.error.0.iter())
        {
            target.0.fill(Default::default());
            for (a, s) in row.0.iter().zip(secret.0.iter()) {
                crate::algebra::multiply_ntt_into(a, s, &mut self.product);
                for (sum, product) in target.0.iter_mut().zip(self.product.0.iter()) {
                    *sum = *sum + *product;
                }
            }
            for (sum, error) in target.0.iter_mut().zip(error.0.iter()) {
                *sum = *sum + *error;
            }
        }
    }
}
