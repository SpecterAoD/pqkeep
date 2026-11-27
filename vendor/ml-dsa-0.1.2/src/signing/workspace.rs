//! DE: Alle privaten Signierkandidaten bleiben in vorab gesperrten Inline-Flächen.
//! EN: Keep every private signing candidate in prelocked inline storage.

use crate::{
    B32, B64, MlDsaParams,
    algebra::{NttPolynomial, NttVector, Polynomial, Vector},
    hash_workspace::HashWorkspace,
    param::{EncodedW1, MaskSamplingSize},
    sampling::in_place::SamplingWorkspace,
};
use hybrid_array::{Array, typenum::U256};
use zeroize::{Zeroize, ZeroizeOnDrop};

// DE/EN: Dieselbe Feldliste für Initialisierung und vollständigen Wipe.
// Use the same field list for initialization and complete wiping.
macro_rules! workspace {
    ($($field:ident: $ty:ty),+ $(,)?) => {
        /// DE: Gesamtes Objekt vor Zufall/Seed/Nachricht sperren.
        /// EN: Lock the complete object before randomness/seed/message input.
        pub struct SigningWorkspace<P: MlDsaParams> { $(pub(super) $field: $ty),+ }
        impl<P: MlDsaParams> Default for SigningWorkspace<P> {
            fn default() -> Self { Self { $($field: Default::default()),+ } }
        }
        impl<P: MlDsaParams> Zeroize for SigningWorkspace<P> {
            fn zeroize(&mut self) { $(self.$field.zeroize();)+ }
        }
        impl<P: MlDsaParams> Drop for SigningWorkspace<P> {
            fn drop(&mut self) { self.zeroize(); }
        }
        impl<P: MlDsaParams> ZeroizeOnDrop for SigningWorkspace<P> {}
        impl<P: MlDsaParams> core::fmt::Debug for SigningWorkspace<P> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct("SigningWorkspace").finish_non_exhaustive()
            }
        }
    };
}

workspace! {
    hash: HashWorkspace,
    sampling: SamplingWorkspace,
    rnd: B32,
    mu: B64,
    rhopp: B64,
    mask_bytes: Array<u8, <P::Gamma1 as MaskSamplingSize>::SampleSize>,
    y: Vector<P::L>,
    y_hat: NttVector<P::L>,
    w_hat: NttVector<P::K>,
    w: Vector<P::K>,
    w1: Vector<P::K>,
    w1_bytes: EncodedW1<P>,
    challenge: Array<u8, P::Lambda>,
    c: Polynomial,
    c_hat: NttPolynomial,
    product: NttPolynomial,
    product_l: NttVector<P::L>,
    product_k: NttVector<P::K>,
    cs1: Vector<P::L>,
    cs2: Vector<P::K>,
    z: Vector<P::L>,
    r0: Vector<P::K>,
    ct0: Vector<P::K>,
    hint_input: Vector<P::K>,
    hints: Array<Array<bool, U256>, P::K>,
}
