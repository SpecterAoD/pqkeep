//! DE: Verborgene Schlüssel, Signaturen und gesamte Verifikationsarithmetik schützen.
//! EN: Protect hidden keys, signatures and the complete verification arithmetic.

use crate::{
    B64, MlDsaParams,
    algebra::{NttMatrix, NttPolynomial, NttVector, Polynomial, Vector},
    hash_workspace::HashWorkspace,
    param::EncodedW1,
    sampling::{in_place::SamplingWorkspace, matrix_workspace::MatrixWorkspace},
};
use hybrid_array::{Array, typenum::U256};
use zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! workspace {
    ($($field:ident: $ty:ty),+ $(,)?) => {
        /// DE: Objekt UND alle besuchten Matrixzeilen vor privater Eingabe sperren.
        /// EN: Lock the object AND every visited matrix row before private ingress.
        pub struct ConfidentialVerificationWorkspace<P: MlDsaParams> { $(pub(super) $field: $ty),+ }
        impl<P: MlDsaParams> Default for ConfidentialVerificationWorkspace<P> {
            fn default() -> Self { Self { $($field: Default::default()),+ } }
        }
        impl<P: MlDsaParams> Zeroize for ConfidentialVerificationWorkspace<P> {
            fn zeroize(&mut self) { $(self.$field.zeroize();)+ }
        }
        impl<P: MlDsaParams> Drop for ConfidentialVerificationWorkspace<P> {
            fn drop(&mut self) { self.zeroize(); }
        }
        impl<P: MlDsaParams> ZeroizeOnDrop for ConfidentialVerificationWorkspace<P> {}
        impl<P: MlDsaParams> core::fmt::Debug for ConfidentialVerificationWorkspace<P> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct("ConfidentialVerificationWorkspace").finish_non_exhaustive()
            }
        }
    };
}

workspace! {
    hash: HashWorkspace,
    matrix_sampling: MatrixWorkspace,
    sampling: SamplingWorkspace,
    matrix: NttMatrix<P::K, P::L>,
    t1: Vector<P::K>,
    t1_scaled: Vector<P::K>,
    t1_hat: NttVector<P::K>,
    tr: B64,
    mu: B64,
    z: Vector<P::L>,
    hints: Array<Array<bool, U256>, P::K>,
    c: Polynomial,
    c_hat: NttPolynomial,
    z_hat: NttVector<P::L>,
    az_hat: NttVector<P::K>,
    ct_hat: NttVector<P::K>,
    wp_hat: NttVector<P::K>,
    wp: Vector<P::K>,
    w1: Vector<P::K>,
    w1_bytes: EncodedW1<P>,
    candidate: Array<u8, P::Lambda>,
    product: NttPolynomial,
}

impl<P: MlDsaParams> ConfidentialVerificationWorkspace<P> {
    /// DE: Öffentliche feste Geometrie; so viele Guards vor Eingang vorbereiten.
    /// EN: Public fixed geometry; prepare this many guards before ingress.
    #[must_use]
    pub fn private_storage_count(&self) -> usize {
        self.matrix.row_count()
    }

    /// DE: Stabile Zeilenflächen besuchen; dürfen später nicht ersetzt werden.
    /// EN: Visit stable row storage; rows must never be replaced afterward.
    pub fn visit_private_storage(&self, visitor: impl FnMut(usize, usize) -> bool) -> bool {
        self.matrix.visit_rows(visitor)
    }
}
