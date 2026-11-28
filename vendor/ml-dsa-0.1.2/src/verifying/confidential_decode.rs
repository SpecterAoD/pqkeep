//! DE: Signatur-Hints ohne gewöhnliche Schnitt-/Index-/Hint-Arrays dekodieren.
//! EN: Decode signature hints without ordinary cut/index/hint arrays.

use super::confidential::ConfidentialVerificationWorkspace;
use crate::{EncodedSignature, MlDsaParams, algebra::AlgebraExt, param::EncodedHint};
use hybrid_array::typenum::Unsigned;

impl<P: MlDsaParams> ConfidentialVerificationWorkspace<P> {
    pub(super) fn decode_signature(&mut self, signature: &EncodedSignature<P>) -> bool {
        let (_, z, hints) = P::split_sig(signature);
        P::decode_z_into(z, &mut self.z);
        self.z.infinity_norm() < P::GAMMA1_MINUS_BETA && self.decode_hints(hints)
    }

    fn decode_hints(&mut self, bytes: &EncodedHint<P>) -> bool {
        let (indices, cuts) = P::split_hint(bytes);
        self.hints.iter_mut().for_each(|row| row.fill(false));
        let mut start = 0;
        for (row, end) in self.hints.iter_mut().zip(cuts.iter()) {
            let end = usize::from(*end);
            if end < start || end > P::Omega::USIZE {
                return false;
            }
            let selected = &indices[start..end];
            if !selected.windows(2).all(|pair| pair[0] < pair[1]) {
                return false;
            }
            for index in selected {
                row[usize::from(*index)] = true;
            }
            start = end;
        }
        indices[start..].iter().all(|byte| *byte == 0)
    }
}
