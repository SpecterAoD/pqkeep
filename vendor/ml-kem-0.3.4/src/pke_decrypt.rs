//! DE: Private Entschlüsselungs-Zwischenwerte direkt in geliehene Ziele schreiben.
//! EN: Write private decryption intermediates directly into borrowed destinations.

use super::DecryptionKey;
use crate::{
    B32, Ciphertext, DecryptionWorkspace,
    algebra::{BaseField, Ntt, NttInverse, Polynomial, Vector, dot_ntt_into},
    compress::Compress,
    param::PkeParams,
};
use array::typenum::U1;
use module_lattice::{Encode, byte_encode_into};

impl<P: PkeParams> DecryptionKey<P> {
    pub(crate) fn decrypt_into(
        &self,
        ciphertext: &Ciphertext<P>,
        workspace: &mut DecryptionWorkspace,
        out: &mut B32,
    ) {
        let (c1, c2) = P::split_ct(ciphertext);
        // DE: Diese Operanden hängen ausschließlich vom empfangenen öffentlichen Chiffrat ab.
        // EN: These operands depend only on the received public ciphertext.
        let mut u: Vector<P::K> = Encode::<P::Du>::decode(c1);
        u.decompress::<P::Du>();
        let mut v: Polynomial = Encode::<P::Dv>::decode(c2);
        v.decompress::<P::Dv>();
        let u_hat = u.ntt();
        dot_ntt_into(
            &self.s_hat,
            &u_hat,
            &mut workspace.sum,
            &mut workspace.product,
        );
        workspace
            .sum
            .ntt_inverse_into(&mut workspace.decrypted_product);
        for ((out, public), private) in workspace
            .message
            .0
            .iter_mut()
            .zip(v.0.iter())
            .zip(workspace.decrypted_product.0.iter())
        {
            *out = *public - *private;
        }
        workspace.message.compress::<U1>();
        byte_encode_into::<BaseField, U1>(&workspace.message.0, out);
    }
}
