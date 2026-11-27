//! DE: Vorhandene PKE-Verschlüsselung mit vollständig geliehenen privaten Flächen.
//! EN: Existing PKE encryption with entirely borrowed private storage.

use super::EncryptionKey;
use crate::{
    B32, EncryptionWorkspace,
    algebra::{
        BaseField, Ntt, NttInverse, NttMatrix, NttVector, dot_ntt_into, matrix_sample_ntt,
        sample_poly_cbd_into, sample_poly_vec_cbd_into,
    },
    compress::Compress,
    crypto::PRF_into_with_xof,
    param::PkeParams,
};
use array::typenum::{U1, Unsigned};
use kem::InvalidKey;
use module_lattice::{byte_decode_into, byte_encode_into, byte_encode_vector_into};

impl<P: PkeParams> EncryptionKey<P> {
    // DE: Auch das interne Vergleichs-Chiffrat ausschließlich im geliehenen Ziel halten.
    // EN: Keep even internal candidate ciphertext exclusively in borrowed storage.
    pub(crate) fn encrypt_into(
        &self,
        message: &B32,
        randomness: &B32,
        workspace: &mut EncryptionWorkspace<P>,
    ) -> Result<(), InvalidKey> {
        workspace.sample(randomness);
        let matrix = matrix_sample_ntt(&self.rho, true);
        workspace.transform(&matrix, &self.t_hat);
        workspace.finish(message)
    }
}

impl<P: PkeParams> EncryptionWorkspace<P> {
    fn sample(&mut self, randomness: &B32) {
        sample_poly_vec_cbd_into::<P::Eta1, P::K>(
            randomness,
            0,
            &mut self.random,
            &mut self.prf1,
            &mut self.xof,
            &mut self.reader,
        );
        sample_poly_vec_cbd_into::<P::Eta2, P::K>(
            randomness,
            P::K::U8,
            &mut self.error,
            &mut self.prf2,
            &mut self.xof,
            &mut self.reader,
        );
        PRF_into_with_xof::<P::Eta2>(
            randomness,
            2 * P::K::U8,
            &mut self.prf2,
            &mut self.xof,
            &mut self.reader,
        );
        sample_poly_cbd_into::<P::Eta2>(&self.prf2, &mut self.error_scalar);
        self.random.ntt_into(&mut self.random_hat);
    }

    fn transform(&mut self, matrix: &NttMatrix<P::K>, public: &NttVector<P::K>) {
        for ((row, target), error) in matrix
            .0
            .iter()
            .zip(self.u.0.iter_mut())
            .zip(self.error.0.iter())
        {
            dot_ntt_into(row, &self.random_hat, &mut self.sum, &mut self.product);
            self.sum.ntt_inverse_into(target);
            for (value, error) in target.0.iter_mut().zip(error.0.iter()) {
                *value = *value + *error;
            }
        }
        dot_ntt_into(public, &self.random_hat, &mut self.sum, &mut self.product);
        self.sum.ntt_inverse_into(&mut self.dot);
    }

    fn finish(&mut self, message: &B32) -> Result<(), InvalidKey> {
        byte_decode_into::<BaseField, U1>(message, &mut self.message.0);
        self.message.decompress::<U1>();
        for (((out, dot), error), message) in self
            .v
            .0
            .iter_mut()
            .zip(self.dot.0.iter())
            .zip(self.error_scalar.0.iter())
            .zip(self.message.0.iter())
        {
            *out = (*dot + *error) + *message;
        }
        self.u.compress::<P::Du>();
        self.v.compress::<P::Dv>();
        let (c1, c2) = P::split_ct_mut(&mut self.ciphertext);
        byte_encode_vector_into::<BaseField, P::Du, P::K>(&self.u, c1).map_err(|_| InvalidKey)?;
        byte_encode_into::<BaseField, P::Dv>(&self.v.0, c2);
        Ok(())
    }
}
