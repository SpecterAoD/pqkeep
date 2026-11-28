//! DE: Ursprüngliche Verifikationsgleichung ausschließlich in gesperrten Zielen.
//! EN: Original verification equation using protected destinations throughout.

use super::confidential::ConfidentialVerificationWorkspace;
use crate::{
    EncodedSignature, EncodedVerifyingKey, MlDsaParams,
    algebra::Elem,
    hint::use_hint,
    ntt::{Ntt, NttInverse, multiply_ntt_into},
};
use ctutils::CtEq;
use module_lattice::Truncate;

impl<P: MlDsaParams> ConfidentialVerificationWorkspace<P> {
    /// DE: Caller muss Objekt und besuchte Matrixzeilen vorab sperren.
    /// Schlüssel/Signatur werden nur geliehen; keine Dekodier-Owner zurückgeben.
    /// EN: Caller must prelock the object and every visited matrix row.
    /// Borrow key/signature; never return owned decoding intermediates.
    #[must_use]
    pub fn verify_encoded(
        &mut self,
        key: &EncodedVerifyingKey<P>,
        message: &[u8],
        context: &[u8],
        signature: &EncodedSignature<P>,
    ) -> bool {
        if context.len() > 255 || !self.decode_signature(signature) {
            return false;
        }
        self.prepare_key(key);
        let length: u8 = Truncate::truncate(context.len());
        self.hash
            .start(&[&self.tr, &[0], &[length], context, message]);
        self.hash.read(&mut self.mu);
        let (challenge, _, _) = P::split_sig(signature);
        self.sampling.ball_into(challenge, P::TAU, &mut self.c);
        self.c.ntt_into(&mut self.c_hat);
        self.z.ntt_into(&mut self.z_hat);
        self.matrix
            .multiply_into(&self.z_hat, &mut self.az_hat, &mut self.product);
        self.reconstruct_w1();
        if P::encode_w1_into(&self.w1, &mut self.w1_bytes).is_err() {
            return false;
        }
        self.hash.start(&[&self.mu, &self.w1_bytes]);
        self.hash.read(&mut self.candidate);
        challenge.ct_eq(&self.candidate).into()
    }

    fn prepare_key(&mut self, key: &EncodedVerifyingKey<P>) {
        let (rho, t1) = P::split_vk(key);
        P::decode_t1_into(t1, &mut self.t1);
        self.matrix_sampling.expand(rho, &mut self.matrix);
        for (source, target) in self.t1.0.iter().zip(self.t1_scaled.0.iter_mut()) {
            for (source, target) in source.0.iter().zip(target.0.iter_mut()) {
                *target = Elem::new(1 << 13) * *source;
            }
        }
        self.t1_scaled.ntt_into(&mut self.t1_hat);
        self.hash.start(&[key.as_slice()]);
        self.hash.read(&mut self.tr);
    }

    fn reconstruct_w1(&mut self) {
        for (source, target) in self.t1_hat.0.iter().zip(self.ct_hat.0.iter_mut()) {
            multiply_ntt_into(&self.c_hat, source, target);
        }
        for ((a, b), out) in self
            .az_hat
            .0
            .iter()
            .zip(self.ct_hat.0.iter())
            .zip(self.wp_hat.0.iter_mut())
        {
            for ((a, b), out) in a.0.iter().zip(b.0.iter()).zip(out.0.iter_mut()) {
                *out = *a - *b;
            }
        }
        self.wp_hat.ntt_inverse_into(&mut self.wp);
        for ((poly, hints), out) in self
            .wp
            .0
            .iter()
            .zip(self.hints.iter())
            .zip(self.w1.0.iter_mut())
        {
            for ((value, hint), out) in poly.0.iter().zip(hints.iter()).zip(out.0.iter_mut()) {
                *out = use_hint::<P::TwoGamma2>(*hint, *value);
            }
        }
    }
}
