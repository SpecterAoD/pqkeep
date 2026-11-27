//! DE: Ursprüngliche Signierformeln mit geliehenen privaten Zwischenzielen.
//! EN: Original signing formulas with borrowed private intermediate outputs.

use super::{ExpandedSigningKey, signing_nonces, workspace::SigningWorkspace};
use crate::{
    MlDsaParams, Signature,
    algebra::{AlgebraExt, Elem, NttPolynomial, NttVector, Vector},
    hint::{Hint, make_hint},
    ntt::{Ntt, NttInverse, multiply_ntt_into},
    param::SpecQ,
};
use hybrid_array::typenum::Unsigned;
use module_lattice::{ArraySize, MaybeBox, Truncate};
use signature::{Error, rand_core::TryCryptoRng};

fn product_into<K: ArraySize>(c: &NttPolynomial, v: &NttVector<K>, out: &mut NttVector<K>) {
    for (source, target) in v.0.iter().zip(out.0.iter_mut()) {
        multiply_ntt_into(c, source, target);
    }
}

fn combine<K: ArraySize>(
    a: &Vector<K>,
    b: &Vector<K>,
    out: &mut Vector<K>,
    f: impl Fn(Elem, Elem) -> Elem,
) {
    for ((a, b), out) in a.0.iter().zip(b.0.iter()).zip(out.0.iter_mut()) {
        for ((a, b), out) in a.0.iter().zip(b.0.iter()).zip(out.0.iter_mut()) {
            *out = f(*a, *b);
        }
    }
}

impl<P: MlDsaParams> ExpandedSigningKey<P> {
    /// DE: Caller sperrt den vollständigen Workspace vor privater Verarbeitung.
    /// EN: Caller prelocks the complete workspace before private processing.
    ///
    /// # Errors
    /// DE/EN: Kontext >255, OS-Zufallfehler oder erschöpfte Nonces / invalid context,
    /// OS randomness failure or exhausted nonces; no deterministic fallback.
    pub fn sign_randomized_with_workspace<R: TryCryptoRng + ?Sized>(
        &self,
        message: &[u8],
        context: &[u8],
        rng: &mut R,
        work: &mut SigningWorkspace<P>,
    ) -> Result<Signature<P>, Error> {
        if context.len() > 255 {
            return Err(Error::new());
        }
        rng.try_fill_bytes(&mut work.rnd)
            .map_err(|_| Error::new())?;
        let length: u8 = Truncate::truncate(context.len());
        work.hash
            .start(&[&self.tr, &[0], &[length], context, message]);
        work.hash.read(&mut work.mu);
        work.hash.start(&[&self.K, &work.rnd, &work.mu]);
        work.hash.read(&mut work.rhopp);
        for nonce in signing_nonces::<P>() {
            self.challenge_into(nonce, work)?;
            self.response_into(work);
            if work.z.infinity_norm() >= P::GAMMA1_MINUS_BETA
                || work.r0.infinity_norm() >= P::GAMMA2_MINUS_BETA
            {
                continue;
            }
            let weight = self.hints_into(work);
            if work.ct0.infinity_norm() >= P::Gamma2::U32 || weight > P::Omega::USIZE {
                continue;
            }
            return Ok(Self::accepted_signature(work));
        }
        Err(Error::new())
    }

    // DE: Ausschließlich nach beiden Akzeptanzprüfungen aufrufen.
    // EN: Call only after both acceptance checks.
    fn accepted_signature(work: &mut SigningWorkspace<P>) -> Signature<P> {
        for poly in &mut work.z.0 {
            for value in &mut poly.0 {
                *value = value.mod_plus_minus::<SpecQ>();
            }
        }
        Signature {
            c_tilde: work.challenge.clone(),
            z: MaybeBox::new(work.z.clone()),
            h: Hint(MaybeBox::new(work.hints.clone())),
        }
    }

    fn challenge_into(&self, nonce: u16, work: &mut SigningWorkspace<P>) -> Result<(), Error> {
        work.sampling.mask_into::<P::L, P::Gamma1>(
            &work.rhopp,
            nonce,
            &mut work.mask_bytes,
            &mut work.y,
        );
        work.y.ntt_into(&mut work.y_hat);
        self.A_hat
            .multiply_into(&work.y_hat, &mut work.w_hat, &mut work.product);
        work.w_hat.ntt_inverse_into(&mut work.w);
        for (source, target) in work.w.0.iter().zip(work.w1.0.iter_mut()) {
            for (source, target) in source.0.iter().zip(target.0.iter_mut()) {
                *target = source.high_bits::<P::TwoGamma2>();
            }
        }
        P::encode_w1_into(&work.w1, &mut work.w1_bytes).map_err(|_| Error::new())?;
        work.hash.start(&[&work.mu, &work.w1_bytes]);
        work.hash.read(&mut work.challenge);
        work.sampling
            .ball_into(&work.challenge, P::TAU, &mut work.c);
        work.c.ntt_into(&mut work.c_hat);
        Ok(())
    }

    fn response_into(&self, work: &mut SigningWorkspace<P>) {
        product_into(&work.c_hat, &self.s1_hat, &mut work.product_l);
        work.product_l.ntt_inverse_into(&mut work.cs1);
        product_into(&work.c_hat, &self.s2_hat, &mut work.product_k);
        work.product_k.ntt_inverse_into(&mut work.cs2);
        combine(&work.y, &work.cs1, &mut work.z, |a, b| a + b);
        combine(&work.w, &work.cs2, &mut work.r0, |a, b| {
            (a - b).low_bits::<P::TwoGamma2>()
        });
    }

    fn hints_into(&self, work: &mut SigningWorkspace<P>) -> usize {
        product_into(&work.c_hat, &self.t0_hat, &mut work.product_k);
        work.product_k.ntt_inverse_into(&mut work.ct0);
        combine(&work.w, &work.cs2, &mut work.hint_input, |a, b| a - b);
        let mut weight = 0;
        for ((ct0, input), hints) in work
            .ct0
            .0
            .iter()
            .zip(work.hint_input.0.iter_mut())
            .zip(work.hints.iter_mut())
        {
            for ((ct0, input), hint) in ct0.0.iter().zip(input.0.iter_mut()).zip(hints.iter_mut()) {
                *input = *input + *ct0;
                *hint = make_hint::<P::TwoGamma2>(-*ct0, *input);
                weight += usize::from(*hint);
            }
        }
        weight
    }
}
