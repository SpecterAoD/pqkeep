//! DE: Öffentliche Vorbereitung vor Host-Sperren, dann private In-place-Keygen.
//! EN: Public preparation before host locking, followed by private in-place keygen.

use super::{ExpandedSigningKey, SigningKey};
use crate::{
    B32, B64, MlDsaParams, Seed, VerifyingKey,
    algebra::{AlgebraExt, NttMatrix, NttPolynomial, NttVector, Vector},
    hash_workspace::HashWorkspace,
    ntt::{Ntt, NttInverse},
    param::SamplingSize,
    sampling::{expand_a, in_place::SamplingWorkspace},
};
use hybrid_array::typenum::Unsigned;
use module_lattice::MaybeBox;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DE: Schlüsselzustand und beide privaten Payloads vor Seed-Befüllung sperren.
/// EN: Prelock key state and both private payloads before seed population.
pub trait SeedKeyInPlace: Zeroize + ZeroizeOnDrop + Sized {
    /// DE/EN: Feste, vorab zu sperrende Arbeitsfläche / fixed workspace to prelock.
    type Workspace: Default + ZeroizeOnDrop;
    /// DE/EN: Nur öffentliche Anfangswerte / public initial values only.
    #[must_use]
    fn public_state() -> Self;
    /// DE: Genau zwei private Payloads; Adressgeometrie nicht protokollieren.
    /// EN: Exactly two private payloads; do not log address geometry.
    fn visit_private_storage(&self, visit: impl FnMut(usize, usize) -> bool) -> bool;
    /// DE: Zustand, beide Payloads und Workspace müssen bereits gesperrt sein.
    /// EN: State, both payloads and workspace must already be locked.
    fn initialize_seed_with_workspace(&mut self, seed: &Seed, work: &mut Self::Workspace);
}

/// DE: Vollständig inline; gesamtes Objekt vor Seed-Verarbeitung sperren.
/// EN: Entirely inline; lock the complete object before seed processing.
pub struct KeyGenerationWorkspace<P: MlDsaParams> {
    hash: HashWorkspace,
    sampling: SamplingWorkspace,
    rhop: B64,
    product: NttPolynomial,
    sum: NttVector<P::K>,
    t: Vector<P::K>,
    t1: Vector<P::K>,
}

impl<P: MlDsaParams> Default for KeyGenerationWorkspace<P> {
    fn default() -> Self {
        Self {
            hash: Default::default(),
            sampling: Default::default(),
            rhop: Default::default(),
            product: Default::default(),
            sum: Default::default(),
            t: Default::default(),
            t1: Default::default(),
        }
    }
}

impl<P: MlDsaParams> Zeroize for KeyGenerationWorkspace<P> {
    fn zeroize(&mut self) {
        self.hash.zeroize();
        self.sampling.zeroize();
        self.rhop.zeroize();
        self.product.zeroize();
        self.sum.zeroize();
        self.t.zeroize();
        self.t1.zeroize();
    }
}
impl<P: MlDsaParams> Drop for KeyGenerationWorkspace<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl<P: MlDsaParams> ZeroizeOnDrop for KeyGenerationWorkspace<P> {}
impl<P: MlDsaParams> core::fmt::Debug for KeyGenerationWorkspace<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyGenerationWorkspace")
            .finish_non_exhaustive()
    }
}

impl<P: MlDsaParams> SeedKeyInPlace for SigningKey<P> {
    type Workspace = KeyGenerationWorkspace<P>;

    fn public_state() -> Self {
        let rho = B32::default();
        let t1 = Vector::default();
        let verifying_key = VerifyingKey::new(rho.clone(), t1, expand_a(&rho), None);
        let expanded_key = ExpandedSigningKey {
            rho,
            K: Default::default(),
            tr: Default::default(),
            s1: Default::default(),
            s2: Default::default(),
            t0: Default::default(),
            s1_hat: Default::default(),
            s2_hat: Default::default(),
            t0_hat: Default::default(),
            A_hat: NttMatrix::from_fn(|_| NttVector::default()),
        };
        Self {
            expanded_key: MaybeBox::new(expanded_key),
            seed: MaybeBox::new(Seed::default()),
            verifying_key,
        }
    }

    fn visit_private_storage(&self, mut visit: impl FnMut(usize, usize) -> bool) -> bool {
        visit(
            core::ptr::from_ref(&*self.expanded_key).addr(),
            size_of::<ExpandedSigningKey<P>>(),
        ) && visit(core::ptr::from_ref(&*self.seed).addr(), size_of::<Seed>())
    }

    fn initialize_seed_with_workspace(&mut self, seed: &Seed, work: &mut Self::Workspace) {
        self.seed.copy_from_slice(seed);
        let key = &mut *self.expanded_key;
        work.hash.start(&[seed, &[P::K::U8], &[P::L::U8]]);
        work.hash.read(&mut key.rho);
        work.hash.read(&mut work.rhop);
        work.hash.read(&mut key.K);
        // DE: Ausschließlich öffentliche rho-Matrix darf ungesperrt alloziert werden.
        // EN: Only the public rho-derived matrix may allocate outside locks.
        key.A_hat = expand_a(&key.rho);
        work.sampling
            .expand_s_into(&work.rhop, P::Eta::ETA, 0, &mut key.s1);
        work.sampling
            .expand_s_into(&work.rhop, P::Eta::ETA, P::L::USIZE, &mut key.s2);
        key.s1.ntt_into(&mut key.s1_hat);
        key.A_hat
            .multiply_into(&key.s1_hat, &mut work.sum, &mut work.product);
        work.sum.ntt_inverse_into(&mut work.t);
        work.round_into(key);
        key.s2.ntt_into(&mut key.s2_hat);
        key.t0.ntt_into(&mut key.t0_hat);
        // DE/EN: Erst die fertigen öffentlichen t1/rho verlassen den Workspace.
        // Only completed public t1/rho leave the workspace.
        let enc = VerifyingKey::<P>::encode_internal(&key.rho, &work.t1);
        work.hash.start(&[&enc]);
        work.hash.read(&mut key.tr);
        self.verifying_key = VerifyingKey::new(
            key.rho.clone(),
            work.t1.clone(),
            key.A_hat.clone(),
            Some(enc),
        );
    }
}

impl<P: MlDsaParams> ExpandedSigningKey<P> {
    /// DE: Nur öffentliche Defaults; Caller sperrt Objekt und alle Matrixzeilen.
    /// EN: Public defaults only; caller prelocks object and every matrix row.
    #[must_use]
    pub fn public_confidential_state() -> Self {
        Self {
            rho: Default::default(),
            K: Default::default(),
            tr: Default::default(),
            s1: Default::default(),
            s2: Default::default(),
            t0: Default::default(),
            s1_hat: Default::default(),
            s2_hat: Default::default(),
            t0_hat: Default::default(),
            A_hat: Default::default(),
        }
    }

    /// DE/EN: Öffentliche feste Zeilenanzahl / public fixed row count.
    #[must_use]
    pub fn confidential_storage_count(&self) -> usize {
        self.A_hat.row_count()
    }

    /// DE: Jede Zeile muss vor privater Konstruktion gesperrt sein.
    /// EN: Every row must be locked before private construction.
    pub fn visit_confidential_storage(&self, visitor: impl FnMut(usize, usize) -> bool) -> bool {
        self.A_hat.visit_rows(visitor)
    }

    /// DE: Einschließlich zuvor öffentlich klassifizierter Matrix vor Unlock löschen.
    /// EN: Wipe the formerly public-classified matrix as well before unlocking.
    pub fn zeroize_confidential(&mut self) {
        self.A_hat.zeroize();
        self.zeroize();
    }

    /// DE: Objekt, Zeilen und Arbeitsfläche müssen vollständig gesperrt sein.
    /// EN: Object, rows and workspace must all be fully locked.
    /// # Errors
    /// DE/EN: Ungültige öffentliche Zielgeometrie / invalid public output geometry.
    pub fn initialize_confidential_seed(
        &mut self,
        seed: &Seed,
        work: &mut super::confidential_key::ConfidentialKeyGenerationWorkspace<P>,
    ) -> Result<(), signature::Error> {
        work.inner.hash.start(&[seed, &[P::K::U8], &[P::L::U8]]);
        work.inner.hash.read(&mut self.rho);
        work.inner.hash.read(&mut work.inner.rhop);
        work.inner.hash.read(&mut self.K);
        work.matrix_sampling.expand(&self.rho, &mut self.A_hat);
        work.inner
            .sampling
            .expand_s_into(&work.inner.rhop, P::Eta::ETA, 0, &mut self.s1);
        work.inner
            .sampling
            .expand_s_into(&work.inner.rhop, P::Eta::ETA, P::L::USIZE, &mut self.s2);
        self.s1.ntt_into(&mut self.s1_hat);
        self.A_hat
            .multiply_into(&self.s1_hat, &mut work.inner.sum, &mut work.inner.product);
        work.inner.sum.ntt_inverse_into(&mut work.inner.t);
        work.inner.round_into(self);
        self.s2.ntt_into(&mut self.s2_hat);
        self.t0.ntt_into(&mut self.t0_hat);
        let (rho, t1) = work.encoded.as_mut_slice().split_at_mut(32);
        rho.copy_from_slice(&self.rho);
        let t1 = t1.try_into().map_err(|_| signature::Error::new())?;
        P::encode_t1_into(&work.inner.t1, t1);
        work.inner.hash.start(&[&work.encoded]);
        work.inner.hash.read(&mut self.tr);
        Ok(())
    }
}

impl<P: MlDsaParams> KeyGenerationWorkspace<P> {
    fn round_into(&mut self, key: &mut ExpandedSigningKey<P>) {
        for ((t, s2), (t1, t0)) in self
            .t
            .0
            .iter_mut()
            .zip(key.s2.0.iter())
            .zip(self.t1.0.iter_mut().zip(key.t0.0.iter_mut()))
        {
            for ((value, error), (high, low)) in
                t.0.iter_mut()
                    .zip(s2.0.iter())
                    .zip(t1.0.iter_mut().zip(t0.0.iter_mut()))
            {
                *value = *value + *error;
                (*high, *low) = value.power2round();
            }
        }
    }
}
