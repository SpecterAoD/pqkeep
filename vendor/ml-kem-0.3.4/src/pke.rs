use crate::B32;
use crate::algebra::{
    Ntt, NttInverse, NttMatrix, NttVector, Polynomial, Vector, matrix_sample_ntt, sample_poly_cbd,
    sample_poly_vec_cbd,
};
use crate::compress::Compress;
use crate::crypto::PRF;
use crate::param::{EncodedDecryptionKey, EncodedEncryptionKey, PkeParams};
use array::typenum::{U1, Unsigned};
use core::fmt;
use kem::{Ciphertext, InvalidKey};
use module_lattice::{
    Encode,
    ctutils::{Choice, CtEq},
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(feature = "protected-workspace")]
#[path = "pke_decrypt.rs"]
mod protected_decrypt;
#[cfg(feature = "protected-workspace")]
#[path = "pke_encrypt.rs"]
mod protected_encrypt;

/// A `DecryptionKey` provides the ability to generate a new key pair, and decrypt an
/// encrypted value.
#[derive(Clone, Default)]
pub(crate) struct DecryptionKey<P>
where
    P: PkeParams,
{
    s_hat: NttVector<P::K>,
}

// Don't print the secret vector `s_hat`
impl<P> fmt::Debug for DecryptionKey<P>
where
    P: PkeParams,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptionKey").finish_non_exhaustive()
    }
}

impl<P> CtEq for DecryptionKey<P>
where
    P: PkeParams,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.s_hat.ct_eq(&other.s_hat)
    }
}

impl<P> Eq for DecryptionKey<P> where P: PkeParams {}
impl<P> PartialEq for DecryptionKey<P>
where
    P: PkeParams,
{
    fn eq(&self, other: &Self) -> bool {
        // Compare decryption keys in constant-time
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "zeroize")]
impl<P> Zeroize for DecryptionKey<P>
where
    P: PkeParams,
{
    fn zeroize(&mut self) {
        self.s_hat.zeroize();
    }
}

impl<P> DecryptionKey<P>
where
    P: PkeParams,
{
    /// Generate a new random decryption key according to the `K-PKE.KeyGen` procedure.
    // Algorithm 12. K-PKE.KeyGen()
    pub(crate) fn generate(d: &B32) -> (Self, EncryptionKey<P>) {
        let mut dk = Self::default();
        let ek = dk.generate_in_place(d);
        (dk, ek)
    }

    // DE: Erweiterten Schlüssel direkt im bestehenden Ziel befüllen; kein privates Self zurück.
    // EN: Populate the expanded key in existing storage; never return private Self here.
    pub(crate) fn generate_in_place(&mut self, d: &B32) -> EncryptionKey<P> {
        self.generate_with_workspace(d, &mut crate::KeyGenerationWorkspace::default())
    }

    // DE: Alle festen privaten Vektoren direkt in vorab gesperrtem Caller-Speicher.
    // EN: Keep all fixed private vectors directly in caller-prelocked storage.
    pub(crate) fn generate_with_workspace(
        &mut self,
        d: &B32,
        workspace: &mut crate::KeyGenerationWorkspace<P>,
    ) -> EncryptionKey<P> {
        let k = P::K::U8;
        crate::crypto::G_into_with_hash(&[&d[..], &[k]], &mut workspace.g, &mut workspace.hash);
        let (rho, sigma) = workspace.g.split_ref::<array::typenum::U32>();
        let A_hat: NttMatrix<P::K> = matrix_sample_ntt(rho, false);
        crate::algebra::sample_poly_vec_cbd_into::<P::Eta1, P::K>(
            sigma,
            0,
            &mut workspace.sampled,
            &mut workspace.prf,
            &mut workspace.xof,
            &mut workspace.reader,
        );
        workspace.sampled.ntt_into(&mut self.s_hat);
        crate::algebra::sample_poly_vec_cbd_into::<P::Eta1, P::K>(
            sigma,
            P::K::U8,
            &mut workspace.sampled,
            &mut workspace.prf,
            &mut workspace.xof,
            &mut workspace.reader,
        );
        workspace.sampled.ntt_into(&mut workspace.error);
        let rho = rho.clone();
        workspace.compute_public(&A_hat, &self.s_hat);
        // DE: Erst nach vollständiger Fehleraddition sind t_hat/rho öffentliche Ausgabe.
        // EN: Only after complete error addition are t_hat/rho public output.
        EncryptionKey {
            t_hat: workspace.public.clone(),
            rho,
        }
    }

    /// Decrypt ciphertext to obtain the encrypted value, according to the K-PKE.Decrypt procedure.
    // Algorithm 14. kK-PKE.Decrypt(dk_PKE, c)
    pub(crate) fn decrypt(&self, ciphertext: &Ciphertext<P>) -> B32 {
        let (c1, c2) = P::split_ct(ciphertext);

        let mut u: Vector<P::K> = Encode::<P::Du>::decode(c1);
        u.decompress::<P::Du>();

        let mut v: Polynomial = Encode::<P::Dv>::decode(c2);
        v.decompress::<P::Dv>();

        let u_hat = u.ntt();
        let sTu = (&self.s_hat * &u_hat).ntt_inverse();
        let mut w = &v - &sTu;
        Encode::<U1>::encode(w.compress::<U1>())
    }

    /// Represent this decryption key as a byte array `(s_hat)`
    pub(crate) fn to_bytes(&self) -> EncodedDecryptionKey<P> {
        P::encode_u12(&self.s_hat)
    }

    /// Parse an decryption key from a byte array `(s_hat)`
    pub(crate) fn from_bytes(enc: &EncodedDecryptionKey<P>) -> Self {
        let s_hat = P::decode_u12(enc);
        Self { s_hat }
    }
}

/// An `EncryptionKey` provides the ability to encrypt a value so that it can only be
/// decrypted by the holder of the corresponding decapsulation key.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub(crate) struct EncryptionKey<P>
where
    P: PkeParams,
{
    t_hat: NttVector<P::K>,
    rho: B32,
}

impl<P> EncryptionKey<P>
where
    P: PkeParams,
{
    /// Encrypt the specified message for the holder of the corresponding decryption key, using the
    /// provided randomness, according the `K-PKE.Encrypt` procedure.
    pub(crate) fn encrypt(&self, message: &B32, randomness: &B32) -> Ciphertext<P> {
        let r = sample_poly_vec_cbd::<P::Eta1, P::K>(randomness, 0);
        let e1 = sample_poly_vec_cbd::<P::Eta2, P::K>(randomness, P::K::U8);

        let prf_output = PRF::<P::Eta2>(randomness, 2 * P::K::U8);
        let e2: Polynomial = sample_poly_cbd::<P::Eta2>(&prf_output);

        let A_hat_t: NttMatrix<P::K> = matrix_sample_ntt(&self.rho, true);
        let r_hat: NttVector<P::K> = r.ntt();
        let ATr: Vector<P::K> = (&A_hat_t * &r_hat).ntt_inverse();
        let mut u = ATr + e1;

        let mut mu: Polynomial = Encode::<U1>::decode(message);
        mu.decompress::<U1>();

        let tTr: Polynomial = (&self.t_hat * &r_hat).ntt_inverse();
        let mut v = &(&tTr + &e2) + &mu;

        let c1 = Encode::<P::Du>::encode(u.compress::<P::Du>());
        let c2 = Encode::<P::Dv>::encode(v.compress::<P::Dv>());
        P::concat_ct(c1, c2)
    }

    /// Represent this encryption key as a byte array `(t_hat || rho)`
    pub(crate) fn to_bytes(&self) -> EncodedEncryptionKey<P> {
        let t_hat = P::encode_u12(&self.t_hat);
        P::concat_ek(t_hat, self.rho.clone())
    }

    /// Parse an encryption key from a byte array `(t_hat || rho)`.
    ///
    /// # Errors
    /// Returns [`InvalidKey`] in the event that the key fails the encapsulation key checks
    /// specified in FIPS 203 §7.2.
    pub(crate) fn from_bytes(enc: &EncodedEncryptionKey<P>) -> Result<Self, InvalidKey> {
        let (t_hat, rho) = P::split_ek(enc);
        let t_hat = P::decode_u12(t_hat);
        let ret = Self {
            t_hat,
            rho: rho.clone(),
        };

        // Check the candidate encapsulation key is valid using the method specified in FIPS 203
        // §7.2 ML-KEM Encapsulation:
        //
        // > Encapsulation key check. To check a candidate encapsulation key `ek`, perform the
        // > following:
        // >
        // > 1. (Type check) If `ek` is not an array of bytes of length 384𝑘+32 for the value of 𝑘
        // >    specified by the relevant parameter set, then input checking failed.
        // > 2. (Modulus check) Perform the computation:
        // >
        // >    test ← ByteEncode₁₂(ByteDecode₁₂(ek[0:384𝑘]))
        // >
        // >    (see Section 4.2.1). If `test ≠ ek[0∶384𝑘]`, then input checking failed. This
        // >    check ensures that the integers encoded in the public key are in the valid range
        // >    `[0,q-1]`.
        // >
        // > If both checks pass, then `ML-KEM.Encaps` can be run with input `ek`. It is important
        // > to note that this checking process does not guarantee that ek is a properly produced
        // > output of `ML-KEM.KeyGen`.
        // >
        // > `ML-KEM.Encaps` shall not be run with an encapsulation key that has not been checked as
        // > above.
        //
        // #1 is performed by the `EncodedEncryptionKey` type, and the following check vicariously
        // performs #2 by encoding the integer-mod-q array using our implementation of ByteEncode₁₂
        // and comparing the resulting serialization to see if it round-trips.
        if &ret.to_bytes() == enc {
            Ok(ret)
        } else {
            Err(InvalidKey)
        }
    }
}
