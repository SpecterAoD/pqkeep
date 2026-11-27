//! DE: Feste Inline-Flächen; gesamtes Objekt vor privater Befüllung sperren.
//! EN: Fixed inline workspaces; prelock the entire object before private population.

use crate::{
    B32, Ciphertext, EncapsulationWorkspace,
    algebra::{NttPolynomial, NttVector, Polynomial, Vector},
    crypto::PrfOutput,
    param::{KemParams, PkeParams},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

// DE: Jede deklarierte Fläche erhält Default und Wipe aus derselben Feldliste.
// EN: Generate public defaults and complete wiping from the same field list.
macro_rules! workspace {
    ($name:ident $(<$p:ident: $bound:path>)? { $($field:ident: $ty:ty),+ $(,)? }) => {
        /// DE: Feste private Arbeitsfläche; Caller muss das ganze Objekt vorab sperren.
        /// EN: Fixed private workspace; caller must prelock the complete object.
        pub struct $name $(<$p: $bound>)? { $(pub(crate) $field: $ty),+ }
        impl $(<$p: $bound>)? Default for $name $(<$p>)? {
            fn default() -> Self { Self { $($field: Default::default()),+ } }
        }
        impl $(<$p: $bound>)? Zeroize for $name $(<$p>)? {
            fn zeroize(&mut self) { $(self.$field.zeroize();)+ }
        }
        impl $(<$p: $bound>)? ZeroizeOnDrop for $name $(<$p>)? {}
        impl $(<$p: $bound>)? Drop for $name $(<$p>)? {
            fn drop(&mut self) { self.zeroize(); }
        }
        impl $(<$p: $bound>)? core::fmt::Debug for $name $(<$p>)? {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    };
}

workspace!(EncryptionWorkspace<P: PkeParams> {
    random: Vector<P::K>,
    error: Vector<P::K>,
    error_scalar: Polynomial,
    random_hat: NttVector<P::K>,
    u: Vector<P::K>,
    message: Polynomial,
    dot: Polynomial,
    v: Polynomial,
    product: NttPolynomial,
    sum: NttPolynomial,
    prf1: PrfOutput<P::Eta1>,
    prf2: PrfOutput<P::Eta2>,
    xof: shake::Shake256,
    reader: shake::Shake256Reader,
    ciphertext: Ciphertext<P>,
});

workspace!(DecryptionWorkspace {
    product: NttPolynomial,
    sum: NttPolynomial,
    decrypted_product: Polynomial,
    message: Polynomial,
});

workspace!(DecapsulationWorkspace<P: KemParams> {
    encryption: EncryptionWorkspace<P>,
    decryption: DecryptionWorkspace,
    message: B32,
    g: EncapsulationWorkspace,
    rejection: B32,
    hash: sha3::Sha3_512,
    xof: shake::Shake256,
    reader: shake::Shake256Reader,
});
