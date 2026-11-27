//! DE: Gleiche Koeffizientenwahl, aber ausschließlich geliehene private Flächen.
//! EN: Preserve coefficient selection using borrowed private storage only.

use super::{Eta, coeffs_from_byte};
use crate::{
    algebra::{Polynomial, Vector},
    hash_workspace::HashWorkspace,
};
use hybrid_array::{
    Array,
    typenum::{U1, U8, U272},
};
use module_lattice::{ArraySize, Truncate};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DE: Sampler inklusive Hash, Reader und Ausgabebytes vorab sperren.
/// EN: Prelock sampler including hash, reader and output bytes.
#[derive(Default)]
pub(crate) struct SamplingWorkspace {
    hash: HashWorkspace,
    bytes: Array<u8, U272>,
    byte: Array<u8, U1>,
    signs: Array<u8, U8>,
}

impl SamplingWorkspace {
    pub(crate) fn mask_into<K: ArraySize, G: crate::param::MaskSamplingSize>(
        &mut self,
        rho: &[u8],
        nonce: u16,
        bytes: &mut Array<u8, G::SampleSize>,
        out: &mut Vector<K>,
    ) {
        for (index, polynomial) in out.0.iter_mut().enumerate() {
            let index: u16 = Truncate::truncate(index);
            self.hash.start(&[rho, &(nonce + index).to_le_bytes()]);
            self.hash.read(bytes);
            G::unpack_into(bytes, polynomial);
        }
    }

    pub(crate) fn ball_into(&mut self, rho: &[u8], tau: usize, out: &mut Polynomial) {
        use crate::algebra::{BaseField, Elem};
        use module_lattice::Field;
        out.0.fill(Elem::new(0));
        self.hash.start(&[rho]);
        self.hash.read(&mut self.signs);
        for i in (256 - tau)..256 {
            self.hash.read(&mut self.byte);
            while usize::from(self.byte[0]) > i {
                self.hash.read(&mut self.byte);
            }
            let j = usize::from(self.byte[0]);
            out.0[i] = out.0[j];
            out.0[j] = if super::bit_set(&self.signs, i + tau - 256) {
                Elem::new(BaseField::Q - 1)
            } else {
                Elem::new(1)
            };
        }
    }
    pub(crate) fn expand_s_into<K: ArraySize>(
        &mut self,
        rho: &[u8],
        eta: Eta,
        base: usize,
        out: &mut Vector<K>,
    ) {
        for (index, polynomial) in out.0.iter_mut().enumerate() {
            self.bounded_into(rho, eta, Truncate::truncate(base + index), polynomial);
        }
    }

    fn bounded_into(&mut self, rho: &[u8], eta: Eta, nonce: u16, out: &mut Polynomial) {
        // DE/EN: Nonce ist öffentlich / nonce is public; 272-byte consumption unchanged.
        self.hash.start(&[rho, &nonce.to_le_bytes()]);
        self.hash.read(&mut self.bytes);
        let mut index = 0;
        for &byte in &self.bytes {
            append(byte, eta, out, &mut index);
            if index == 256 {
                break;
            }
        }
        while index < 256 {
            self.hash.read(&mut self.byte);
            append(self.byte[0], eta, out, &mut index);
        }
    }
}

fn append(byte: u8, eta: Eta, out: &mut Polynomial, index: &mut usize) {
    let (first, second) = coeffs_from_byte(byte, eta);
    if let Some(value) = first {
        out.0[*index] = value;
        *index += 1;
    }
    if *index < 256 {
        if let Some(value) = second {
            out.0[*index] = value;
            *index += 1;
        }
    }
}

impl Zeroize for SamplingWorkspace {
    fn zeroize(&mut self) {
        self.hash.zeroize();
        self.bytes.zeroize();
        self.byte.zeroize();
        self.signs.zeroize();
    }
}
impl Drop for SamplingWorkspace {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for SamplingWorkspace {}
impl core::fmt::Debug for SamplingWorkspace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SamplingWorkspace").finish_non_exhaustive()
    }
}
