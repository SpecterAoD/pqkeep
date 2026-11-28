//! DE: Ursprüngliches ExpandA mit vorab gesperrtem SHAKE128-/Sampler-Scratch.
//! EN: Original ExpandA with prelocked SHAKE128/sampling scratch.

use super::coeff_from_three_bytes_ref;
use crate::algebra::{NttMatrix, NttPolynomial};
use module_lattice::{ArraySize, Truncate};
use shake::{
    Shake128, Shake128Reader,
    digest::{Reset, Update, XofReader},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) struct MatrixWorkspace {
    hash: Shake128,
    reader: Shake128Reader,
    bytes: [[u8; 3]; 280],
    extra: [u8; 3],
}

impl Default for MatrixWorkspace {
    fn default() -> Self {
        Self {
            hash: Default::default(),
            reader: Default::default(),
            bytes: [[0; 3]; 280],
            extra: [0; 3],
        }
    }
}

impl MatrixWorkspace {
    pub(crate) fn expand<K: ArraySize, L: ArraySize>(
        &mut self,
        rho: &[u8],
        out: &mut NttMatrix<K, L>,
    ) {
        for (r, row) in out.rows_mut().enumerate() {
            for (s, poly) in row.0.iter_mut().enumerate() {
                self.polynomial(rho, Truncate::truncate(r), Truncate::truncate(s), poly);
            }
        }
    }

    fn polynomial(&mut self, rho: &[u8], r: u8, s: u8, out: &mut NttPolynomial) {
        self.hash.reset();
        self.reader.zeroize();
        self.hash.update(rho);
        self.hash.update(&[s]);
        self.hash.update(&[r]);
        self.hash.finalize_reader_into(&mut self.reader);
        self.reader.read(self.bytes.as_flattened_mut());
        let mut index = 0;
        for chunk in &self.bytes {
            if let Some(value) = coeff_from_three_bytes_ref(chunk) {
                out.0[index] = value;
                index += 1;
                if index == 256 {
                    break;
                }
            }
        }
        // DE: Originalen zusätzlichen Rejection-Pfad ohne Parameteränderung behalten.
        // EN: Preserve original extra rejection path without parameter changes.
        while index < 256 {
            self.reader.read(&mut self.extra);
            if let Some(value) = coeff_from_three_bytes_ref(&self.extra) {
                out.0[index] = value;
                index += 1;
            }
        }
    }
}

impl Zeroize for MatrixWorkspace {
    fn zeroize(&mut self) {
        self.hash.zeroize();
        self.reader.zeroize();
        self.bytes.zeroize();
        self.extra.zeroize();
    }
}
impl Drop for MatrixWorkspace {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for MatrixWorkspace {}
