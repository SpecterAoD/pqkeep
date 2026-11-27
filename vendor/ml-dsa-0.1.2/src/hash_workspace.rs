//! DE: Vorab zu sperrender SHAKE-Zustand ohne private Rückgabewerte.
//! EN: Prelock this SHAKE state; private output is always borrowed.

use shake::{
    Shake256, Shake256Reader,
    digest::{Reset, Update, XofReader},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DE: Gesamtes Objekt vor privater Eingabe sperren.
/// EN: Lock the complete object before any private input.
#[derive(Default)]
pub(crate) struct HashWorkspace {
    hash: Shake256,
    reader: Shake256Reader,
}

impl HashWorkspace {
    pub(crate) fn start(&mut self, inputs: &[&[u8]]) {
        self.hash.reset();
        self.reader.zeroize();
        for input in inputs {
            self.hash.update(input);
        }
        self.hash.finalize_reader_into(&mut self.reader);
    }

    pub(crate) fn read(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

impl Zeroize for HashWorkspace {
    fn zeroize(&mut self) {
        self.hash.zeroize();
        self.reader.zeroize();
    }
}

impl Drop for HashWorkspace {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for HashWorkspace {}

impl core::fmt::Debug for HashWorkspace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HashWorkspace").finish_non_exhaustive()
    }
}
