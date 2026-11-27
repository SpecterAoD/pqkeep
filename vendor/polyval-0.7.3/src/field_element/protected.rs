//! DE: Private Feldzustände und breite Produkte vollständig vorab sperren.
//! EN: Prelock complete private field states and wide products.

use super::{FieldElement, MultiplicationWorkspace};
use crate::{Block, Key, Tag};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DE: Caller sperrt das gesamte Objekt vor Schlüssel-/Datenverarbeitung.
/// EN: Caller prelocks the entire object before processing keys or data.
#[derive(Default)]
pub struct ProtectedPolyval {
    h: FieldElement,
    accumulator: FieldElement,
    input: FieldElement,
    multiplication: MultiplicationWorkspace,
}

impl ProtectedPolyval {
    /// DE/EN: Direkter POLYVAL-Schlüssel, self vorher sperren / prelock self first.
    pub fn initialize(&mut self, key: &Key) {
        self.reset();
        self.h.0.copy_from_slice(key);
    }

    /// DE: Ursprüngliche GHASH-Transformation reverse/mulX direkt im gesperrten Feld.
    /// EN: Original GHASH reverse/mulX transformation directly in the locked field.
    pub fn initialize_reversed_mulx(&mut self, key: &Key) {
        self.initialize(key);
        self.h.0.reverse();
        self.h.mulx_in_place();
    }

    /// DE/EN: Schlüssel behalten, private Arbeitsflächen löschen / retain key, wipe scratch.
    pub fn reset(&mut self) {
        self.accumulator.zeroize();
        self.input.zeroize();
        self.multiplication.zeroize();
    }

    /// DE/EN: Gesamtes Objekt vor Datenverarbeitung sperren / prelock before input.
    pub fn update_block(&mut self, block: &Block) {
        self.update_ordered(block, false);
    }

    /// DE/EN: Ursprüngliche GHASH-Byteumkehr / original GHASH byte reversal.
    pub fn update_reversed_block(&mut self, block: &Block) {
        self.update_ordered(block, true);
    }

    fn update_ordered(&mut self, block: &Block, reversed: bool) {
        for i in 0..16 {
            let index = if reversed { 15 - i } else { i };
            self.input.0[i] = self.accumulator.0[i] ^ block[index];
        }
        self.multiplication
            .multiply_into(&self.h, &self.input, &mut self.accumulator);
    }

    /// DE: Privates Ausgabeziel vorher sperren. EN: Prelock private output storage.
    pub fn finalize_into(&self, out: &mut Tag) {
        out.copy_from_slice(&self.accumulator.0);
    }

    /// DE: GHASH-Ausgabe direkt ins gesperrte Ziel. EN: GHASH output into prelocked storage.
    pub fn finalize_reversed_into(&self, out: &mut Tag) {
        for (target, source) in out.iter_mut().zip(self.accumulator.0.iter().rev()) {
            *target = *source;
        }
    }
}

impl Zeroize for ProtectedPolyval {
    fn zeroize(&mut self) {
        self.h.zeroize();
        self.reset();
    }
}
impl Drop for ProtectedPolyval {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for ProtectedPolyval {}
impl core::fmt::Debug for ProtectedPolyval {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProtectedPolyval").finish_non_exhaustive()
    }
}
