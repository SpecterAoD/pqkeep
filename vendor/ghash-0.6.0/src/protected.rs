//! DE: Bestehende GHASH/POLYVAL-Abbildung ohne private Rückgabe-/Klonpuffer.
//! EN: Existing GHASH/POLYVAL mapping without private return or clone buffers.

use crate::{Block, Key, Tag};
use polyval::ProtectedPolyval;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DE: Gesamten Zustand vor privater Befüllung sperren.
/// EN: Prelock the complete state before private population.
#[derive(Default)]
pub struct ProtectedGHash {
    state: ProtectedPolyval,
}

impl ProtectedGHash {
    /// DE/EN: Schlüssel direkt im gesperrten Zustand initialisieren / initialize in locked state.
    pub fn initialize(&mut self, key: &Key) {
        self.state.initialize_reversed_mulx(key);
    }
    /// DE/EN: Schlüssel behalten, neue Nachricht / retain key, begin a new message.
    pub fn reset(&mut self) {
        self.state.reset();
    }
    /// DE/EN: Geliehener Block, keine private Umkehrkopie / borrowed block without reversal copy.
    pub fn update_block(&mut self, block: &Block) {
        self.state.update_reversed_block(block);
    }
    /// DE/EN: Privates Ausgabeziel vorher sperren / prelock private output.
    pub fn finalize_into(&self, out: &mut Tag) {
        self.state.finalize_reversed_into(out);
    }
}
impl Zeroize for ProtectedGHash {
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}
impl Drop for ProtectedGHash {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for ProtectedGHash {}
impl core::fmt::Debug for ProtectedGHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProtectedGHash").finish_non_exhaustive()
    }
}
