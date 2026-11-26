//! DE: Öffentlicher Anfangszustand und feste private Payloads für Host-Sperren.
//! EN: Public initial state and fixed private payloads for host-owned locks.

use crate::{Seed, kem::InvalidKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DE: Retention ohne neue private Heaps; interne Konstruktionsflächen bleiben separat.
/// EN: Retention without new private heaps; internal construction scratch remains separate.
pub trait SeedKeyInPlace: Zeroize + ZeroizeOnDrop + Sized {
    /// DE: Nur öffentliche Nullwerte; vor privater Initialisierung Zustand/Payloads sperren.
    /// EN: Only public zero values; lock state/payloads before private initialization.
    #[must_use]
    fn public_state() -> Self;

    /// DE: Genau drei feste Payloads besuchen; bei fehlender Speicherung/Verweigerung false.
    /// EN: Visit exactly three fixed payloads; return false on missing storage or denial.
    /// DE: Adressen sind vertrauliche Geometrie, nicht protokollieren oder behalten.
    /// EN: Addresses are confidential geometry; do not log or retain them separately.
    fn visit_private_storage(&self, visit: impl FnMut(usize, usize) -> bool) -> bool;

    /// DE: Private Payloads ohne Reallokation befüllen; Aufrufer muss vorher voll sperren.
    /// EN: Populate private payloads without reallocating; caller must prelock completely.
    ///
    /// # Errors
    /// DE/EN: `InvalidKey` ohne vorbereiteten Seedspeicher / without prepared seed storage.
    /// DE: Kein Schutzversprechen für interne Hash-/PKE-/Konstruktor-Arbeitsflächen.
    /// EN: Does not promise protected internal hash/PKE/construction scratch.
    fn initialize_seed_in_place(&mut self, seed: &Seed) -> Result<(), InvalidKey>;
}
