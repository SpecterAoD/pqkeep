//! DE: Öffentlicher Anfangszustand und feste private Payloads für Host-Sperren.
//! EN: Public initial state and fixed private payloads for host-owned locks.

use crate::{Seed, kem::InvalidKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DE: Retention ohne neue private Heaps; interne Konstruktionsflächen bleiben separat.
/// EN: Retention without new private heaps; internal construction scratch remains separate.
pub trait SeedKeyInPlace: Zeroize + ZeroizeOnDrop + Sized {
    /// DE: Feste, vor Befüllung zu sperrende Arbeitsfläche. EN: Prelock before population.
    type Workspace: Default + ZeroizeOnDrop;
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
    fn initialize_seed_in_place(&mut self, seed: &Seed) -> Result<(), InvalidKey> {
        self.initialize_seed_with_workspace(seed, &mut Self::Workspace::default())
    }

    /// DE: Caller sperrt auch workspace vor Seed-Verarbeitung vollständig.
    /// EN: Caller must also completely prelock workspace before processing the seed.
    ///
    /// # Errors
    /// DE/EN: `InvalidKey` bei fehlendem Seedspeicher / for missing seed storage.
    fn initialize_seed_with_workspace(
        &mut self,
        seed: &Seed,
        workspace: &mut Self::Workspace,
    ) -> Result<(), InvalidKey>;
}
