//! DE: Vollständig geliehene private KEM-Operationsflächen.
//! EN: Entirely borrowed private KEM operation storage.

use crate::{
    B32, EncapsulationWorkspace,
    kem::{Ciphertext, Decapsulate, Encapsulate, InvalidKey},
};
use zeroize::ZeroizeOnDrop;

/// DE: Caller sperrt Entropie, G, Hash und die gesamte PKE-Fläche vor privater Verarbeitung.
/// EN: Caller prelocks entropy, G output, hash and the entire PKE workspace before processing.
pub trait EncapsulateWithWorkspace: Encapsulate {
    /// DE: Feste Inline-Fläche, vor privater Befüllung sperren. EN: Fixed prelocked inline storage.
    type Workspace: Default + ZeroizeOnDrop;

    /// DE: Nur das beabsichtigt öffentliche Chiffrat zurückgeben; keine privaten Rückgabewerte.
    /// EN: Return only intended public ciphertext, never private intermediate values.
    /// DE/EN: Frische gleichverteilte OS-Entropie m erforderlich / fresh uniform OS entropy required.
    ///
    /// # Errors
    /// DE/EN: `InvalidKey` bei ungültiger öffentlicher Ausgabegeometrie / invalid output geometry.
    fn encapsulate_with_workspace(
        &self,
        m: &B32,
        derived: &mut EncapsulationWorkspace,
        hash: &mut sha3::Sha3_512,
        workspace: &mut Self::Workspace,
    ) -> Result<Ciphertext<Self::Kem>, InvalidKey>;
}

/// DE: Auch private Entkapselungskandidaten und Vergleichs-Chiffrat im Caller-Speicher halten.
/// EN: Keep private decapsulation candidates and recomputed ciphertext in caller storage.
pub trait DecapsulateWithWorkspace: Decapsulate {
    /// DE: Feste Inline-Fläche, vor privater Befüllung sperren. EN: Fixed prelocked inline storage.
    type Workspace: Default + ZeroizeOnDrop;

    /// DE: Schlüssel-Payloads, workspace und out müssen vollständig vorab gesperrt sein.
    /// EN: Key payloads, workspace and out must be completely prelocked.
    ///
    /// # Errors
    /// DE/EN: `InvalidKey` bei ungültiger öffentlicher Ausgabegeometrie / invalid output geometry.
    fn decapsulate_with_workspace(
        &self,
        ciphertext: &Ciphertext<Self::Kem>,
        workspace: &mut Self::Workspace,
        out: &mut B32,
    ) -> Result<(), InvalidKey>;
}
