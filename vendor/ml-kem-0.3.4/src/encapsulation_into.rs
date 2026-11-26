//! DE: Additiver Ausgabeweg mit geliehenen Caller-Arbeitsflächen.
//! EN: Additive output path borrowing caller-owned workspaces.

use crate::{
    B32,
    array::{Array, sizes::U64},
    kem::{Ciphertext, Encapsulate},
};

/// DE: Vollständige G-Ausgabe K || r; der Caller schützt und löscht alle 64 Byte.
/// EN: Full G output K || r; the caller protects and wipes all 64 bytes.
pub type EncapsulationWorkspace = Array<u8, U64>;

/// DE: Kapselung ohne privaten SharedKey-Rückgabewert.
/// EN: Encapsulation without returning a private SharedKey by value.
pub trait EncapsulateInto: Encapsulate {
    /// DE: Leitet direkt in workspace ab und liefert ausschließlich das Chiffrat.
    /// EN: Derive directly into workspace and return only public ciphertext.
    ///
    /// # Warning
    /// DE: m muss für jeden Aufruf frisch und gleichverteilt vom OS-CSPRNG sein.
    /// Der Caller muss m/workspace vor Befüllung sperren und danach löschen.
    /// EN: m must be fresh uniform OS-CSPRNG output for every call. The caller
    /// must lock m/workspace before population and wipe afterwards. This API
    /// does not protect internal hash/PKE/compiler scratch or arbitrary callers.
    fn encapsulate_into(
        &self,
        m: &B32,
        workspace: &mut EncapsulationWorkspace,
    ) -> Ciphertext<Self::Kem>;
}

/// DE: Zusätzlicher Einstieg mit geliehenem Hashzustand statt privater Wertübertragung.
/// EN: Additional entry borrowing hash state instead of transferring private state by value.
pub trait EncapsulateWithHash: EncapsulateInto {
    /// DE: Caller sperrt m, workspace und hash vor Befüllung; hash wird zurückgesetzt.
    /// EN: Caller prelocks m, workspace and hash; hash is reset before and after use.
    /// DE: Interne Keccak-/PKE-Arbeitsflächen sind hierdurch nicht automatisch geschützt.
    /// EN: This does not automatically protect internal Keccak/PKE scratch storage.
    fn encapsulate_with_hash(
        &self,
        m: &B32,
        workspace: &mut EncapsulationWorkspace,
        hash: &mut sha3::Sha3_512,
    ) -> Ciphertext<Self::Kem>;
}
