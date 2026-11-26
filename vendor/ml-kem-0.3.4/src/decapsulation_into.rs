//! DE: Entkapselung in geliehene Ausgabe ohne privaten SharedKey-Rückgabewert.
//! EN: Decapsulation into borrowed output without a private SharedKey return value.

use crate::{
    B32,
    kem::{Ciphertext, Decapsulate},
};
use core::array::TryFromSliceError;

/// DE: Additiver Ausgabeweg; schützt nicht eigenständig Provider-Konstruktoren/Scratch.
/// EN: Additive output path; does not independently protect provider construction/scratch.
pub trait DecapsulateInto: Decapsulate {
    /// DE: Caller sperrt out vor dem Aufruf und löscht es vor Unlock/Freigabe.
    /// EN: Caller must lock out before entry and wipe it before unlocking/releasing it.
    fn decapsulate_into(&self, ciphertext: &Ciphertext<Self::Kem>, out: &mut B32);

    /// DE: Falsche Länge ablehnen, ohne out zu verändern; implizite Ablehnung erhalten.
    /// EN: Reject an incorrect length without changing out; retain implicit rejection.
    ///
    /// # Errors
    /// DE/EN: `TryFromSliceError` bei falscher Chiffratlänge / on incorrect ciphertext length.
    fn decapsulate_slice_into(
        &self,
        ciphertext: &[u8],
        out: &mut B32,
    ) -> Result<(), TryFromSliceError> {
        let ciphertext = ciphertext.try_into()?;
        self.decapsulate_into(&ciphertext, out);
        Ok(())
    }
}
