//! DE: Erster HKDF-Ausgabeblock ohne versteckte Secret-Allokationen/Kopien.
//! EN: First HKDF output block without hidden secret allocations/copies.
use hmac::digest::{Output, OutputSizeUser};

/// Caller-owned keyed state and scratch; allocate and protect before calling.
pub trait InPlaceHmac: OutputSizeUser {
    /// Set the HMAC key without moving state.
    fn rekey(&mut self, key: &[u8]);
    /// Absorb message data.
    fn update(&mut self, data: &[u8]);
    /// Write the tag into caller-owned protected memory.
    fn finalize_into(&mut self, out: &mut Output<Self>);
}

/// RFC 5869 extract and first expand block, equivalent to GenericHkdf for HashLen bytes.
/// DE: PRK, Ausgabe und MAC-Zustand werden vom Aufrufer gesperrt/gelöscht.
/// EN: Caller locks/wipes PRK, output and MAC state. No cloning or returned secret arrays.
pub fn derive_first_block_in_place<M: InPlaceHmac>(
    mac: &mut M,
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    prk: &mut Output<M>,
    out: &mut Output<M>,
) {
    mac.rekey(salt);
    mac.update(ikm);
    mac.finalize_into(prk);
    mac.rekey(prk);
    mac.update(info);
    mac.update(&[1]);
    mac.finalize_into(out);
}
