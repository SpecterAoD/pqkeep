//! DE: Streaming-AEAD: Klartext verschlüsseln, ein Byte (oder die Länge) gezielt verändern, dann
//!     entschlüsseln. Unverändert muss der Klartext zurückkommen, verändert muss es scheitern.
//! EN: Streaming AEAD: encrypt plaintext, change one byte (or the length), then decrypt.
//!     Unchanged must return the plaintext, changed must fail.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqkeep::crypto::stream::{PREFIX_LEN, decrypt, encrypt};

const KEY: [u8; 32] = [7; 32];
const PREFIX: [u8; PREFIX_LEN] = [1; PREFIX_LEN];

fuzz_target!(|input: (Vec<u8>, u32, u8, bool)| {
    let (plain, pos, flip, truncate) = input;
    let mut sealed = Vec::new();
    encrypt(&KEY, PREFIX, b"aad", &mut plain.as_slice(), &mut sealed).expect("encrypt");
    let idx = pos as usize % sealed.len().max(1);
    let changed = if truncate {
        sealed.truncate(idx);
        true
    } else if flip != 0 && !sealed.is_empty() {
        sealed[idx] ^= flip;
        true
    } else {
        false
    };
    let mut out = Vec::new();
    let result = decrypt(&KEY, PREFIX, b"aad", &mut sealed.as_slice(), &mut out);
    if changed {
        assert!(
            result.is_err(),
            "Manipulation nicht erkannt / tampering not detected"
        );
    } else {
        assert_eq!(result.expect("decrypt"), plain.len() as u64);
        assert_eq!(out, plain);
    }
});
