//! DE: Gemeinsame Bausteine der Header-v2-Tests – dieselben Werte wie `pslot()`/`rslot()` in
//! `scripts/test_v2_spec.py`. EN: Shared pieces of the header v2 tests – same values as there.

use pqkeep::crypto::KemAlgorithm;
use pqkeep::crypto::kdf::KdfParams;
use pqkeep::files::Content;
use pqkeep::files::format_v2::{HeaderV2, Slot};

pub const KEMS: [(KemAlgorithm, usize); 3] = [
    (KemAlgorithm::MlKem512, 768),
    (KemAlgorithm::MlKem768, 1088),
    (KemAlgorithm::MlKem1024, 1568),
];

/// DE: Nonce 0..11. EN: Nonce 0..11.
pub fn nonce() -> [u8; 12] {
    core::array::from_fn(|i| u8::try_from(i).unwrap())
}

/// DE: Salt 32..63. EN: Salt 32..63.
pub fn salt() -> Vec<u8> {
    (32..64).collect()
}

pub fn pslot(factor: bool) -> Slot {
    Slot::Passphrase {
        factor,
        params: KdfParams {
            memory_kib: 65536,
            iterations: 3,
            parallelism: 1,
        },
        salt: salt(),
        nonce: nonce(),
    }
}

/// DE: Empfänger mit ID `first, 0, 0, …` und Null-Chiffrat. EN: Recipient with ID `first, 0, …`.
pub fn rslot(first: u8, kem: usize) -> Slot {
    let mut recipient_id = [0u8; 32];
    recipient_id[0] = first;
    Slot::Recipient {
        algorithm: KEMS[kem].0,
        recipient_id,
        kem_ciphertext: vec![0; KEMS[kem].1],
        nonce: nonce(),
    }
}

/// DE: Header mit Hülle `i` = 48 × Byte `i`. EN: Header with wrap `i` = 48 × byte `i`.
pub fn header(content: Content, prefix: [u8; 7], slots: Vec<Slot>) -> HeaderV2 {
    let wraps = (0..slots.len())
        .map(|i| [u8::try_from(i).unwrap(); 48])
        .collect();
    HeaderV2 {
        content,
        prefix,
        slots,
        wraps,
    }
}

/// DE: Der Vier-Zugänge-Header aus `test_V02_shared_digests`. EN: The four-slot header from there.
pub fn mixed() -> HeaderV2 {
    let slots = vec![pslot(true), rslot(1, 0), rslot(2, 1), rslot(3, 2)];
    header(Content::Directory, [0, 1, 2, 3, 4, 5, 6], slots)
}
