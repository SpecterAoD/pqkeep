#![allow(clippy::unwrap_used, clippy::expect_used)]

use sha3::{Digest, Sha3_256, Sha3_512};

use super::{COMMIT_LEN, SIGNER_BLOCK_LEN, SIGNER_KEY_LEN, Signer, check_commit, commit, message};
use crate::Error;
use crate::files::format::Reader;

/// DE: Sollwerte unabhängig mit Python `hashlib` berechnet. EN: Expected values computed
/// independently with Python `hashlib`.
#[test]
fn commit_and_message_match_independent_reference() {
    let key: Vec<u8> = (0u8..32).collect();
    assert_eq!(
        hex::encode(commit(&key).unwrap()),
        "7bee0981a894478a670dda184e32374f3c49a0414e14c3ea8c554ed51cd1c16c"
    );
    let msg = message(b"header", &Sha3_512::digest(b"body"), 12_345);
    assert_eq!(msg.len(), 155);
    assert_eq!(
        hex::encode(Sha3_256::digest(&msg)),
        "39aa858644890d44f78d47e7db9cb14bb6da2781d08f0433c0d184765f28b03d"
    );
}

/// DE: Schlüsselbindung: richtiger Schlüssel ok, jeder andere = `Decrypt` (#44, S4).
/// EN: Key commitment: right key ok, any other = `Decrypt` (#44, S4).
#[test]
fn commitment_rejects_another_file_key() {
    let key = [7u8; 32];
    let signer = Signer {
        public_key: vec![1; SIGNER_KEY_LEN],
        commit: commit(&key).unwrap(),
    };
    assert_eq!(check_commit(&signer, &key), Ok(()));
    let mut other = key;
    other[31] ^= 1;
    assert_eq!(check_commit(&signer, &other), Err(Error::Decrypt));
}

#[test]
fn block_roundtrip_and_strict_reading() {
    let signer = Signer {
        public_key: (0..SIGNER_KEY_LEN)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect(),
        commit: [9; COMMIT_LEN],
    };
    let block = signer.encode().unwrap();
    assert_eq!(block.len(), SIGNER_BLOCK_LEN);
    let mut input = block.as_slice();
    let mut r = Reader { inner: &mut input };
    assert_eq!(Signer::read(&mut r).unwrap(), signer);
    // DE: Anderer Algorithmus = nicht unterstützt; zu kurz = ungültig.
    // EN: Other algorithm = unsupported; too short = invalid.
    let mut other = block.clone();
    other[0] = 2;
    let mut input = other.as_slice();
    assert_eq!(
        Signer::read(&mut Reader { inner: &mut input }),
        Err(Error::Unsupported)
    );
    let mut short = &block[..block.len() - 1];
    assert!(Signer::read(&mut Reader { inner: &mut short }).is_err());
    let wrong = Signer {
        public_key: vec![0; SIGNER_KEY_LEN - 1],
        commit: [0; COMMIT_LEN],
    };
    assert!(wrong.encode().is_err());
}
