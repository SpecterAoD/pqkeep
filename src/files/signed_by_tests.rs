//! DE: Tatsächliche Identitäts-Owner und unveränderte Hashbytes prüfen.
//! EN: Check actual identity owners and unchanged hash bytes.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::files::locked_owner_tests::locked;
use sha3::Digest;

#[test]
fn identity_hash_matches_public_reference_and_all_owners_are_locked() {
    let key = b"public synthetic sender identity";
    let signed = SignedBy::from_public_key(key).unwrap();
    let expected = Sha3_256::digest(key);
    let matches_reference = signed.key_id() == expected.as_slice();
    assert!(matches_reference);
    locked(signed.0.get());
    signed.0.get().assert_metadata_locked();
    assert!(crate::hardening::memlock::is_locked(
        signed.key_id().as_ptr().addr()
    ));
    assert!(crate::hardening::memlock::is_locked(
        signed.key_id().as_ptr().addr() + 31
    ));
    assert_eq!(format!("{signed:?}"), "SignedBy([REDACTED])");
}

#[test]
fn duplication_keeps_source_and_locks_an_independent_destination() {
    let signed = SignedBy::from_public_key(b"public reference").unwrap();
    let duplicate = signed.try_duplicate().unwrap();
    assert_eq!(signed, duplicate);
    assert!(!std::ptr::eq(
        signed.key_id().as_ptr(),
        duplicate.key_id().as_ptr()
    ));
    locked(duplicate.0.get());
    duplicate.0.get().assert_metadata_locked();
    drop(signed);
    let matches_reference = duplicate.key_id() == Sha3_256::digest(b"public reference").as_slice();
    assert!(matches_reference);
}

#[test]
fn identity_comparison_checks_every_byte_and_refuses_noncanonical_lengths() {
    let signed = SignedBy::from_key_id(&[0x5a; 32]).unwrap();
    for index in 0..32 {
        let mut changed = [0x5a; 32];
        changed[index] ^= 1;
        assert_ne!(signed, SignedBy::from_key_id(&changed).unwrap());
    }
    for len in [0, 1, 31, 33, 64] {
        assert!(matches!(
            SignedBy::from_key_id(&vec![0; len]),
            Err(Error::InvalidInput { field: "key_id" })
        ));
    }
}
