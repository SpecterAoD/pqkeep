//! DE: Interne Tests der signierten Nachricht (festes Byte-Muster).
//! EN: Internal tests of the signed message (fixed byte pattern).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

fn sample() -> SignatureFile {
    SignatureFile {
        key_id: (0u8..32).collect(),
        digest: FileDigest {
            sha3_512: [0xab; DIGEST_LEN],
            size: 0x0102_0304_0506_0708,
        },
        created_utc: "2026-11-08T12:00:00Z".to_owned(),
        signature: vec![0; SIGNATURE_LEN],
    }
}

#[test]
fn message_layout_is_fixed() {
    let m = sample().message();
    let mut expected = Vec::new();
    expected.extend_from_slice(&10u64.to_le_bytes());
    expected.extend_from_slice(b"PQKEEP-SIG");
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&9u64.to_le_bytes());
    expected.extend_from_slice(b"ML-DSA-87");
    expected.extend_from_slice(&32u64.to_le_bytes());
    expected.extend((0u8..32).collect::<Vec<_>>());
    expected.extend_from_slice(&8u64.to_le_bytes());
    expected.extend_from_slice(b"SHA3-512");
    expected.extend_from_slice(&64u64.to_le_bytes());
    expected.extend_from_slice(&[0xab; 64]);
    expected.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
    expected.extend_from_slice(&20u64.to_le_bytes());
    expected.extend_from_slice(b"2026-11-08T12:00:00Z");
    assert_eq!(m, expected);
}

#[test]
fn every_field_changes_the_message() {
    let base = sample().message();
    let mut s = sample();
    s.key_id[0] ^= 1;
    assert_ne!(s.message(), base);
    let mut s = sample();
    s.digest.sha3_512[63] ^= 1;
    assert_ne!(s.message(), base);
    let mut s = sample();
    s.digest.size += 1;
    assert_ne!(s.message(), base);
    let mut s = sample();
    s.created_utc = "2026-11-08T12:00:01Z".to_owned();
    assert_ne!(s.message(), base);
}

#[test]
fn json_roundtrip_keeps_all_fields() {
    let s = sample();
    let back = SignatureFile::from_json(&s.to_json().unwrap()).unwrap();
    assert_eq!(back, s);
}
