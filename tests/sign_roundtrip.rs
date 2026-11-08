//! DE: Signieren und Prüfen im Erfolgsfall, SHA3-512-Testvektoren, gestreamte große Daten.
//! EN: Signing and verifying in the success case, SHA3-512 test vectors, large streamed data.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Read;

use pqkeep::crypto::{DsaAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{PublicKeyFile, UnlockedKey};
use pqkeep::sign::{self, SignatureFile, digest_reader};
use sha3::{Digest, Sha3_512};

const ML_DSA_87: KeyAlgorithm = KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87);

fn signer() -> (UnlockedKey, PublicKeyFile) {
    let (file, pass) = common::key_file(ML_DSA_87);
    (
        file.unlock(pass.as_ref()).unwrap(),
        file.public_part().unwrap(),
    )
}

#[test]
fn sha3_512_known_answers() {
    // DE: NIST-Beispielwerte (FIPS 202). EN: NIST example values (FIPS 202).
    let empty = digest_reader(&b""[..]).unwrap();
    assert_eq!(
        hex::encode(empty.sha3_512),
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
         15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    );
    assert_eq!(empty.size, 0);
    let abc = digest_reader(&b"abc"[..]).unwrap();
    assert_eq!(
        hex::encode(abc.sha3_512),
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
         10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    );
}

#[test]
fn streamed_digest_matches_one_shot_across_block_borders() {
    for len in [65_535usize, 65_536, 65_537, 3 * 65_536 + 11] {
        let data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let streamed = digest_reader(&data[..]).unwrap();
        let one_shot: [u8; 64] = Sha3_512::digest(&data).into();
        assert_eq!(streamed.sha3_512, one_shot, "Länge / length {len}");
        assert_eq!(streamed.size, len as u64);
    }
}

#[test]
fn sign_and_verify_in_memory() {
    let (key, public) = signer();
    let data = b"Vertrag / contract v1".to_vec();
    let sig = sign::sign_reader(&key, &data[..]).unwrap();
    assert_eq!(sig.key_id(), public.key_id());
    let ok = sign::verify_reader(&public, &sig, &data[..]).unwrap();
    assert_eq!(ok.key_id, public.key_id());
    assert_eq!(ok.size, data.len() as u64);
    assert_eq!(ok.created_utc, sig.created_utc());
}

#[test]
fn empty_file_can_be_signed() {
    let (key, public) = signer();
    let sig = sign::sign_reader(&key, &b""[..]).unwrap();
    assert_eq!(
        sign::verify_reader(&public, &sig, &b""[..]).unwrap().size,
        0
    );
}

#[test]
fn file_roundtrip_via_json_and_rename() {
    let (key, public) = signer();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bericht.pdf");
    std::fs::write(&path, b"%PDF-1.7 Beispiel").unwrap();
    let sig = sign::sign_file(&key, &path).unwrap();
    let sig_path = dir.path().join(format!("bericht.pdf.{}", sign::EXTENSION));
    std::fs::write(&sig_path, sig.to_json().unwrap()).unwrap();
    let loaded = sign::load(&sig_path).unwrap();
    assert_eq!(loaded, sig);
    // DE: Der Dateiname ist nicht signiert. EN: The file name is not signed.
    let renamed = dir.path().join("umbenannt.pdf");
    std::fs::rename(&path, &renamed).unwrap();
    sign::verify_file(&public, &loaded, &renamed).unwrap();
}

#[test]
fn signatures_are_randomised_but_both_verify() {
    let (key, public) = signer();
    let a = sign::sign_reader(&key, &b"gleich"[..]).unwrap();
    let b = sign::sign_reader(&key, &b"gleich"[..]).unwrap();
    assert_ne!(a.to_json().unwrap(), b.to_json().unwrap());
    sign::verify_reader(&public, &a, &b"gleich"[..]).unwrap();
    sign::verify_reader(&public, &b, &b"gleich"[..]).unwrap();
}

#[test]
fn large_input_is_streamed() {
    // DE: 8 MiB (128 Blöcke) aus einem Generator, nie als Ganzes im Speicher.
    // EN: 8 MiB (128 blocks) from a generator, never held in memory as a whole.
    const LEN: u64 = 8 * 1024 * 1024;
    let (key, public) = signer();
    let source = || std::io::repeat(0x5a).take(LEN);
    let sig = sign::sign_reader(&key, source()).unwrap();
    assert_eq!(sig.digest().size, LEN);
    sign::verify_reader(&public, &sig, source()).unwrap();
}

#[test]
fn json_has_expected_fixed_values() {
    let (key, _) = signer();
    let sig = sign::sign_reader(&key, &b"x"[..]).unwrap();
    let json: serde_json::Value = serde_json::from_str(&sig.to_json().unwrap()).unwrap();
    assert_eq!(json["magic"], "PQKEEP-SIG");
    assert_eq!(json["format_version"], 1);
    assert_eq!(json["algorithm"], "ML-DSA-87");
    assert_eq!(json["hash_algorithm"], "SHA3-512");
    assert_eq!(json["context"], "PQKeep/sig/v1");
    assert_eq!(json["file_size"], 1);
    let back = SignatureFile::from_json(&sig.to_json().unwrap()).unwrap();
    assert_eq!(back, sig);
}
