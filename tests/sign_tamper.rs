//! DE: Manipulationen an Datei, Signatur und signierten Feldern sowie falsche Schlüssel:
//! immer `InvalidSignature`, nie eine Panik.
//! EN: Tampering with file, signature and signed fields, and wrong keys: always
//! `InvalidSignature`, never a panic.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use base64ct::{Base64, Encoding};
use pqkeep::Error;
use pqkeep::crypto::{DsaAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{PublicKeyFile, UnlockedKey};
use pqkeep::sign::{self, SIGNATURE_LEN, SignatureFile};
use serde_json::Value;

const ML_DSA_87: KeyAlgorithm = KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87);
const DATA: &[u8] = b"Kaufvertrag / purchase agreement: 1000 EUR";

struct Fixture {
    public: PublicKeyFile,
    sig: SignatureFile,
}

fn signer() -> (UnlockedKey, PublicKeyFile) {
    let (file, pass) = common::key_file(ML_DSA_87);
    (
        file.unlock(pass.as_ref()).unwrap(),
        file.public_part().unwrap(),
    )
}

fn fixture() -> Fixture {
    let (key, public) = signer();
    let sig = sign::sign_reader(&key, DATA).unwrap();
    Fixture { public, sig }
}

fn verify(f: &Fixture, sig: &SignatureFile, data: &[u8]) -> Result<sign::Verified, Error> {
    sign::verify_reader(&f.public, sig, data)
}

/// DE: Ändert ein JSON-Feld und liest die Signatur neu ein. EN: Changes a JSON field and re-parses.
fn with_field(sig: &SignatureFile, field: &str, value: Value) -> SignatureFile {
    let mut json: Value = serde_json::from_str(&sig.to_json().unwrap()).unwrap();
    json[field] = value;
    SignatureFile::from_json(&json.to_string()).unwrap()
}

#[test]
fn unchanged_input_verifies() {
    let f = fixture();
    verify(&f, &f.sig, DATA).unwrap();
}

#[test]
fn any_change_to_the_file_is_detected() {
    let f = fixture();
    for i in [0, DATA.len() / 2, DATA.len() - 1] {
        assert_eq!(
            verify(&f, &f.sig, &common::flip(DATA, i)),
            Err(Error::InvalidSignature)
        );
    }
    let mut longer = DATA.to_vec();
    longer.push(0);
    assert_eq!(verify(&f, &f.sig, &longer), Err(Error::InvalidSignature));
    let shorter = &DATA[..DATA.len() - 1];
    assert_eq!(verify(&f, &f.sig, shorter), Err(Error::InvalidSignature));
    assert_eq!(verify(&f, &f.sig, b""), Err(Error::InvalidSignature));
}

#[test]
fn flipped_signature_bytes_are_rejected() {
    let f = fixture();
    let json: Value = serde_json::from_str(&f.sig.to_json().unwrap()).unwrap();
    let raw = Base64::decode_vec(json["signature"].as_str().unwrap()).unwrap();
    // DE: Stichprobe über die ganze Signatur inkl. erstem und letztem Byte.
    // EN: Sample across the whole signature incl. first and last byte.
    let positions = (0..SIGNATURE_LEN).step_by(97).chain([SIGNATURE_LEN - 1]);
    for i in positions {
        let tampered = Base64::encode_string(&common::flip(&raw, i));
        let sig = with_field(&f.sig, "signature", Value::from(tampered));
        assert_eq!(
            verify(&f, &sig, DATA),
            Err(Error::InvalidSignature),
            "Byte {i}"
        );
    }
}

#[test]
fn signed_timestamp_cannot_be_changed() {
    let f = fixture();
    let sig = with_field(&f.sig, "created_utc", Value::from("2020-01-01T00:00:00Z"));
    assert_eq!(verify(&f, &sig, DATA), Err(Error::InvalidSignature));
}

#[test]
fn hash_and_size_fields_are_bound() {
    let f = fixture();
    let size = with_field(&f.sig, "file_size", Value::from(DATA.len() + 1));
    assert_eq!(verify(&f, &size, DATA), Err(Error::InvalidSignature));
    let hash = hex::encode([0u8; 64]);
    let digest = with_field(&f.sig, "file_sha3_512", Value::from(hash));
    assert_eq!(verify(&f, &digest, DATA), Err(Error::InvalidSignature));
}

#[test]
fn hash_swapped_to_other_file_with_matching_fields_is_rejected() {
    // DE: Angreifer setzt Hash/Größe einer anderen Datei ein; die Signatur passt nicht mehr.
    // EN: Attacker inserts hash/size of another file; the signature no longer matches.
    let f = fixture();
    let other = b"Kaufvertrag / purchase agreement: 9000 EUR";
    let d = sign::digest_reader(&other[..]).unwrap();
    let swapped = with_field(
        &f.sig,
        "file_sha3_512",
        Value::from(hex::encode(d.sha3_512)),
    );
    assert_eq!(verify(&f, &swapped, other), Err(Error::InvalidSignature));
}

#[test]
fn wrong_public_key_is_rejected() {
    let f = fixture();
    let (_, other_public) = signer();
    let result = sign::verify_reader(&other_public, &f.sig, DATA);
    assert_eq!(result, Err(Error::InvalidSignature));
}

#[test]
fn key_id_swapped_to_other_key_is_rejected() {
    // DE: Schlüssel-ID auf den Prüfschlüssel umgeschrieben → ML-DSA-Prüfung scheitert.
    // EN: Key ID rewritten to the verifying key → ML-DSA verification fails.
    let f = fixture();
    let (_, other_public) = signer();
    let sig = with_field(&f.sig, "key_id", Value::from(other_public.key_id_hex()));
    let result = sign::verify_reader(&other_public, &sig, DATA);
    assert_eq!(result, Err(Error::InvalidSignature));
}
