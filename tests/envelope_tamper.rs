//! DE: Manipulation gültig aussehender Container: Jedes Header-Feld wird so
//! geändert, dass das Einlesen noch gelingt – dann muss das Entsperren scheitern.
//! EN: Tampering with valid-looking containers: each header field is changed so
//! that parsing still succeeds – unlocking must then fail.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqc_keyforge::Error;
use pqc_keyforge::crypto::{KemAlgorithm, KeyAlgorithm, kem};
use pqc_keyforge::envelope::KeyFile;
use pqc_keyforge::security::StrongPassphrase;
use serde_json::{Value, json};
use sha3::{Digest, Sha3_256};

fn setup(alg: KeyAlgorithm) -> (Value, StrongPassphrase) {
    let (file, pass) = common::key_file(alg);
    (
        serde_json::from_str(&file.to_json().unwrap()).unwrap(),
        pass,
    )
}

fn unlock_err(v: &Value, pass: &StrongPassphrase) -> Option<Error> {
    let file = KeyFile::from_json(&serde_json::to_string(v).unwrap())
        .expect("Einlesen muss gelingen / parsing must succeed");
    file.unlock(pass.as_ref()).err()
}

fn flip_b64(text: &str) -> String {
    use base64ct::{Base64, Encoding};
    let mut bytes = Base64::decode_vec(text).unwrap();
    bytes[0] ^= 1;
    Base64::encode_string(&bytes)
}

#[test]
fn metadata_and_time_are_authenticated() {
    let (base, pass) = setup(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let edits: [(&str, &str, Value); 5] = [
        ("metadata", "name", json!("Mallory")),
        ("metadata", "department", json!("Einkauf")),
        ("metadata", "company", json!("Neu GmbH")),
        ("metadata", "organization", Value::Null),
        ("created_utc", "", json!("2030-01-01T00:00:00Z")),
    ];
    for (outer, inner, value) in edits {
        let mut v = base.clone();
        if inner.is_empty() {
            v[outer] = value;
        } else if value.is_null() {
            v[outer].as_object_mut().unwrap().remove(inner);
        } else {
            v[outer][inner] = value;
        }
        assert_eq!(
            unlock_err(&v, &pass),
            Some(Error::Decrypt),
            "{outer}.{inner}"
        );
    }
}

#[test]
fn swapped_public_key_with_matching_key_id_detected() {
    // DE: Angreifer ersetzt öffentlichen Schlüssel und passt die Schlüssel-ID an.
    // EN: Attacker replaces the public key and adjusts the key ID.
    let (mut v, pass) = setup(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let other = kem::generate(KemAlgorithm::MlKem768).unwrap();
    v["public_key"] = json!(<base64ct::Base64 as base64ct::Encoding>::encode_string(
        &other.public_key
    ));
    v["key_id"] = json!(hex::encode(Sha3_256::digest(&other.public_key)));
    assert_eq!(unlock_err(&v, &pass), Some(Error::Decrypt));
}

#[test]
fn crypto_fields_are_authenticated() {
    let (base, pass) = setup(KeyAlgorithm::Dsa(
        pqc_keyforge::crypto::DsaAlgorithm::default(),
    ));
    for (outer, inner) in [
        ("kdf", "salt"),
        ("cipher", "nonce"),
        ("cipher", "ciphertext"),
    ] {
        let mut v = base.clone();
        v[outer][inner] = json!(flip_b64(v[outer][inner].as_str().unwrap()));
        assert_eq!(
            unlock_err(&v, &pass),
            Some(Error::Decrypt),
            "{outer}.{inner}"
        );
    }
    let mut v = base.clone();
    v["kdf"]["iterations"] = json!(4);
    assert_eq!(unlock_err(&v, &pass), Some(Error::Decrypt), "iterations");
}

#[test]
fn aes_key_id_is_authenticated() {
    let (mut v, pass) = setup(KeyAlgorithm::Aes256);
    v["key_id"] = json!("ab".repeat(32));
    assert_eq!(unlock_err(&v, &pass), Some(Error::Decrypt));
}

#[test]
fn algorithm_swap_rejected() {
    // DE: Anderer Algorithmus → falsche Länge des öffentlichen Schlüssels beim Einlesen.
    // EN: Other algorithm → wrong public key length when parsing.
    let (mut v, _pass) = setup(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    v["algorithm"] = json!("ML-KEM-512");
    let err = KeyFile::from_json(&serde_json::to_string(&v).unwrap()).err();
    assert_eq!(
        err,
        Some(Error::InvalidInput {
            field: "public_key"
        })
    );
}

#[test]
fn wrong_passphrase_fails() {
    let (v, _pass) = setup(KeyAlgorithm::Aes256);
    let other = common::random_passphrase();
    assert_eq!(unlock_err(&v, &other), Some(Error::Decrypt));
}
