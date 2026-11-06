//! DE: Roundtrip aller Algorithmen: erzeugen → JSON → einlesen → entsperren →
//! Schlüssel funktioniert. EN: Round trip for all algorithms: generate → JSON →
//! parse → unlock → key works.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqc_keyforge::Error;
use pqc_keyforge::crypto::{ALL_ALGORITHMS, KeyAlgorithm, aead, dsa, kem};
use pqc_keyforge::envelope::{self, KeyFile, Metadata};

fn check_key_works(unlocked: &envelope::UnlockedKey) {
    let secret = unlocked.secret().expose();
    match unlocked.algorithm {
        KeyAlgorithm::Kem(a) => {
            let enc = kem::encapsulate(a, &unlocked.public_key).unwrap();
            let shared = kem::decapsulate(a, secret, &enc.ciphertext).unwrap();
            assert_eq!(shared.expose(), enc.shared_secret.expose());
        }
        KeyAlgorithm::Dsa(a) => {
            let sig = dsa::sign(a, secret, b"msg", b"").unwrap();
            assert!(dsa::verify(a, &unlocked.public_key, b"msg", b"", &sig));
        }
        KeyAlgorithm::Aes256 => {
            let sealed = aead::seal(secret, b"msg", b"").unwrap();
            let opened = aead::open(secret, &sealed.nonce, &sealed.ciphertext, b"").unwrap();
            assert_eq!(opened.expose(), b"msg");
        }
    }
}

#[test]
fn all_algorithms_roundtrip() {
    for alg in ALL_ALGORITHMS {
        let (file, pass) = common::key_file(alg);
        let json = file.to_json().unwrap();
        let parsed = KeyFile::from_json(&json).unwrap();
        assert_eq!(parsed, file, "{alg:?}");
        assert_eq!(parsed.to_json().unwrap(), json, "stabil / stable");
        let unlocked = parsed.unlock(pass.as_ref()).unwrap();
        assert_eq!(unlocked.algorithm, alg);
        assert_eq!(unlocked.secret().len(), alg.secret_len());
        assert_eq!(unlocked.public_key.len(), alg.public_key_len());
        check_key_works(&unlocked);
    }
}

#[test]
fn json_contains_expected_fields_and_no_secret() {
    let (file, _pass) = common::key_file(KeyAlgorithm::Kem(
        pqc_keyforge::crypto::KemAlgorithm::default(),
    ));
    let json = file.to_json().unwrap();
    for key in [
        "\"magic\": \"PQC-KEYFORGE-KEY\"",
        "\"format_version\": 1",
        "\"algorithm\": \"ML-KEM-768\"",
        "\"argon2id\"",
        "\"aes-256-gcm\"",
        "\"name\": \"Test User\"",
    ] {
        assert!(json.contains(key), "{key}");
    }
    assert!(
        !json.contains("\"company\""),
        "leere Felder fehlen / empty fields omitted"
    );
    assert_eq!(file.key_id_hex().len(), 64);
}

#[test]
fn asymmetric_key_id_is_sha3_of_public_key() {
    use sha3::{Digest, Sha3_256};
    let (file, _) = common::key_file(KeyAlgorithm::Dsa(
        pqc_keyforge::crypto::DsaAlgorithm::default(),
    ));
    let expected = hex::encode(Sha3_256::digest(file.public_key()));
    assert_eq!(file.key_id_hex(), expected);
}

#[test]
fn aes_key_id_is_random() {
    let (a, _) = common::key_file(KeyAlgorithm::Aes256);
    let (b, _) = common::key_file(KeyAlgorithm::Aes256);
    assert_ne!(a.key_id_hex(), b.key_id_hex());
    assert_eq!(a.public_key(), &[] as &[u8]);
}

#[test]
fn metadata_is_nfc_normalised_on_create() {
    let pass = common::random_passphrase();
    let meta = Metadata::with_name("Jose\u{301}");
    let alg = KeyAlgorithm::Aes256;
    let file = KeyFile::generate(&pass, alg, &meta, &common::min_params()).unwrap();
    assert_eq!(file.metadata().name, "Jos\u{e9}");
}

#[test]
fn create_rejects_mismatched_public_key() {
    let pass = common::random_passphrase();
    let a = kem::generate(pqc_keyforge::crypto::KemAlgorithm::default()).unwrap();
    let b = kem::generate(pqc_keyforge::crypto::KemAlgorithm::default()).unwrap();
    let alg = KeyAlgorithm::Kem(pqc_keyforge::crypto::KemAlgorithm::default());
    let meta = Metadata::with_name("x");
    let err = KeyFile::create(
        &pass,
        alg,
        a.seed().expose(),
        &b.public_key,
        &meta,
        &common::min_params(),
    );
    assert_eq!(
        err.err(),
        Some(Error::InvalidInput {
            field: "public_key"
        })
    );
}

#[test]
fn created_timestamp_is_rfc3339_now() {
    let (file, _) = common::key_file(KeyAlgorithm::Aes256);
    let created = envelope::time::parse_rfc3339(file.created_utc()).unwrap();
    let now = envelope::time::parse_rfc3339(&envelope::time::now_rfc3339()).unwrap();
    assert!((now - created).abs() < 120);
}
