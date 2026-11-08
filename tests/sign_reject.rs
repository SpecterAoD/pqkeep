//! DE: Strenges Einlesen von `.pqsig` und falsche Schlüsseltypen: klare Fehler, nie Panik.
//! EN: Strict parsing of `.pqsig` and wrong key types: clear errors, never a panic.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::Error;
use pqkeep::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqkeep::sign::{self, MAX_SIG_FILE_BYTES, SignatureFile};
use serde_json::Value;

const ML_DSA_87: KeyAlgorithm = KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87);

fn valid_json() -> Value {
    let (file, pass) = common::key_file(ML_DSA_87);
    let key = file.unlock(pass.as_ref()).unwrap();
    let sig = sign::sign_reader(&key, &b"daten"[..]).unwrap();
    serde_json::from_str(&sig.to_json().unwrap()).unwrap()
}

fn parse_with(field: &str, value: Value) -> Result<SignatureFile, Error> {
    let mut json = valid_json();
    json[field] = value;
    SignatureFile::from_json(&json.to_string())
}

fn invalid(field: &'static str) -> Result<SignatureFile, Error> {
    Err(Error::InvalidInput { field })
}

#[test]
fn other_key_types_cannot_sign() {
    for algorithm in [
        KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa65),
        KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa44),
        KeyAlgorithm::Kem(KemAlgorithm::MlKem1024),
        KeyAlgorithm::Aes256,
    ] {
        let (file, pass) = common::key_file(algorithm);
        let key = file.unlock(pass.as_ref()).unwrap();
        let result = sign::sign_reader(&key, &b"x"[..]);
        assert_eq!(result.err(), Some(Error::Unsupported), "{algorithm:?}");
    }
}

#[test]
fn other_public_key_types_cannot_verify() {
    let (file, pass) = common::key_file(ML_DSA_87);
    let sig = sign::sign_reader(&file.unlock(pass.as_ref()).unwrap(), &b"x"[..]).unwrap();
    for algorithm in [
        KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa65),
        KeyAlgorithm::Kem(KemAlgorithm::MlKem1024),
    ] {
        let public = common::key_file(algorithm).0.public_part().unwrap();
        let result = sign::verify_reader(&public, &sig, &b"x"[..]);
        assert_eq!(result, Err(Error::Unsupported), "{algorithm:?}");
    }
}

#[test]
fn fixed_fields_are_enforced() {
    assert_eq!(
        parse_with("magic", Value::from("PQKEEP-PUB")),
        invalid("magic")
    );
    assert_eq!(
        parse_with("context", Value::from("PQKeep/sig/v2")),
        invalid("context")
    );
    for (field, value) in [
        ("format_version", Value::from(0)),
        ("format_version", Value::from(2)),
        ("algorithm", Value::from("ML-DSA-65")),
        ("algorithm", Value::from("ml-dsa-87")),
        ("hash_algorithm", Value::from("SHA3-256")),
    ] {
        assert_eq!(parse_with(field, value), Err(Error::Unsupported), "{field}");
    }
}

#[test]
fn encodings_are_strict() {
    let key_id = valid_json()["key_id"].as_str().unwrap().to_uppercase();
    assert_eq!(parse_with("key_id", Value::from(key_id)), invalid("key_id"));
    assert_eq!(parse_with("key_id", Value::from("00")), invalid("key_id"));
    assert_eq!(
        parse_with("file_sha3_512", Value::from("ab")),
        invalid("file_sha3_512")
    );
    assert_eq!(
        parse_with("signature", Value::from("AAAA")),
        invalid("signature")
    );
    let long = "A".repeat(7000);
    assert_eq!(
        parse_with("signature", Value::from(long)),
        invalid("signature")
    );
    assert_eq!(
        parse_with("signature", Value::from("@@@@")),
        invalid("signature")
    );
    for bad in [
        "2026-11-08 12:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-11-08T12:00:00+01:00",
    ] {
        assert_eq!(
            parse_with("created_utc", Value::from(bad)),
            invalid("created_utc")
        );
    }
}

#[test]
fn structure_is_strict() {
    let mut json = valid_json();
    json["extra"] = Value::from(1);
    assert_eq!(SignatureFile::from_json(&json.to_string()), invalid("json"));
    let mut json = valid_json();
    json.as_object_mut().unwrap().remove("created_utc");
    assert_eq!(SignatureFile::from_json(&json.to_string()), invalid("json"));
    assert_eq!(parse_with("file_size", Value::from(-1)), invalid("json"));
    assert_eq!(parse_with("file_size", Value::from("5")), invalid("json"));
    assert_eq!(SignatureFile::from_json("kein json"), invalid("json"));
    assert_eq!(SignatureFile::from_json(""), invalid("json"));
}

#[test]
fn oversized_input_is_rejected_before_parsing() {
    let text = format!("{}{}", valid_json(), " ".repeat(MAX_SIG_FILE_BYTES));
    assert_eq!(SignatureFile::from_json(&text), invalid("file"));
}

#[test]
fn missing_files_report_io_errors() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("fehlt.pqsig");
    assert!(matches!(sign::load(&missing), Err(Error::Io(_))));
    let (file, pass) = common::key_file(ML_DSA_87);
    let key = file.unlock(pass.as_ref()).unwrap();
    assert!(matches!(sign::sign_file(&key, &missing), Err(Error::Io(_))));
}
