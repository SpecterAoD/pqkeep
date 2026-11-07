//! DE: Ablehnung fehlerhafter Container (ohne Passphrase, beim Einlesen):
//! unbekannte/fehlende Felder, Magic, Version, Algorithmus, Base64, Längen, Größe,
//! KDF-Grenzen, Schlüssel-ID. Nie eine Panik.
//! EN: Rejection of malformed containers (without passphrase, when parsing):
//! unknown/missing fields, magic, version, algorithm, Base64, lengths, size,
//! KDF bounds, key ID. Never a panic.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::unnecessary_wraps)]

mod common;

use pqkeep::Error;
use pqkeep::crypto::KeyAlgorithm;
use pqkeep::envelope::{KeyFile, MAX_FILE_BYTES};
use serde_json::{Value, json};

fn valid() -> Value {
    let (file, _) = common::key_file(KeyAlgorithm::Kem(pqkeep::crypto::KemAlgorithm::default()));
    serde_json::from_str(&file.to_json().unwrap()).unwrap()
}

fn parse(v: &Value) -> Result<KeyFile, Error> {
    KeyFile::from_json(&serde_json::to_string(v).unwrap())
}

fn invalid(field: &'static str) -> Option<Error> {
    Some(Error::InvalidInput { field })
}

#[test]
fn baseline_is_valid() {
    assert!(parse(&valid()).is_ok());
}

#[test]
fn unknown_and_missing_fields() {
    let mut v = valid();
    v["extra"] = json!(1);
    assert_eq!(parse(&v).err(), invalid("json"));
    let mut v = valid();
    v["kdf"]["extra"] = json!("x");
    assert_eq!(parse(&v).err(), invalid("json"));
    let mut v = valid();
    v.as_object_mut().unwrap().remove("public_key");
    assert_eq!(parse(&v).err(), invalid("json"));
    let mut v = valid();
    v["metadata"].as_object_mut().unwrap().remove("name");
    assert_eq!(parse(&v).err(), invalid("json"));
}

#[test]
fn identifiers_and_version() {
    let cases: [(&str, &str, Value, Option<Error>); 6] = [
        ("magic", "", json!("OTHER"), invalid("magic")),
        ("format_version", "", json!(0), Some(Error::Unsupported)),
        ("format_version", "", json!(2), Some(Error::Unsupported)),
        ("algorithm", "", json!("RSA-4096"), Some(Error::Unsupported)),
        (
            "kdf",
            "algorithm",
            json!("scrypt"),
            Some(Error::Unsupported),
        ),
        (
            "cipher",
            "algorithm",
            json!("chacha20"),
            Some(Error::Unsupported),
        ),
    ];
    for (outer, inner, value, expected) in cases {
        let mut v = valid();
        if inner.is_empty() {
            v[outer] = value;
        } else {
            v[outer][inner] = value;
        }
        assert_eq!(parse(&v).err(), expected, "{outer}.{inner}");
    }
}

#[test]
fn wrong_types_and_overflow() {
    for (key, value) in [
        ("format_version", json!("1")),
        ("format_version", json!(-1)),
        ("format_version", json!(4_294_967_296_u64)),
        ("public_key", json!(5)),
        ("metadata", json!("x")),
    ] {
        let mut v = valid();
        v[key] = value;
        assert_eq!(parse(&v).err(), invalid("json"), "{key}");
    }
}

#[test]
fn base64_must_be_strict() {
    // DE: Salt (32 Byte) endet auf „=“; daran lassen sich alle Fälle zeigen.
    // EN: The salt (32 bytes) ends with "="; all cases can be shown with it.
    let v = valid();
    let salt = v["kdf"]["salt"].as_str().unwrap().to_owned();
    assert!(salt.ends_with('='));
    let mut wrong_char = salt.clone();
    wrong_char.replace_range(0..1, "-");
    for bad in [
        format!("{salt}="),
        salt.trim_end_matches('=').to_owned(),
        format!(" {salt}"),
        format!("{salt}\n"),
        wrong_char,
        "####".to_owned(),
    ] {
        let mut v = valid();
        v["kdf"]["salt"] = json!(bad);
        assert_eq!(parse(&v).err(), invalid("salt"), "{bad}");
    }
    // DE: Nicht-kanonisch: gesetzte Füllbits im letzten Zeichen vor „=“.
    // EN: Non-canonical: padding bits set in the last character before "=".
    let mut v = valid();
    v["kdf"]["salt"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=");
    assert_eq!(parse(&v).err(), invalid("salt"));
}

#[test]
fn wrong_binary_lengths() {
    let b64 = |n: usize| <base64ct::Base64 as base64ct::Encoding>::encode_string(&vec![1u8; n]);
    let cases = [
        ("public_key", "", b64(100), "public_key"),
        ("kdf", "salt", b64(8), "salt"),
        ("kdf", "salt", b64(100), "salt"),
        ("cipher", "nonce", b64(16), "nonce"),
        ("cipher", "ciphertext", b64(10), "ciphertext"),
        ("cipher", "ciphertext", b64(1000), "ciphertext"),
    ];
    for (outer, inner, value, field) in cases {
        let mut v = valid();
        if inner.is_empty() {
            v[outer] = json!(value);
        } else {
            v[outer][inner] = json!(value);
        }
        assert_eq!(parse(&v).err(), invalid(field), "{outer}.{inner}");
    }
}

#[test]
fn key_id_checked_without_passphrase() {
    for bad in [
        "00".repeat(32),
        "AB".repeat(32),
        "0".repeat(63),
        "zz".repeat(32),
    ] {
        let mut v = valid();
        v["key_id"] = json!(bad);
        assert_eq!(parse(&v).err(), invalid("key_id"), "{bad}");
    }
}

#[test]
fn kdf_bounds_enforced_on_read() {
    for (key, value) in [
        ("memory_kib", 1024),
        ("memory_kib", u32::MAX),
        ("iterations", 1),
        ("iterations", 100),
        ("parallelism", 0),
        ("parallelism", 64),
    ] {
        let mut v = valid();
        v["kdf"][key] = json!(value);
        assert_eq!(parse(&v).err(), Some(Error::KdfParams), "{key}={value}");
    }
}

#[test]
fn bad_timestamp_rejected() {
    for bad in [
        "2026-13-01T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-11-06 18:00:00",
        "",
    ] {
        let mut v = valid();
        v["created_utc"] = json!(bad);
        assert_eq!(parse(&v).err(), invalid("created_utc"), "{bad}");
    }
}

#[test]
fn size_limit_and_garbage() {
    let huge = " ".repeat(MAX_FILE_BYTES + 1);
    assert_eq!(KeyFile::from_json(&huge).err(), invalid("file"));
    for garbage in [
        "",
        "{",
        "null",
        "[]",
        "\"x\"",
        "{\"magic\":1}",
        "\u{feff}{}",
    ] {
        assert_eq!(
            KeyFile::from_json(garbage).err(),
            invalid("json"),
            "{garbage}"
        );
    }
}

#[test]
fn duplicate_keys_rejected() {
    let text = serde_json::to_string(&valid()).unwrap();
    let dup = text.replacen('{', "{\"magic\":\"PQKEEP-KEY\",", 1);
    assert_eq!(KeyFile::from_json(&dup).err(), invalid("json"));
}
