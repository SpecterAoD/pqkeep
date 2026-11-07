//! DE: Öffentliche Schlüsseldatei: Roundtrip, enthält nichts Geheimes, strenger
//! Parser (Magic, Version, AES, Länge, Schlüssel-ID, unbekannte Felder).
//! EN: Public key file: round trip, contains nothing secret, strict parser
//! (magic, version, AES, length, key ID, unknown fields).

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqc_keyforge::Error;
use pqc_keyforge::crypto::{KemAlgorithm, KeyAlgorithm};
use pqc_keyforge::envelope::PublicKeyFile;
use serde_json::{Value, json};

fn valid() -> (Value, pqc_keyforge::envelope::KeyFile) {
    let (file, _) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem1024));
    let json = file.public_part().unwrap().to_json().unwrap();
    (serde_json::from_str(&json).unwrap(), file)
}

fn parse(v: &Value) -> Result<PublicKeyFile, Error> {
    PublicKeyFile::from_json(&serde_json::to_string(v).unwrap())
}

#[test]
fn roundtrip_without_secrets() {
    let (v, key) = valid();
    let public = parse(&v).unwrap();
    assert_eq!(public.key_id(), key.key_id());
    assert_eq!(public.public_key(), key.public_key());
    assert_eq!(public.metadata(), key.metadata());
    // DE: Nur Feldnamen prüfen – im Base64-Text des öffentlichen Schlüssels können
    //     Folgen wie „kdf“ zufällig vorkommen (früher sporadisch fehlschlagend).
    // EN: Check field names only – sequences like "kdf" can occur by chance in the
    //     base64 text of the public key (used to fail sporadically).
    let names = field_names(&v);
    for secret_field in ["kdf", "cipher", "salt", "ciphertext", "nonce"] {
        assert!(!names.iter().any(|n| n == secret_field), "{secret_field}");
    }
}

fn field_names(v: &Value) -> Vec<String> {
    match v {
        Value::Object(map) => map
            .iter()
            .flat_map(|(k, inner)| std::iter::once(k.clone()).chain(field_names(inner)))
            .collect(),
        Value::Array(items) => items.iter().flat_map(field_names).collect(),
        _ => Vec::new(),
    }
}

#[test]
fn strict_parsing() {
    let cases: [(&str, Value, Error); 5] = [
        (
            "magic",
            json!("PQC-KEYFORGE-KEY"),
            Error::InvalidInput { field: "magic" },
        ),
        ("format_version", json!(2), Error::Unsupported),
        ("algorithm", json!("AES-256"), Error::Unsupported),
        (
            "algorithm",
            json!("ML-KEM-768"),
            Error::InvalidInput {
                field: "public_key",
            },
        ),
        (
            "key_id",
            json!("00".repeat(32)),
            Error::InvalidInput { field: "key_id" },
        ),
    ];
    for (key, value, expected) in cases {
        let (mut v, _) = valid();
        v[key] = value;
        assert_eq!(parse(&v).err(), Some(expected), "{key}");
    }
    let (mut v, _) = valid();
    v["kdf"] = json!({});
    assert_eq!(parse(&v).err(), Some(Error::InvalidInput { field: "json" }));
}
