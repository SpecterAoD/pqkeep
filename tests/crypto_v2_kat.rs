//! DE: Known-Answer-Tests für die v2-Schlüsselableitung (C01, C02 aus `docs/V2_TESTS.md`).
//! C01: vollständige Kette Argon2id (Secret = Faktordatei, AD = Domäne) → HKDF-SHA3-256 bei den
//! echten Mindestparametern gegen `tests/kat/v2_argon2id.json` (erzeugt mit `argon2pure`, siehe
//! `tests/kat/README.md`). C02: eine mit Python `cryptography` 41.0.7 unabhängig erzeugte
//! AES-256-GCM-Hülle öffnet sich mit dem abgeleiteten Schlüssel. Nur öffentliche Testbytes.
//!
//! EN: Known-answer tests for the v2 key derivation (C01, C02 in `docs/V2_TESTS.md`).
//! C01: full chain Argon2id (secret = factor file, AD = domain) → HKDF-SHA3-256 at the real
//! minimum parameters against `tests/kat/v2_argon2id.json` (generated with `argon2pure`, see
//! `tests/kat/README.md`). C02: an AES-256-GCM wrap created independently with Python
//! `cryptography` 41.0.7 opens with the derived key. Public test bytes only.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::Error;
use pqkeep::crypto::factor::Factor;
use pqkeep::crypto::kdf::{self, KdfParams};
use pqkeep::crypto::v2::{self, Domain};
use pqkeep::crypto::{SecretBytes, aead};
use pqkeep::security::Passphrase;
use serde_json::Value;

/// DE: Klartext der Passphrase aus `scripts/v2_argon2_vectors.py` (öffentlicher Testwert).
/// EN: Plain text of the passphrase in `scripts/v2_argon2_vectors.py` (public test value).
const PASSPHRASE: &str = "PQKeep v2 Testvektor – nicht geheim";

// DE: C02 – Hülle für den ersten Fall der Datei (file, mit Faktor): Nonce 200..211,
//     Dateischlüssel 160..191, AAD wie unten. EN: C02 – wrap for the file's first case.
const WRAP_AAD: &[u8] = b"PQKeep/file/v2\0aad/wrap\0Testvektor C02";
const WRAP_CIPHERTEXT: &str = "c82d05713a6d7fe68531274755c61ca484073dc63762e36edbf312468128c0bf\
                               5d8fed4efa8672cb149e1112db40da7c";

struct Vectors {
    doc: Value,
}

impl Vectors {
    fn load() -> Self {
        let path = format!("{}/tests/kat/v2_argon2id.json", env!("CARGO_MANIFEST_DIR"));
        let doc = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        Self { doc }
    }

    fn bytes(&self, field: &str) -> Vec<u8> {
        hex::decode(self.doc[field].as_str().unwrap()).unwrap()
    }

    fn cases(&self) -> &[Value] {
        self.doc["cases"].as_array().unwrap()
    }
}

fn passphrase(vectors: &Vectors) -> Passphrase {
    let pass = Passphrase::new(PASSPHRASE).unwrap();
    assert_eq!(pass.expose(), vectors.bytes("passphrase_hex"));
    pass
}

fn number(case: &Value, field: &str) -> u32 {
    u32::try_from(case[field].as_u64().unwrap()).unwrap()
}

fn derive(vectors: &Vectors, case: &Value) -> SecretBytes {
    let domain = match case["domain"].as_str().unwrap() {
        "file" => Domain::File,
        "key" => Domain::Key,
        other => unreachable!("unbekannt / unknown: {other}"),
    };
    let factor = Factor::from_bytes(&vectors.bytes("factor_hex")).unwrap();
    let factor = (number(case, "factor") == 1).then_some(&factor);
    let params = KdfParams {
        memory_kib: number(case, "memory_kib"),
        iterations: number(case, "iterations"),
        parallelism: number(case, "parallelism"),
    };
    let salt = vectors.bytes("salt_hex");
    v2::passphrase_kek(domain, &passphrase(vectors), factor, &salt, &params).unwrap()
}

#[test]
fn c01_argon2id_with_secret_and_domain() {
    let vectors = Vectors::load();
    assert_eq!(vectors.cases().len(), 3);
    for case in vectors.cases() {
        assert_eq!(number(case, "memory_kib"), kdf::MIN_MEMORY_KIB);
        let key = derive(&vectors, case);
        assert_eq!(
            hex::encode(key.expose()),
            case["hkdf_hex"].as_str().unwrap(),
            "{case}"
        );
    }
}

#[test]
fn c02_independent_wrap_opens() {
    let vectors = Vectors::load();
    let key = derive(&vectors, &vectors.cases()[0]);
    let nonce: Vec<u8> = (200..212).collect();
    let file_key: Vec<u8> = (160..192).collect();
    let ciphertext = hex::decode(WRAP_CIPHERTEXT).unwrap();
    let opened = aead::open(key.expose(), &nonce, &ciphertext, WRAP_AAD).unwrap();
    assert_eq!(opened.expose(), file_key);

    // DE: Andere AAD oder der Schlüssel ohne Faktor öffnen nicht.
    // EN: A different AAD or the key without factor do not open.
    let other_aad = aead::open(key.expose(), &nonce, &ciphertext, b"PQKeep/key/v2\0");
    assert_eq!(other_aad.err(), Some(Error::Decrypt));
    let without_factor = derive(&vectors, &vectors.cases()[1]);
    let wrong_key = aead::open(without_factor.expose(), &nonce, &ciphertext, WRAP_AAD);
    assert_eq!(wrong_key.err(), Some(Error::Decrypt));
}

#[test]
fn bounds_are_checked_before_deriving() {
    let pass = Passphrase::new(PASSPHRASE).unwrap();
    let good = KdfParams {
        memory_kib: kdf::MIN_MEMORY_KIB,
        iterations: kdf::MIN_ITERATIONS,
        parallelism: 1,
    };
    let weak = KdfParams {
        memory_kib: kdf::MIN_MEMORY_KIB - 1,
        ..good
    };
    let huge = KdfParams {
        memory_kib: kdf::MAX_MEMORY_KIB + 1,
        ..good
    };
    for params in [weak, huge] {
        let result = v2::passphrase_kek(Domain::File, &pass, None, &[7; 32], &params);
        assert_eq!(result.err(), Some(Error::KdfParams));
    }
    for salt_len in [0, kdf::MIN_SALT_LEN - 1, kdf::MAX_SALT_LEN + 1] {
        let result = v2::passphrase_kek(Domain::Key, &pass, None, &vec![7; salt_len], &good);
        assert_eq!(result.err(), Some(Error::InvalidInput { field: "salt" }));
    }
}
