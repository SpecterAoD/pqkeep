//! DE: Known-Answer-Tests mit NIST-ACVP-Vektoren (siehe tests/kat/README.md).
//! EN: Known-answer tests with NIST ACVP vectors (see tests/kat/README.md).

// DE: unwrap in Hilfsfunktionen erlaubt. EN: unwrap allowed in helper functions.
#![allow(clippy::unwrap_used)]

use pqc_keyforge::crypto::{DsaAlgorithm, KemAlgorithm, dsa, kem};
use serde_json::Value;

fn cases(file: &str) -> Vec<Value> {
    let path = format!("{}/tests/kat/{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(path).unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    let list = doc["cases"].as_array().unwrap().clone();
    assert!(!list.is_empty(), "keine Testfälle / no test cases: {file}");
    list
}

fn bytes(case: &Value, field: &str) -> Vec<u8> {
    hex::decode(case[field].as_str().unwrap()).unwrap()
}

fn kem_alg(name: &str) -> KemAlgorithm {
    match name {
        "ML-KEM-512" => KemAlgorithm::MlKem512,
        "ML-KEM-768" => KemAlgorithm::MlKem768,
        "ML-KEM-1024" => KemAlgorithm::MlKem1024,
        other => unreachable!("unbekannt / unknown: {other}"),
    }
}

fn dsa_alg(name: &str) -> DsaAlgorithm {
    match name {
        "ML-DSA-44" => DsaAlgorithm::MlDsa44,
        "ML-DSA-65" => DsaAlgorithm::MlDsa65,
        "ML-DSA-87" => DsaAlgorithm::MlDsa87,
        other => unreachable!("unbekannt / unknown: {other}"),
    }
}

#[test]
fn ml_kem_keygen_vectors() {
    let list = cases("ml_kem_keygen.json");
    for case in &list {
        let alg = kem_alg(case["parameterSet"].as_str().unwrap());
        let kp = kem::from_seed(alg, &bytes(case, "seed")).unwrap();
        assert_eq!(kp.public_key, bytes(case, "ek"), "tcId {}", case["tcId"]);
    }
    assert_eq!(list.len(), 12);
}

#[test]
fn ml_dsa_keygen_vectors() {
    let list = cases("ml_dsa_keygen.json");
    for case in &list {
        let alg = dsa_alg(case["parameterSet"].as_str().unwrap());
        let kp = dsa::from_seed(alg, &bytes(case, "seed")).unwrap();
        assert_eq!(kp.public_key, bytes(case, "pk"), "tcId {}", case["tcId"]);
    }
    assert_eq!(list.len(), 12);
}

#[test]
fn ml_dsa_sigver_vectors() {
    let list = cases("ml_dsa_sigver.json");
    let mut passed = 0;
    for case in &list {
        let alg = dsa_alg(case["parameterSet"].as_str().unwrap());
        let expected = case["testPassed"].as_bool().unwrap();
        let ok = dsa::verify(
            alg,
            &bytes(case, "pk"),
            &bytes(case, "message"),
            &bytes(case, "context"),
            &bytes(case, "signature"),
        );
        assert_eq!(ok, expected, "tcId {} ({})", case["tcId"], case["reason"]);
        passed += usize::from(expected);
    }
    // DE: Sowohl gültige als auch ungültige Fälle müssen vorkommen.
    // EN: Both valid and invalid cases must be present.
    assert!(passed > 0 && passed < list.len());
}

/// DE: Argon2id über die öffentliche `derive()` mit unseren Mindestparametern.
/// Referenzwerte aus der C-Referenzimplementierung der Argon2-Autoren
/// (argon2-cffi 25.1.0 / argon2-cffi-bindings 26.1.0), siehe tests/kat/README.md.
/// EN: Argon2id via the public `derive()` with our minimum parameters.
/// Reference values from the Argon2 authors' C reference implementation
/// (argon2-cffi 25.1.0 / argon2-cffi-bindings 26.1.0), see tests/kat/README.md.
#[test]
fn argon2id_reference_vectors_via_public_api() {
    use pqc_keyforge::crypto::kdf::{self, KdfParams};
    let cases = [
        (
            1,
            "da7f5946ce245087b21ce1e42135edbea81e4f3e8c5bec552a929fb10cd5ceb0",
        ),
        (
            4,
            "6904f1422410f8360c6538300210a2868f5e80cd88606ec7d6e7e93b49983cea",
        ),
    ];
    for (parallelism, expected) in cases {
        let params = KdfParams {
            memory_kib: kdf::MIN_MEMORY_KIB,
            iterations: kdf::MIN_ITERATIONS,
            parallelism,
        };
        let key = kdf::derive(&[0x01; 32], &[0x02; 32], &params).unwrap();
        assert_eq!(hex::encode(key.expose()), expected, "p = {parallelism}");
    }
}

/// DE: ML-KEM-Entkapselung mit Seed (Wycheproof, C2SP): gültige Fälle aus FIPS 203,
/// alle Fälle zur impliziten Ablehnung (manipuliertes Chiffrat → exaktes Ersatz-
/// Geheimnis) sowie ungültige Längen, die einen Fehler liefern müssen.
/// EN: ML-KEM decapsulation from seed (Wycheproof, C2SP): valid cases from FIPS 203,
/// all implicit-rejection cases (tampered ciphertext → exact substitute secret)
/// and invalid lengths that must yield an error.
#[test]
fn ml_kem_decaps_wycheproof_vectors() {
    let list = cases("ml_kem_decaps_wycheproof.json");
    let (mut valid, mut invalid, mut rejection) = (0, 0, 0);
    for case in &list {
        let id = format!("tcId {} ({})", case["tcId"], case["comment"]);
        let alg = kem_alg(case["parameterSet"].as_str().unwrap());
        let seed = bytes(case, "seed");
        let ct = bytes(case, "c");
        let result = kem::from_seed(alg, &seed)
            .and_then(|kp| kem::decapsulate(alg, kp.seed().expose(), &ct).map(|k| (kp, k)));
        if case["result"] == "invalid" {
            assert!(result.is_err(), "{id}");
            invalid += 1;
            continue;
        }
        let (kp, shared) = result.unwrap();
        let ek = bytes(case, "ek");
        if !ek.is_empty() {
            assert_eq!(kp.public_key, ek, "{id}");
        }
        assert_eq!(shared.expose(), bytes(case, "K").as_slice(), "{id}");
        valid += 1;
        let flags = case["flags"].as_array().unwrap();
        rejection += usize::from(flags.iter().any(|f| f == "MalleableCiphertext"));
    }
    assert!(valid > 0 && invalid > 0 && rejection > 0);
    assert_eq!(valid + invalid, list.len());
}
