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
