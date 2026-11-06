//! DE: ML-DSA: Signieren/Prüfen, Seed-Ableitung, Längen und Fehlerfälle.
//! EN: ML-DSA: sign/verify, seed derivation, lengths and error cases.

mod common;

use pqc_keyforge::Error;
use pqc_keyforge::crypto::DsaAlgorithm::{self, MlDsa44, MlDsa65, MlDsa87};
use pqc_keyforge::crypto::dsa;

/// DE: (Algorithmus, Länge öffentl. Schlüssel, Länge Signatur) laut FIPS 204.
/// EN: (algorithm, public key length, signature length) per FIPS 204.
const SIZES: [(DsaAlgorithm, usize, usize); 3] = [
    (MlDsa44, 1312, 2420),
    (MlDsa65, 1952, 3309),
    (MlDsa87, 2592, 4627),
];

const MSG: &[u8] = b"PQC KeyForge test message";
const CTX: &[u8] = b"keyforge-test";

#[test]
fn default_is_ml_dsa_65() {
    assert_eq!(DsaAlgorithm::default(), MlDsa65);
}

#[test]
fn sign_verify_all_parameter_sets() {
    for (alg, pk_len, sig_len) in SIZES {
        let kp = dsa::generate(alg).unwrap();
        assert_eq!(kp.public_key.len(), pk_len);
        assert_eq!(kp.seed().len(), dsa::SEED_LEN);
        let sig = dsa::sign(alg, kp.seed().expose(), MSG, CTX).unwrap();
        assert_eq!(sig.len(), sig_len);
        assert!(dsa::verify(alg, &kp.public_key, MSG, CTX, &sig));
    }
}

#[test]
fn seed_reproduces_public_key() {
    for (alg, _, _) in SIZES {
        let kp = dsa::generate(alg).unwrap();
        let again = dsa::from_seed(alg, kp.seed().expose()).unwrap();
        assert_eq!(again.public_key, kp.public_key);
    }
}

#[test]
fn signatures_are_hedged() {
    // DE: Randomisiert: zwei Signaturen derselben Nachricht unterscheiden sich.
    // EN: Randomised: two signatures of the same message differ.
    let kp = dsa::generate(MlDsa65).unwrap();
    let a = dsa::sign(MlDsa65, kp.seed().expose(), MSG, CTX).unwrap();
    let b = dsa::sign(MlDsa65, kp.seed().expose(), MSG, CTX).unwrap();
    assert_ne!(a, b);
    assert!(dsa::verify(MlDsa65, &kp.public_key, MSG, CTX, &b));
}

#[test]
fn tampering_is_detected() {
    let kp = dsa::generate(MlDsa65).unwrap();
    let other = dsa::generate(MlDsa65).unwrap();
    let sig = dsa::sign(MlDsa65, kp.seed().expose(), MSG, CTX).unwrap();
    let pk = &kp.public_key;
    assert!(!dsa::verify(MlDsa65, pk, b"other message", CTX, &sig));
    assert!(!dsa::verify(MlDsa65, pk, MSG, b"other-ctx", &sig));
    assert!(!dsa::verify(MlDsa65, pk, MSG, b"", &sig));
    assert!(!dsa::verify(MlDsa65, &other.public_key, MSG, CTX, &sig));
    for i in [0, sig.len() / 2, sig.len() - 1] {
        assert!(!dsa::verify(MlDsa65, pk, MSG, CTX, &common::flip(&sig, i)));
    }
    assert!(!dsa::verify(MlDsa65, &common::flip(pk, 0), MSG, CTX, &sig));
}

#[test]
fn malformed_inputs_return_false_without_panic() {
    let kp = dsa::generate(MlDsa44).unwrap();
    let sig = dsa::sign(MlDsa44, kp.seed().expose(), MSG, CTX).unwrap();
    let pk = &kp.public_key;
    assert!(!dsa::verify(MlDsa44, pk, MSG, CTX, &sig[..sig.len() - 1]));
    assert!(!dsa::verify(MlDsa44, pk, MSG, CTX, &[]));
    assert!(!dsa::verify(MlDsa44, &pk[..10], MSG, CTX, &sig));
    assert!(!dsa::verify(MlDsa44, pk, MSG, CTX, &vec![0xFF; sig.len()]));
    // DE: Signatur eines anderen Parametersatzes. EN: Signature of another parameter set.
    assert!(!dsa::verify(MlDsa65, pk, MSG, CTX, &sig));
}

#[test]
fn context_length_limit() {
    let kp = dsa::generate(MlDsa44).unwrap();
    let max = vec![1u8; dsa::MAX_CONTEXT_LEN];
    let sig = dsa::sign(MlDsa44, kp.seed().expose(), MSG, &max).unwrap();
    assert!(dsa::verify(MlDsa44, &kp.public_key, MSG, &max, &sig));
    let too_long = vec![1u8; dsa::MAX_CONTEXT_LEN + 1];
    let err = dsa::sign(MlDsa44, kp.seed().expose(), MSG, &too_long).err();
    assert_eq!(err, Some(Error::InvalidInput { field: "context" }));
    assert!(!dsa::verify(MlDsa44, &kp.public_key, MSG, &too_long, &sig));
}

#[test]
fn wrong_seed_length_rejected() {
    for len in [0, 31, 33, 64] {
        let err = dsa::from_seed(MlDsa65, &vec![3u8; len]).err();
        assert_eq!(err, Some(Error::InvalidInput { field: "seed" }));
        assert!(dsa::sign(MlDsa65, &vec![3u8; len], MSG, CTX).is_err());
    }
}
