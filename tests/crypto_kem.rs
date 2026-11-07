//! DE: ML-KEM: Roundtrip, Seed-Ableitung, Längen und Fehlerfälle.
//! EN: ML-KEM: round trip, seed derivation, lengths and error cases.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::Error;
use pqkeep::crypto::KemAlgorithm::{self, MlKem512, MlKem768, MlKem1024};
use pqkeep::crypto::kem;

/// DE: (Algorithmus, Länge öffentl. Schlüssel, Länge Chiffrat) laut FIPS 203.
/// EN: (algorithm, public key length, ciphertext length) per FIPS 203.
const SIZES: [(KemAlgorithm, usize, usize); 3] = [
    (MlKem512, 800, 768),
    (MlKem768, 1184, 1088),
    (MlKem1024, 1568, 1568),
];

#[test]
fn default_is_ml_kem_768() {
    assert_eq!(KemAlgorithm::default(), MlKem768);
}

#[test]
fn roundtrip_all_parameter_sets() {
    for (alg, pk_len, ct_len) in SIZES {
        let kp = kem::generate(alg).unwrap();
        assert_eq!(kp.public_key.len(), pk_len);
        assert_eq!(kp.seed().len(), kem::SEED_LEN);
        let enc = kem::encapsulate(alg, &kp.public_key).unwrap();
        assert_eq!(enc.ciphertext.len(), ct_len);
        let shared = kem::decapsulate(alg, kp.seed().expose(), &enc.ciphertext).unwrap();
        assert_eq!(shared.expose(), enc.shared_secret.expose());
        assert_eq!(shared.len(), 32);
    }
}

#[test]
fn seed_reproduces_public_key() {
    for (alg, _, _) in SIZES {
        let kp = kem::generate(alg).unwrap();
        let again = kem::from_seed(alg, kp.seed().expose()).unwrap();
        assert_eq!(again.public_key, kp.public_key);
    }
}

#[test]
fn generated_keys_differ() {
    let a = kem::generate(MlKem768).unwrap();
    let b = kem::generate(MlKem768).unwrap();
    assert_ne!(a.seed().expose(), b.seed().expose());
    assert_ne!(a.public_key, b.public_key);
}

#[test]
fn tampered_ciphertext_gives_different_secret() {
    // DE: Implizite Ablehnung: kein Fehler, aber ein anderes Geheimnis.
    // EN: Implicit rejection: no error, but a different secret.
    let kp = kem::generate(MlKem768).unwrap();
    let enc = kem::encapsulate(MlKem768, &kp.public_key).unwrap();
    for i in [0, enc.ciphertext.len() / 2, enc.ciphertext.len() - 1] {
        let bad = common::flip(&enc.ciphertext, i);
        let shared = kem::decapsulate(MlKem768, kp.seed().expose(), &bad).unwrap();
        assert_ne!(shared.expose(), enc.shared_secret.expose());
    }
}

#[test]
fn wrong_seed_length_rejected() {
    for len in [0, 32, 63, 65] {
        let seed = vec![7u8; len];
        let err = kem::from_seed(MlKem768, &seed).err();
        assert_eq!(err, Some(Error::InvalidInput { field: "seed" }));
    }
}

#[test]
fn wrong_public_key_length_rejected() {
    let kp = kem::generate(MlKem768).unwrap();
    let short = &kp.public_key[..kp.public_key.len() - 1];
    let err = kem::encapsulate(MlKem768, short).err();
    assert_eq!(
        err,
        Some(Error::InvalidInput {
            field: "public_key"
        })
    );
    // DE: Schlüssel eines anderen Parametersatzes. EN: Key of another parameter set.
    assert!(kem::encapsulate(MlKem1024, &kp.public_key).is_err());
}

#[test]
fn wrong_ciphertext_length_rejected() {
    let kp = kem::generate(MlKem512).unwrap();
    for len in [0, 767, 769] {
        let ct = vec![0u8; len];
        let err = kem::decapsulate(MlKem512, kp.seed().expose(), &ct).err();
        assert_eq!(
            err,
            Some(Error::InvalidInput {
                field: "ciphertext"
            })
        );
    }
}
