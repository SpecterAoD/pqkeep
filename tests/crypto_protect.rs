//! DE: Ganzer Ablauf: Schlüssel erzeugen, schützen, entsperren und mit dem
//! wiederhergestellten Schlüssel arbeiten (Encaps/Decaps, Sign/Verify, AES).
//!
//! EN: Full flow: generate, protect, unlock and use the restored key
//! (encaps/decaps, sign/verify, AES).

mod common;

use pqc_keyforge::Error;
use pqc_keyforge::crypto::protect::{self, AAD_DOMAIN};
use pqc_keyforge::crypto::{
    ALL_ALGORITHMS, DsaAlgorithm, KemAlgorithm, KeyAlgorithm, aead, dsa, kem,
};

const META: &[u8] = b"name=Test;org=Example";

#[test]
fn kem_key_survives_protection() {
    let pass = common::random_passphrase();
    let alg = KemAlgorithm::MlKem768;
    let kp = kem::generate(alg).unwrap();
    let p = protect::protect(
        &pass,
        KeyAlgorithm::Kem(alg),
        kp.seed().expose(),
        &common::min_params(),
        META,
    )
    .unwrap();

    let seed = protect::unprotect(pass.as_ref(), &p, META).unwrap();
    assert_eq!(seed.expose(), kp.seed().expose());
    let restored = kem::from_seed(alg, seed.expose()).unwrap();
    assert_eq!(restored.public_key, kp.public_key);

    let enc = kem::encapsulate(alg, &kp.public_key).unwrap();
    let shared = kem::decapsulate(alg, restored.seed().expose(), &enc.ciphertext).unwrap();
    assert_eq!(shared.expose(), enc.shared_secret.expose());
}

#[test]
fn dsa_key_survives_protection() {
    let pass = common::random_passphrase();
    let alg = DsaAlgorithm::MlDsa65;
    let kp = dsa::generate(alg).unwrap();
    let p = protect::protect(
        &pass,
        KeyAlgorithm::Dsa(alg),
        kp.seed().expose(),
        &common::min_params(),
        META,
    )
    .unwrap();

    let seed = protect::unprotect(pass.as_ref(), &p, META).unwrap();
    let sig = dsa::sign(alg, seed.expose(), b"message", b"").unwrap();
    assert!(dsa::verify(alg, &kp.public_key, b"message", b"", &sig));
}

#[test]
fn aes_key_survives_protection() {
    let pass = common::random_passphrase();
    let key = aead::generate_key().unwrap();
    let p = protect::protect(
        &pass,
        KeyAlgorithm::Aes256,
        key.expose(),
        &common::min_params(),
        META,
    )
    .unwrap();
    let restored = protect::unprotect(pass.as_ref(), &p, META).unwrap();
    assert_eq!(restored.expose(), key.expose());
}

#[test]
fn fresh_salt_nonce_and_ciphertext_each_time() {
    let pass = common::random_passphrase();
    let key = aead::generate_key().unwrap();
    let params = common::min_params();
    let a = protect::protect(&pass, KeyAlgorithm::Aes256, key.expose(), &params, META).unwrap();
    let b = protect::protect(&pass, KeyAlgorithm::Aes256, key.expose(), &params, META).unwrap();
    assert_ne!(a.salt, b.salt);
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);
    assert_eq!(a.salt.len(), 32);
}

#[test]
fn secret_length_must_match_algorithm() {
    let pass = common::random_passphrase();
    for alg in ALL_ALGORITHMS {
        let wrong = vec![0u8; alg.secret_len() + 1];
        let err = protect::protect(&pass, alg, &wrong, &common::min_params(), META).err();
        assert_eq!(
            err,
            Some(Error::InvalidInput { field: "secret" }),
            "{alg:?}"
        );
    }
}

#[test]
fn weak_parameters_rejected_on_protect() {
    let pass = common::random_passphrase();
    let key = aead::generate_key().unwrap();
    let mut weak = common::min_params();
    weak.iterations = 1;
    let err = protect::protect(&pass, KeyAlgorithm::Aes256, key.expose(), &weak, META).err();
    assert_eq!(err, Some(Error::KdfParams));
}

#[test]
fn algorithm_ids_roundtrip() {
    for alg in ALL_ALGORITHMS {
        assert_eq!(KeyAlgorithm::from_id(alg.id()), Ok(alg));
    }
    assert_eq!(KeyAlgorithm::from_id("ML-KEM-999"), Err(Error::Unsupported));
    assert_eq!(KeyAlgorithm::from_id(""), Err(Error::Unsupported));
}

#[test]
fn aad_is_unambiguous() {
    // DE: Verschiebung zwischen Salt und Metadaten darf nicht dieselbe AAD ergeben.
    // EN: Shifting bytes between salt and metadata must not produce the same AAD.
    let p = common::min_params();
    let alg = KeyAlgorithm::Aes256;
    let a = protect::associated_data(alg, &p, b"saltsaltsaltsalt1", b"meta");
    let b = protect::associated_data(alg, &p, b"saltsaltsaltsalt", b"1meta");
    assert_ne!(a, b);
    assert!(a.starts_with(AAD_DOMAIN));
}
