//! DE: Manipulationstests: jedes einzelne Byte von Chiffrat, Tag, Nonce und AAD,
//! abgeschnittene Daten sowie Salt, Parameter, Algorithmus, Metadaten und
//! falsche Passphrase beim geschützten Schlüssel. Ergebnis immer Fehler, nie Panik.
//!
//! EN: Tampering tests: every single byte of ciphertext, tag, nonce and AAD,
//! truncated data, plus salt, parameters, algorithm, metadata and wrong
//! passphrase on the protected key. Always an error, never a panic.

// DE: unwrap in Hilfsfunktionen erlaubt. EN: unwrap allowed in helper functions.
#![allow(clippy::unwrap_used)]

mod common;

use pqc_keyforge::Error;
use pqc_keyforge::crypto::protect::{self, ProtectedKey};
use pqc_keyforge::crypto::{KemAlgorithm, KeyAlgorithm, aead, kem};

const AAD: &[u8] = b"PQC-KeyForge test header with metadata";

#[test]
fn every_ciphertext_and_tag_byte() {
    let key = aead::generate_key().unwrap();
    let sealed = aead::seal(key.expose(), &[7u8; 64], AAD).unwrap();
    for i in 0..sealed.ciphertext.len() {
        let bad = common::flip(&sealed.ciphertext, i);
        let err = aead::open(key.expose(), &sealed.nonce, &bad, AAD).err();
        assert_eq!(err, Some(Error::Decrypt), "byte {i}");
    }
}

#[test]
fn every_nonce_byte() {
    let key = aead::generate_key().unwrap();
    let sealed = aead::seal(key.expose(), &[7u8; 64], AAD).unwrap();
    for i in 0..sealed.nonce.len() {
        let bad = common::flip(&sealed.nonce, i);
        let err = aead::open(key.expose(), &bad, &sealed.ciphertext, AAD).err();
        assert_eq!(err, Some(Error::Decrypt), "byte {i}");
    }
}

#[test]
fn every_aad_byte() {
    let key = aead::generate_key().unwrap();
    let sealed = aead::seal(key.expose(), &[7u8; 64], AAD).unwrap();
    for i in 0..AAD.len() {
        let bad = common::flip(AAD, i);
        let err = aead::open(key.expose(), &sealed.nonce, &sealed.ciphertext, &bad).err();
        assert_eq!(err, Some(Error::Decrypt), "byte {i}");
    }
    let err = aead::open(key.expose(), &sealed.nonce, &sealed.ciphertext, b"").err();
    assert_eq!(err, Some(Error::Decrypt));
}

#[test]
fn truncated_and_extended_data() {
    let key = aead::generate_key().unwrap();
    let sealed = aead::seal(key.expose(), &[7u8; 64], AAD).unwrap();
    for len in 0..sealed.ciphertext.len() {
        let err = aead::open(key.expose(), &sealed.nonce, &sealed.ciphertext[..len], AAD).err();
        assert_eq!(err, Some(Error::Decrypt), "len {len}");
    }
    let mut longer = sealed.ciphertext.clone();
    longer.push(0);
    let err = aead::open(key.expose(), &sealed.nonce, &longer, AAD).err();
    assert_eq!(err, Some(Error::Decrypt));
    for nonce_len in [0, 11, 13] {
        let nonce = vec![0u8; nonce_len];
        let err = aead::open(key.expose(), &nonce, &sealed.ciphertext, AAD).err();
        assert_eq!(err, Some(Error::Decrypt), "nonce {nonce_len}");
    }
}

/// DE: Geschützter ML-KEM-768-Seed mit Minimalparametern.
/// EN: Protected ML-KEM-768 seed with minimal parameters.
fn protected(pass: &[u8]) -> ProtectedKey {
    let kp = kem::generate(KemAlgorithm::MlKem768).unwrap();
    let alg = KeyAlgorithm::Kem(KemAlgorithm::MlKem768);
    protect::protect(pass, alg, kp.seed().expose(), &common::min_params(), AAD).unwrap()
}

fn expect_decrypt_error(pass: &[u8], key: &ProtectedKey, meta: &[u8], what: &str) {
    let err = protect::unprotect(pass, key, meta).err();
    assert_eq!(err, Some(Error::Decrypt), "{what}");
}

#[test]
fn wrong_passphrase() {
    let pass = common::random_passphrase();
    let key = protected(&pass);
    expect_decrypt_error(&common::random_passphrase(), &key, AAD, "random");
    expect_decrypt_error(&common::flip(&pass, pass.len() - 1), &key, AAD, "1 bit");
    expect_decrypt_error(&pass[..pass.len() - 1], &key, AAD, "truncated");
}

#[test]
fn header_fields_are_authenticated() {
    let pass = common::random_passphrase();
    let key = protected(&pass);

    let mut k = key.clone();
    k.salt = common::flip(&k.salt, 0);
    expect_decrypt_error(&pass, &k, AAD, "salt");

    let mut k = key.clone();
    k.kdf.iterations += 1;
    expect_decrypt_error(&pass, &k, AAD, "iterations");

    // DE: Gleiche Seed-Länge, anderer Algorithmus. EN: Same seed length, other algorithm.
    let mut k = key.clone();
    k.algorithm = KeyAlgorithm::Kem(KemAlgorithm::MlKem1024);
    expect_decrypt_error(&pass, &k, AAD, "algorithm");

    expect_decrypt_error(&pass, &key, &common::flip(AAD, 3), "metadata");
    expect_decrypt_error(&pass, &key, b"", "metadata empty");
}

#[test]
fn malformed_protected_key_fails_fast() {
    let pass = common::random_passphrase();
    let key = protected(&pass);

    let mut k = key.clone();
    k.ciphertext.pop();
    expect_decrypt_error(&pass, &k, AAD, "truncated ciphertext");

    // DE: Andere Seed-Länge (ML-DSA: 32 statt 64 Byte). EN: Other seed length.
    let mut k = key.clone();
    k.algorithm = KeyAlgorithm::Dsa(pqc_keyforge::crypto::DsaAlgorithm::MlDsa65);
    expect_decrypt_error(&pass, &k, AAD, "algorithm with other length");

    let mut k = key.clone();
    k.kdf.memory_kib = u32::MAX;
    assert_eq!(
        protect::unprotect(&pass, &k, AAD).err(),
        Some(Error::KdfParams)
    );

    let mut k = key;
    k.salt.truncate(4);
    let err = protect::unprotect(&pass, &k, AAD).err();
    assert_eq!(err, Some(Error::InvalidInput { field: "salt" }));
}
