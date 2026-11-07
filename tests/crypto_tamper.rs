//! DE: Manipulationstests: jedes einzelne Byte von Chiffrat, Tag, Nonce und AAD,
//! abgeschnittene Daten sowie Salt, Parameter, Algorithmus, Metadaten und
//! falsche Passphrase beim geschützten Schlüssel. Ergebnis immer Fehler, nie Panik.
//!
//! EN: Tampering tests: every single byte of ciphertext, tag, nonce and AAD,
//! truncated data, plus salt, parameters, algorithm, metadata and wrong
//! passphrase on the protected key. Always an error, never a panic.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::Error;
use pqkeep::crypto::protect::{self, ProtectedKey};
use pqkeep::crypto::{KemAlgorithm, KeyAlgorithm, aead, kem};
use pqkeep::security::{Passphrase, StrongPassphrase};

const AAD: &[u8] = b"PQKeep test header with metadata";

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
fn protected(pass: &StrongPassphrase) -> ProtectedKey {
    let kp = kem::generate(KemAlgorithm::MlKem768).unwrap();
    let alg = KeyAlgorithm::Kem(KemAlgorithm::MlKem768);
    protect::protect(pass, alg, kp.seed().expose(), &common::min_params(), AAD).unwrap()
}

fn expect_decrypt_error(pass: &Passphrase, key: &ProtectedKey, meta: &[u8], what: &str) {
    let err = protect::unprotect(pass, key, meta).err();
    assert_eq!(err, Some(Error::Decrypt), "{what}");
}

#[test]
fn wrong_passphrase() {
    let pass = common::random_passphrase();
    let key = protected(&pass);
    let text = pass.as_ref().expose_str().to_owned();
    let other = common::random_passphrase();
    expect_decrypt_error(other.as_ref(), &key, AAD, "random");
    let mut changed: Vec<char> = text.chars().collect();
    changed[0] = if changed[0] == 'x' { 'y' } else { 'x' };
    let changed: String = changed.into_iter().collect();
    expect_decrypt_error(&common::passphrase(&changed), &key, AAD, "1 char");
    let truncated = &text[..text.len() - 1];
    expect_decrypt_error(&common::passphrase(truncated), &key, AAD, "truncated");
    let longer = format!("{text}x");
    expect_decrypt_error(&common::passphrase(&longer), &key, AAD, "extended");
    // DE: Gegenprobe: dieselbe Passphrase als neu normalisierter Text funktioniert.
    // EN: Cross-check: the same passphrase as freshly normalised text works.
    assert!(protect::unprotect(&common::passphrase(&text), &key, AAD).is_ok());
}

#[test]
fn header_fields_are_authenticated() {
    let pass = common::random_passphrase();
    let key = protected(&pass);

    let mut k = key.clone();
    k.salt = common::flip(&k.salt, 0);
    expect_decrypt_error(pass.as_ref(), &k, AAD, "salt");

    let mut k = key.clone();
    k.kdf.iterations += 1;
    expect_decrypt_error(pass.as_ref(), &k, AAD, "iterations");

    // DE: Gleiche Seed-Länge, anderer Algorithmus. EN: Same seed length, other algorithm.
    let mut k = key.clone();
    k.algorithm = KeyAlgorithm::Kem(KemAlgorithm::MlKem1024);
    expect_decrypt_error(pass.as_ref(), &k, AAD, "algorithm");

    expect_decrypt_error(pass.as_ref(), &key, &common::flip(AAD, 3), "metadata");
    expect_decrypt_error(pass.as_ref(), &key, b"", "metadata empty");
}

#[test]
fn malformed_protected_key_fails_fast() {
    let pass = common::random_passphrase();
    let key = protected(&pass);

    let mut k = key.clone();
    k.ciphertext.pop();
    expect_decrypt_error(pass.as_ref(), &k, AAD, "truncated ciphertext");

    // DE: Andere Seed-Länge (ML-DSA: 32 statt 64 Byte). EN: Other seed length.
    let mut k = key.clone();
    k.algorithm = KeyAlgorithm::Dsa(pqkeep::crypto::DsaAlgorithm::MlDsa65);
    expect_decrypt_error(pass.as_ref(), &k, AAD, "algorithm with other length");

    let mut k = key.clone();
    k.kdf.memory_kib = u32::MAX;
    assert_eq!(
        protect::unprotect(pass.as_ref(), &k, AAD).err(),
        Some(Error::KdfParams)
    );

    let mut k = key;
    k.salt.truncate(4);
    let err = protect::unprotect(pass.as_ref(), &k, AAD).err();
    assert_eq!(err, Some(Error::InvalidInput { field: "salt" }));
}
