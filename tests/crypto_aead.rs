//! DE: AES-256-GCM: Roundtrip, Schlüsselerzeugung, Längenprüfungen.
//! EN: AES-256-GCM: round trip, key generation, length checks.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqc_keyforge::Error;
use pqc_keyforge::crypto::aead;

#[test]
fn roundtrip_with_aad() {
    let key = aead::generate_key().unwrap();
    for len in [0usize, 1, 32, 64, 1000] {
        let plaintext = vec![0x42u8; len];
        let sealed = aead::seal(key.expose(), &plaintext, b"header").unwrap();
        assert_eq!(sealed.ciphertext.len(), len + aead::TAG_LEN);
        let opened =
            aead::open(key.expose(), &sealed.nonce, &sealed.ciphertext, b"header").unwrap();
        assert_eq!(opened.expose(), plaintext.as_slice());
    }
}

#[test]
fn ciphertext_differs_from_plaintext() {
    let key = aead::generate_key().unwrap();
    let plaintext = [0u8; 64];
    let sealed = aead::seal(key.expose(), &plaintext, b"").unwrap();
    assert_ne!(&sealed.ciphertext[..64], &plaintext[..]);
}

#[test]
fn generated_keys_are_256_bit_and_distinct() {
    let a = aead::generate_key().unwrap();
    let b = aead::generate_key().unwrap();
    assert_eq!(a.len(), aead::KEY_LEN);
    assert_eq!(b.len(), 32);
    assert_ne!(a.expose(), b.expose());
}

#[test]
fn wrong_key_length_rejected() {
    for len in [0usize, 16, 31, 33] {
        let key = vec![1u8; len];
        assert_eq!(
            aead::seal(&key, b"x", b"").err(),
            Some(Error::InvalidInput { field: "key" })
        );
        assert_eq!(
            aead::open(&key, &[0u8; 12], &[0u8; 32], b"").err(),
            Some(Error::InvalidInput { field: "key" })
        );
    }
}

#[test]
fn wrong_key_fails() {
    let key = aead::generate_key().unwrap();
    let other = aead::generate_key().unwrap();
    let sealed = aead::seal(key.expose(), b"secret", b"").unwrap();
    let err = aead::open(other.expose(), &sealed.nonce, &sealed.ciphertext, b"").err();
    assert_eq!(err, Some(Error::Decrypt));
}
