//! DE: Zeroize: Geheimnistypen sind `ZeroizeOnDrop` (Prüfung über den Typ) und
//! `zeroize()` nullt Puffer tatsächlich. Grenzen: siehe docs/CRYPTO.md.
//!
//! EN: Zeroize: secret types are `ZeroizeOnDrop` (type-level check) and
//! `zeroize()` really clears buffers. Limits: see docs/CRYPTO.md.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqc_keyforge::crypto::{SecretBytes, aead};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn secret_types_are_zeroize_on_drop() {
    assert_zeroize_on_drop::<SecretBytes>();
    assert_zeroize_on_drop::<Zeroizing<Vec<u8>>>();
    // DE: Schlüsseltypen der Krypto-Crates, die intern verwendet werden.
    // EN: Key types of the crypto crates used internally.
    assert_zeroize_on_drop::<ml_kem::DecapsulationKey<ml_kem::MlKem768>>();
    assert_zeroize_on_drop::<ml_dsa::SigningKey<ml_dsa::MlDsa65>>();
}

#[test]
fn zeroize_clears_slice() {
    let mut buf = [0xAAu8; 64];
    buf.zeroize();
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn secret_bytes_zeroize_empties_content() {
    let mut s = aead::generate_key().unwrap();
    assert_eq!(s.len(), 32);
    s.zeroize();
    // DE: `Vec::zeroize` nullt den Speicher und setzt die Länge auf 0.
    // EN: `Vec::zeroize` zeroes the memory and sets the length to 0.
    assert!(s.is_empty());
    assert_eq!(s.expose(), &[] as &[u8]);
}

#[test]
fn secret_bytes_keeps_content_until_dropped() {
    let s = SecretBytes::from_slice(&[1, 2, 3]);
    assert_eq!(s.expose(), &[1, 2, 3]);
    assert_eq!(s.len(), 3);
}
