//! DE: Einpacken des Dateischlüssels: Passphrase und ML-KEM-Empfänger,
//! Roundtrip, falsche Schlüssel, Manipulation, Längen.
//! EN: Wrapping the file key: passphrase and ML-KEM recipient, round trip,
//! wrong keys, tampering, lengths.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::Error;
use pqkeep::crypto::wrap::{self, FILE_KEY_LEN, RecipientWrap, WRAPPED_LEN};
use pqkeep::crypto::{KemAlgorithm, aead, kem, rng};

const AAD: &[u8] = b"file header without wrap";
const ID: &[u8] = &[0x42; 32];

#[test]
fn passphrase_roundtrip_and_failures() {
    let pass = common::random_passphrase();
    let params = common::min_params();
    let salt = rng::array::<32>().unwrap();
    let file_key = aead::generate_key().unwrap();
    let w = wrap::wrap_with_passphrase(&pass, &params, &salt, file_key.expose(), AAD).unwrap();
    assert_eq!(w.ciphertext.len(), WRAPPED_LEN);
    let back = wrap::unwrap_with_passphrase(pass.as_ref(), &params, &salt, &w, AAD).unwrap();
    assert_eq!(back.expose(), file_key.expose());

    let other = common::random_passphrase();
    let err = wrap::unwrap_with_passphrase(other.as_ref(), &params, &salt, &w, AAD).err();
    assert_eq!(err, Some(Error::Decrypt), "wrong passphrase");
    let mut bad_salt = salt;
    bad_salt[0] ^= 1;
    let err = wrap::unwrap_with_passphrase(pass.as_ref(), &params, &bad_salt, &w, AAD).err();
    assert_eq!(err, Some(Error::Decrypt), "salt");
    let err = wrap::unwrap_with_passphrase(pass.as_ref(), &params, &salt, &w, b"x").err();
    assert_eq!(err, Some(Error::Decrypt), "aad");
}

#[test]
fn recipient_roundtrip_all_parameter_sets() {
    for alg in [
        KemAlgorithm::MlKem512,
        KemAlgorithm::MlKem768,
        KemAlgorithm::MlKem1024,
    ] {
        let kp = kem::generate(alg).unwrap();
        let file_key = aead::generate_key().unwrap();
        let r = wrap::wrap_for_recipient(alg, &kp.public_key, ID, file_key.expose(), AAD).unwrap();
        let back = wrap::unwrap_for_recipient(alg, kp.seed().expose(), ID, &r, AAD).unwrap();
        assert_eq!(back.expose(), file_key.expose(), "{alg:?}");
    }
}

fn recipient_setup() -> (kem::KemKeyPair, RecipientWrap) {
    let alg = KemAlgorithm::MlKem768;
    let kp = kem::generate(alg).unwrap();
    let file_key = aead::generate_key().unwrap();
    let r = wrap::wrap_for_recipient(alg, &kp.public_key, ID, file_key.expose(), AAD).unwrap();
    (kp, r)
}

#[test]
fn wrong_recipient_key_fails() {
    // DE: Implizite Ablehnung → anderes Geheimnis → Auspacken scheitert.
    // EN: Implicit rejection → different secret → unwrapping fails.
    let (_kp, r) = recipient_setup();
    let other = kem::generate(KemAlgorithm::MlKem768).unwrap();
    let err =
        wrap::unwrap_for_recipient(KemAlgorithm::MlKem768, other.seed().expose(), ID, &r, AAD);
    assert_eq!(err.err(), Some(Error::Decrypt));
}

#[test]
fn recipient_tampering_fails() {
    let (kp, r) = recipient_setup();
    let seed = kp.seed().expose();
    let alg = KemAlgorithm::MlKem768;
    let mut bad = r.clone();
    bad.kem_ciphertext[10] ^= 1;
    assert_eq!(
        wrap::unwrap_for_recipient(alg, seed, ID, &bad, AAD).err(),
        Some(Error::Decrypt)
    );
    let mut bad = r.clone();
    bad.wrapped.ciphertext[0] ^= 1;
    assert_eq!(
        wrap::unwrap_for_recipient(alg, seed, ID, &bad, AAD).err(),
        Some(Error::Decrypt)
    );
    let mut bad = r.clone();
    bad.wrapped.nonce[0] ^= 1;
    assert_eq!(
        wrap::unwrap_for_recipient(alg, seed, ID, &bad, AAD).err(),
        Some(Error::Decrypt)
    );
    let other_id = [0x43; 32];
    let err = wrap::unwrap_for_recipient(alg, seed, &other_id, &r, AAD).err();
    assert_eq!(err, Some(Error::Decrypt), "recipient id");
    assert_eq!(
        wrap::unwrap_for_recipient(alg, seed, ID, &r, b"x").err(),
        Some(Error::Decrypt)
    );
    let mut short = r;
    short.wrapped.ciphertext.pop();
    assert_eq!(
        wrap::unwrap_for_recipient(alg, seed, ID, &short, AAD).err(),
        Some(Error::Decrypt)
    );
}

#[test]
fn length_checks() {
    let kp = kem::generate(KemAlgorithm::MlKem768).unwrap();
    let err = wrap::wrap_for_recipient(KemAlgorithm::MlKem768, &kp.public_key, ID, &[0; 16], AAD);
    assert_eq!(err.err(), Some(Error::InvalidInput { field: "file_key" }));
    let err = wrap::wrap_for_recipient(KemAlgorithm::MlKem1024, &kp.public_key, ID, &[0; 32], AAD);
    assert!(err.is_err(), "falsche Schlüssellänge / wrong key length");
    let (_, r) = recipient_setup();
    let mut cut = r;
    cut.kem_ciphertext.truncate(100);
    let err = wrap::unwrap_for_recipient(KemAlgorithm::MlKem768, kp.seed().expose(), ID, &cut, AAD);
    assert_eq!(
        err.err(),
        Some(Error::InvalidInput {
            field: "ciphertext"
        })
    );
    assert_eq!(FILE_KEY_LEN, 32);
}

#[test]
fn each_wrap_uses_fresh_kem_ciphertext() {
    let kp = kem::generate(KemAlgorithm::MlKem768).unwrap();
    let k = [7u8; 32];
    let a = wrap::wrap_for_recipient(KemAlgorithm::MlKem768, &kp.public_key, ID, &k, AAD).unwrap();
    let b = wrap::wrap_for_recipient(KemAlgorithm::MlKem768, &kp.public_key, ID, &k, AAD).unwrap();
    assert_ne!(a.kem_ciphertext, b.kem_ciphertext);
    assert_ne!(a.wrapped, b.wrapped);
}
