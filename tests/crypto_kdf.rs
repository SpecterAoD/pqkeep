//! DE: Argon2id: Profile, Grenzwerte, Salt/Passphrase-Prüfung, Determinismus.
//! EN: Argon2id: profiles, bounds, salt/passphrase checks, determinism.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::Error;
use pqkeep::crypto::kdf::{self, KdfParams, KdfProfile};

fn with(memory_kib: u32, iterations: u32, parallelism: u32) -> KdfParams {
    KdfParams {
        memory_kib,
        iterations,
        parallelism,
    }
}

#[test]
fn profiles_are_valid() {
    for profile in [KdfProfile::Standard, KdfProfile::Hardened] {
        let p = profile.params();
        assert!(p.validate().is_ok(), "{profile:?}");
        assert!((1..=kdf::AUTO_PARALLELISM_CAP).contains(&p.parallelism));
    }
    assert_eq!(KdfProfile::default(), KdfProfile::Standard);
    assert_eq!(KdfProfile::Standard.params().memory_kib, 256 * 1024);
    assert_eq!(KdfProfile::Hardened.params().memory_kib, 1024 * 1024);
}

#[test]
fn boundary_values_accepted() {
    for p in [
        with(kdf::MIN_MEMORY_KIB, kdf::MIN_ITERATIONS, 1),
        with(
            kdf::MAX_MEMORY_KIB,
            kdf::MAX_ITERATIONS,
            kdf::MAX_PARALLELISM,
        ),
    ] {
        assert!(p.validate().is_ok(), "{p:?}");
    }
}

#[test]
fn out_of_bounds_rejected_before_derivation() {
    // DE: Würden diese Werte gerechnet, wäre der Test extrem langsam oder bräuchte
    //     viel Speicher – die Prüfung muss vorher greifen.
    // EN: If these values were computed the test would be very slow or need lots of
    //     memory – the check has to happen first.
    let salt = [0u8; kdf::SALT_LEN];
    let bad = [
        with(kdf::MIN_MEMORY_KIB - 1, 3, 1),
        with(kdf::MAX_MEMORY_KIB + 1, 3, 1),
        with(u32::MAX, 3, 1),
        with(kdf::MIN_MEMORY_KIB, kdf::MIN_ITERATIONS - 1, 1),
        with(kdf::MIN_MEMORY_KIB, kdf::MAX_ITERATIONS + 1, 1),
        with(kdf::MIN_MEMORY_KIB, u32::MAX, 1),
        with(kdf::MIN_MEMORY_KIB, 3, 0),
        with(kdf::MIN_MEMORY_KIB, 3, kdf::MAX_PARALLELISM + 1),
    ];
    for p in bad {
        assert_eq!(p.validate(), Err(Error::KdfParams), "{p:?}");
        let err = kdf::derive(b"irrelevant", &salt, &p).err();
        assert_eq!(err, Some(Error::KdfParams), "{p:?}");
    }
}

#[test]
fn salt_length_checked() {
    let p = common::min_params();
    for len in [0, kdf::MIN_SALT_LEN - 1, kdf::MAX_SALT_LEN + 1] {
        let err = kdf::derive(b"pass", &vec![1u8; len], &p).err();
        assert_eq!(
            err,
            Some(Error::InvalidInput { field: "salt" }),
            "len {len}"
        );
    }
}

#[test]
fn empty_passphrase_rejected() {
    let err = kdf::derive(b"", &[1u8; kdf::SALT_LEN], &common::min_params()).err();
    assert_eq!(
        err,
        Some(Error::InvalidInput {
            field: "passphrase"
        })
    );
}

#[test]
fn derivation_is_deterministic_and_salt_dependent() {
    let p = common::min_params();
    let pass = common::random_secret();
    let salt_a = [0xA5u8; kdf::SALT_LEN];
    let salt_b = [0x5Au8; kdf::SALT_LEN];
    let k1 = kdf::derive(&pass, &salt_a, &p).unwrap();
    let k2 = kdf::derive(&pass, &salt_a, &p).unwrap();
    let k3 = kdf::derive(&pass, &salt_b, &p).unwrap();
    assert_eq!(k1.len(), kdf::OUTPUT_LEN);
    assert_eq!(k1.expose(), k2.expose());
    assert_ne!(k1.expose(), k3.expose());
}

#[test]
fn parameters_change_the_key() {
    let pass = common::random_secret();
    let salt = [0x11u8; kdf::SALT_LEN];
    let base = with(kdf::MIN_MEMORY_KIB, kdf::MIN_ITERATIONS, 1);
    let more_t = with(kdf::MIN_MEMORY_KIB, kdf::MIN_ITERATIONS + 1, 1);
    let more_p = with(kdf::MIN_MEMORY_KIB, kdf::MIN_ITERATIONS, 2);
    let k = kdf::derive(&pass, &salt, &base).unwrap();
    assert_ne!(
        k.expose(),
        kdf::derive(&pass, &salt, &more_t).unwrap().expose()
    );
    assert_ne!(
        k.expose(),
        kdf::derive(&pass, &salt, &more_p).unwrap().expose()
    );
}
