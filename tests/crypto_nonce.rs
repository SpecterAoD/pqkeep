//! DE: Eindeutigkeit von Nonces und Zufallswerten über viele Durchläufe.
//! EN: Uniqueness of nonces and random values over many runs.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;

use pqkeep::crypto::{aead, rng};

const RUNS: usize = 10_000;

#[test]
fn nonces_are_unique() {
    let key = aead::generate_key().unwrap();
    let mut seen = HashSet::with_capacity(RUNS);
    for _ in 0..RUNS {
        let sealed = aead::seal(key.expose(), b"x", b"").unwrap();
        assert!(seen.insert(sealed.nonce), "Nonce doppelt / duplicate nonce");
    }
}

#[test]
fn random_salts_are_unique() {
    let mut seen = HashSet::with_capacity(RUNS);
    for _ in 0..RUNS {
        assert!(seen.insert(rng::array::<32>().unwrap()));
    }
}

#[test]
fn random_bytes_are_not_constant() {
    // DE: Grober Plausibilitätstest, kein Zufallsgütetest.
    // EN: Rough sanity check, not a randomness quality test.
    let data = rng::array::<4096>().unwrap();
    let distinct: HashSet<u8> = data.iter().copied().collect();
    assert!(distinct.len() > 200);
}
