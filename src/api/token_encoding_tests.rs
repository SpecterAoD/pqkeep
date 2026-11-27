//! DE: Unabhängige Base64-Grenzvektoren auf tatsächlichem gesperrtem Scratch.
//! EN: Independent Base64 boundary vectors on actual locked scratch.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::locked_owner_test_support::locked;
use base64ct::{Base64, Base64Unpadded, Base64Url};

#[path = "token_encoding_cleanup_tests.rs"]
mod cleanup;

fn check<T: Encoding>(length: usize, expected: &str) {
    let mut raw = SecretBytes::zeroed(length).unwrap();
    for (i, byte) in raw.expose_mut().iter_mut().enumerate() {
        *byte = u8::try_from((i * 29 + 7) & 255).unwrap();
    }
    let mut work = Workspace::new().unwrap();
    let base = work.0.expose().as_ptr().addr();
    let mut output = SecretBytes::zeroed(expected.len() + 2).unwrap();
    for _ in 0..2 {
        work.0.expose_mut().fill(0xa5);
        output.expose_mut().fill(0xa5);
        locked(raw.expose());
        locked(work.0.expose());
        locked(output.expose());
        let result = work
            .encode::<T>(raw.expose(), &mut output.expose_mut()[1..=expected.len()])
            .unwrap();
        let matches = result.as_bytes() == expected.as_bytes();
        assert!(matches);
        assert_eq!(output.expose()[0], 0xa5);
        assert_eq!(output.expose()[expected.len() + 1], 0xa5);
        assert_eq!(base, work.0.expose().as_ptr().addr());
        locked(work.0.expose());
    }
}

#[test]
fn protected_remainders_match_304_independent_python_cases() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/kat/base64_workspace.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let length = usize::try_from(case["length"].as_u64().unwrap()).unwrap();
        let standard = case["standard"].as_str().unwrap();
        let url = case["url"].as_str().unwrap();
        check::<Base64>(length, standard);
        check::<Base64Unpadded>(length, standard.trim_end_matches('='));
        check::<Base64Url>(length, url);
        check::<Base64UrlUnpadded>(length, url.trim_end_matches('='));
    }
}

fn refuse<T: Encoding>(raw: &SecretBytes) {
    let mut work = Workspace::new().unwrap();
    let mut out = SecretBytes::zeroed(T::encoded_len(raw.expose()) - 1).unwrap();
    out.expose_mut().fill(0xa5);
    work.0.expose_mut().fill(0xa5);
    assert!(work.encode::<T>(raw.expose(), out.expose_mut()).is_err());
    assert!(out.expose().iter().all(|b| *b == 0xa5));
    assert!(work.0.expose().iter().all(|b| *b == 0xa5));
    locked(work.0.expose());
}

#[test]
fn invalid_destination_is_refused_before_scratch_or_output_writes() {
    for length in [1, 2, 3, 31, 32, 33, 4096, 4097] {
        let raw = crate::crypto::rng::secret(length).unwrap();
        refuse::<Base64>(&raw);
        refuse::<Base64Unpadded>(&raw);
        refuse::<Base64Url>(&raw);
        refuse::<Base64UrlUnpadded>(&raw);
    }
}

#[test]
fn token_helper_matches_borrowed_provider_for_fresh_locked_random_inputs() {
    for length in [1, 2, 3, 31, 32, 33, 4095, 4096, 4097] {
        let raw = crate::crypto::rng::secret(length).unwrap();
        let mut a = SecretBytes::zeroed(Base64UrlUnpadded::encoded_len(raw.expose())).unwrap();
        let mut b = SecretBytes::zeroed(a.len()).unwrap();
        let mut work = Workspace::new().unwrap();
        encode(raw.expose(), a.expose_mut()).unwrap();
        work.encode::<Base64UrlUnpadded>(raw.expose(), b.expose_mut())
            .unwrap();
        let matches = a.expose() == b.expose();
        assert!(matches);
        locked(work.0.expose());
    }
}
