//! DE: Tatsächlichen geschützten `BLAKE2b`-Zustand gegen unabhängige Vektoren prüfen.
//! EN: Check actual protected `BLAKE2b` state against independent vectors.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::locked_owner_test_support::locked;
use blake2::ProtectedBlake2b;
use zeroize::Zeroize;

#[test]
fn protected_blake2b_matches_all_sizes_and_lazy_block_boundaries() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/kat/argon_hash_workspaces.json")).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 512);
    let mut hash = SecretState::new(ProtectedBlake2b::default()).unwrap();
    let address = std::ptr::from_ref(hash.get()).addr();
    for case in cases {
        let length = usize::try_from(case["length"].as_u64().unwrap()).unwrap();
        let size = usize::try_from(case["digest_size"].as_u64().unwrap()).unwrap();
        let expected = hex::decode(case["digest"].as_str().unwrap()).unwrap();
        let mut input = SecretBytes::zeroed(length).unwrap();
        for (index, byte) in input.expose_mut().iter_mut().enumerate() {
            *byte = u8::try_from((index * 29 + 7) & 255).unwrap();
        }
        for step in [1, 7, 128, 129] {
            hash.get_mut().initialize(size).unwrap();
            for part in input.expose().chunks(step) {
                hash.get_mut().update(part).unwrap();
                hash.get_mut().update(&[]).unwrap();
            }
            let mut output = SecretBytes::zeroed(size + 4).unwrap();
            output.expose_mut().fill(0xa5);
            locked(hash.get());
            hash.get_mut()
                .finalize_into(&mut output.expose_mut()[2..size + 2])
                .unwrap();
            let equal = output.expose()[2..size + 2] == expected;
            assert!(equal);
            assert!(output.expose()[..2].iter().all(|byte| *byte == 0xa5));
            assert!(output.expose()[size + 2..].iter().all(|byte| *byte == 0xa5));
            let stable = std::ptr::from_ref(hash.get()).addr() == address;
            assert!(stable);
            locked(hash.get());
        }
    }
}

#[test]
fn protected_blake2b_refuses_invalid_output_and_inactive_states() {
    let mut hash = SecretState::new(ProtectedBlake2b::default()).unwrap();
    let input = crate::crypto::rng::secret(129).unwrap();
    assert!(hash.get_mut().initialize(0).is_err());
    assert!(hash.get_mut().initialize(65).is_err());
    hash.get_mut().initialize(32).unwrap();
    hash.get_mut().update(input.expose()).unwrap();
    let mut output = SecretBytes::zeroed(33).unwrap();
    output.expose_mut().fill(0xa5);
    assert!(hash.get_mut().finalize_into(output.expose_mut()).is_err());
    assert!(output.expose().iter().all(|byte| *byte == 0xa5));
    hash.get_mut()
        .finalize_into(&mut output.expose_mut()[..32])
        .unwrap();
    assert!(hash.get_mut().update(input.expose()).is_err());
    assert!(hash.get_mut().finalize_into(output.expose_mut()).is_err());
    hash.get_mut().zeroize();
    locked(hash.get());
    assert!(hash.get_mut().update(input.expose()).is_err());
    assert!(hash.get_mut().finalize_into(output.expose_mut()).is_err());
    assert_eq!(format!("{:?}", hash.get()), "ProtectedBlake2b { .. }");
}

#[test]
fn borrowed_blake2b_word_framing_matches_independent_little_endian_vectors() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/kat/argon_hash_workspaces.json")).unwrap();
    let mut hash = SecretState::new(ProtectedBlake2b::default()).unwrap();
    let mut output = SecretBytes::zeroed(32).unwrap();
    for case in fixture["word_cases"].as_array().unwrap() {
        let value = u32::try_from(case["value"].as_u64().unwrap()).unwrap();
        let expected = hex::decode(case["digest"].as_str().unwrap()).unwrap();
        hash.get_mut().initialize(32).unwrap();
        hash.get_mut().update_u32_le(value).unwrap();
        hash.get_mut().finalize_into(output.expose_mut()).unwrap();
        let equal = output.expose() == expected;
        assert!(equal);
        locked(hash.get());
    }
}
