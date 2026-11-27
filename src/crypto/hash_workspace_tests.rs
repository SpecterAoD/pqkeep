//! DE: Unabhängige Hash-/XOF-Vektoren in vorab gesperrten stabilen Ownern.
//! EN: Independent hash/XOF vectors in prelocked stable owners.
#![allow(clippy::unwrap_used)]

use super::{SecretBytes, secret_state::SecretState};
use crate::locked_owner_test_support::locked;
use serde_json::Value;
use sha3::{Digest, Sha3_256, Sha3_512, digest::FixedOutputReset};
use shake::{Shake, ShakeReader, Update, XofReader};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn cases() -> Vec<Value> {
    let document: Value =
        serde_json::from_str(include_str!("../../tests/kat/hash_workspaces.json")).unwrap();
    document["cases"].as_array().unwrap().clone()
}

fn input(case: &Value) -> SecretBytes {
    let len = usize::try_from(case["length"].as_u64().unwrap()).unwrap();
    let mut input = SecretBytes::zeroed(len).unwrap();
    for (i, byte) in input.expose_mut().iter_mut().enumerate() {
        *byte = u8::try_from((i * 29 + 7) & 255).unwrap();
    }
    input
}

fn check_output(storage: &SecretBytes, expected: &[u8]) {
    let matches = storage.expose()[3..3 + expected.len()] == *expected;
    assert!(matches);
    assert!(storage.expose()[..3].iter().all(|byte| *byte == 0xa5));
    assert!(
        storage.expose()[3 + expected.len()..]
            .iter()
            .all(|byte| *byte == 0xa5)
    );
}

fn fixed<D: Digest + FixedOutputReset + Zeroize + ZeroizeOnDrop>(
    input: &SecretBytes,
    expected: &[u8],
) {
    let mut hash = SecretState::new(D::new()).unwrap();
    let address = std::ptr::from_ref(hash.get()).addr();
    let mut output = SecretBytes::zeroed(expected.len() + 6).unwrap();
    for chunk_size in [1, 7, 72, 136, 168] {
        output.expose_mut().fill(0xa5);
        locked(hash.get());
        for chunk in input.expose().chunks(chunk_size) {
            Digest::update(hash.get_mut(), chunk);
        }
        FixedOutputReset::finalize_into_reset(
            hash.get_mut(),
            (&mut output.expose_mut()[3..3 + expected.len()])
                .try_into()
                .unwrap(),
        );
        check_output(&output, expected);
    }
    hash.get_mut().zeroize();
    let stable = std::ptr::from_ref(hash.get()).addr() == address;
    assert!(stable);
    locked(hash.get());
}

fn xof<const RATE: usize>(input: &SecretBytes, expected: &[u8]) {
    let mut hash = SecretState::new(Shake::<RATE>::default()).unwrap();
    let mut reader = SecretState::new(ShakeReader::<RATE>::default()).unwrap();
    let address = std::ptr::from_ref(reader.get()).addr();
    let mut output = SecretBytes::zeroed(expected.len() + 6).unwrap();
    for step in [1, 7, 8, RATE - 1, RATE, RATE + 1] {
        output.expose_mut().fill(0xa5);
        locked(hash.get());
        locked(reader.get());
        for chunk in input.expose().chunks(17) {
            hash.get_mut().update(chunk);
        }
        hash.get_mut().finalize_reader_into(reader.get_mut());
        reader.get_mut().read(&mut []);
        for chunk in output.expose_mut()[3..3 + expected.len()].chunks_mut(step) {
            reader.get_mut().read(chunk);
        }
        check_output(&output, expected);
    }
    hash.get_mut().zeroize();
    reader.get_mut().zeroize();
    let stable = std::ptr::from_ref(reader.get()).addr() == address;
    assert!(stable);
    locked(hash.get());
    locked(reader.get());
}

#[test]
fn sha3_borrowed_output_matches_independent_vectors_at_rate_boundaries() {
    for case in cases() {
        let input = input(&case);
        fixed::<Sha3_256>(
            &input,
            &hex::decode(case["sha3_256"].as_str().unwrap()).unwrap(),
        );
        fixed::<Sha3_512>(
            &input,
            &hex::decode(case["sha3_512"].as_str().unwrap()).unwrap(),
        );
    }
}

#[test]
fn shake_borrowed_reader_matches_independent_vectors_and_restarts() {
    for case in cases() {
        let input = input(&case);
        xof::<168>(
            &input,
            &hex::decode(case["shake128"].as_str().unwrap()).unwrap(),
        );
        xof::<136>(
            &input,
            &hex::decode(case["shake256"].as_str().unwrap()).unwrap(),
        );
    }
}

fn fixture_byte(state: &[u64; 25], offset: usize) -> u8 {
    u8::try_from((state[offset / 8] >> (8 * (offset % 8))) & 255).unwrap()
}

fn sponge_outputs<const RATE: usize>() {
    // DE: Ausschließlich öffentliche synthetische Lane-Werte, kein Schlüsselmaterial.
    // EN: Public synthetic lane values only, never key material.
    let initial = std::array::from_fn(|i| u64::try_from(i).unwrap() * 0x0101_0101_0101_0101);
    for step in [1, 7, 8, RATE - 1, RATE, RATE + 1] {
        for xor in [false, true] {
            let mut state = initial;
            let mut cursor = sponge_cursor::SpongeCursor::<RATE>::default();
            let mut output = vec![0x3c; RATE * 2 + 13];
            let mut calls = 0;
            for chunk in output.chunks_mut(step) {
                if xor {
                    cursor.squeeze_xor_u64_le(&mut state, |_| calls += 1, chunk);
                } else {
                    cursor.squeeze_read_u64_le(&mut state, |_| calls += 1, chunk);
                }
            }
            for (i, byte) in output.iter().enumerate() {
                let expected = fixture_byte(&initial, i % RATE) ^ if xor { 0x3c } else { 0 };
                let matches = *byte == expected;
                assert!(matches);
            }
            assert_eq!(calls, 3);
            assert_eq!(cursor.pos(), 13);
        }
    }
}

fn sponge_absorption<const RATE: usize>() {
    for step in [1, 7, 8, RATE - 1, RATE, RATE + 1] {
        let mut state = [0u64; 25];
        let mut expected = [0u64; 25];
        let data: Vec<u8> = (0..RATE * 2 + 13)
            .map(|i| u8::try_from((i * 31 + 3) & 255).unwrap())
            .collect();
        for (i, byte) in data.iter().enumerate() {
            let pos = i % RATE;
            expected[pos / 8] ^= u64::from(*byte) << (8 * (pos % 8));
        }
        let mut cursor = sponge_cursor::SpongeCursor::<RATE>::default();
        let mut calls = 0;
        for chunk in data.chunks(step) {
            cursor.absorb_u64_le(&mut state, |_| calls += 1, chunk);
        }
        let matches = state == expected;
        assert!(matches);
        assert_eq!(calls, 2);
        assert_eq!(cursor.pos(), 13);
    }
}

#[test]
fn sponge_byte_accesses_and_captured_permutations_preserve_boundaries() {
    sponge_outputs::<72>();
    sponge_outputs::<136>();
    sponge_outputs::<168>();
    sponge_absorption::<72>();
    sponge_absorption::<136>();
    sponge_absorption::<168>();
}
