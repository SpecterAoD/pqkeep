//! DE: Unabhängige GCM-Vektoren und reale AES-Workspace-Owner prüfen.
//! EN: Check independent GCM vectors and actual AES workspace owners.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::locked_owner_test_support::locked;
use aes_gcm::aes::{Block, ProtectedAes256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[path = "aead_workspace_cleanup_tests.rs"]
mod cleanup;

fn pattern(len: usize, multiplier: usize, add: usize) -> SecretBytes {
    let mut out = SecretBytes::zeroed(len).unwrap();
    for (i, byte) in out.expose_mut().iter_mut().enumerate() {
        *byte = u8::try_from((i * multiplier + add) & 255).unwrap();
    }
    out
}

#[test]
fn uninitialized_and_explicitly_wiped_gcm_refuse_processing_without_output_writes() {
    let mut state = SecretState::new(Aes256Gcm::default()).unwrap();
    let mut buffer = SecretBytes::zeroed(17).unwrap();
    buffer.expose_mut().fill(0xa5);
    let nonce = [0; 12].into();
    let tag = aes_gcm::aead::Tag::<Aes256Gcm>::default();
    for initialize_then_wipe in [false, true] {
        if initialize_then_wipe {
            let key = rng::secret(32).unwrap();
            state
                .get_mut()
                .initialize(key.expose().try_into().unwrap())
                .unwrap();
            state.get_mut().zeroize();
        }
        locked(state.get());
        assert!(
            state
                .get()
                .encrypt_inout_detached(&nonce, &[], buffer.expose_mut().into())
                .is_err()
        );
        assert!(
            state
                .get()
                .decrypt_inout_detached(&nonce, &[], buffer.expose_mut().into(), &tag)
                .is_err()
        );
        assert!(buffer.expose().iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn protected_gcm_matches_72_independent_boundary_vectors() {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/kat/aead_workspaces.json")).unwrap();
    let cases = document["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 72);
    let key = pattern(32, 13, 7);
    let nonce = std::array::from_fn(|i| u8::try_from((i * 19 + 11) & 255).unwrap());
    let state = cipher(key.expose()).unwrap();
    let address = std::ptr::from_ref(state.get()).addr();
    for case in cases {
        let len = usize::try_from(case["length"].as_u64().unwrap()).unwrap();
        let aad_len = usize::try_from(case["aad_length"].as_u64().unwrap()).unwrap();
        let message = pattern(len, 29, 3);
        let aad = pattern(aad_len, 17, 5);
        let expected = hex::decode(case["ciphertext_and_tag"].as_str().unwrap()).unwrap();
        locked(state.get());
        let actual = seal_locked(state.get(), nonce, message.expose(), aad.expose()).unwrap();
        let matches = actual == expected;
        assert!(matches);
        let opened = open(key.expose(), &nonce, &actual, aad.expose()).unwrap();
        let matches = opened.expose() == message.expose();
        assert!(matches);
        locked(state.get());
    }
    let stable = std::ptr::from_ref(state.get()).addr() == address;
    assert!(stable);
    assert_eq!(format!("{:?}", state.get()), "ProtectedAes256Gcm { .. }");
}

#[derive(Default)]
struct Blocks([Block; 5]);
impl ZeroizeOnDrop for Blocks {}
impl Drop for Blocks {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[test]
fn borrowed_aes_native_batches_match_original_and_reject_bad_geometry_before_write() {
    use aes_gcm::aes::{
        Aes256,
        cipher::{BlockCipherEncrypt, KeyInit},
    };
    let key = rng::secret(32).unwrap();
    let mut protected = SecretState::new(ProtectedAes256::default()).unwrap();
    locked(protected.get());
    protected
        .get_mut()
        .initialize(key.expose().try_into().unwrap());
    // DE/EN: Nur Referenzpfad im Test / reference path in tests only.
    let reference = Aes256::new_from_slice(key.expose()).unwrap();
    let mut actual = SecretState::new(Blocks::default()).unwrap();
    let mut expected = SecretState::new(Blocks::default()).unwrap();
    let input: [Block; 5] = std::array::from_fn(|i| Block::from([u8::try_from(i).unwrap(); 16]));
    let batch = protected.get().batch_size();
    assert!(matches!(batch, 2 | 4));
    for count in 0..=batch {
        locked(actual.get());
        protected
            .get_mut()
            .encrypt_blocks_into(&input[..count], &mut actual.get_mut().0[..count])
            .unwrap();
        for (i, block) in expected.get_mut().0[..count].iter_mut().enumerate() {
            block.copy_from_slice(&input[i]);
            reference.encrypt_block(block);
        }
        let equal = actual.get().0[..count] == expected.get().0[..count];
        assert!(equal);
    }
    for block in &mut actual.get_mut().0 {
        block.fill(0xa5);
    }
    assert!(
        protected
            .get_mut()
            .encrypt_blocks_into(&input, &mut actual.get_mut().0)
            .is_err()
    );
    assert!(
        actual
            .get()
            .0
            .iter()
            .flat_map(|block| block.iter())
            .all(|byte| *byte == 0xa5)
    );
    protected.get_mut().zeroize();
    locked(protected.get());
    assert_eq!(format!("{:?}", protected.get()), "ProtectedAes256 { .. }");
}

#[test]
fn protected_gcm_matches_original_with_fresh_keys_and_disjoint_buffers() {
    for _ in 0..3 {
        let key = rng::secret(32).unwrap();
        let state = cipher(key.expose()).unwrap();
        for len in [0, 1, 15, 16, 17, 65, 1025] {
            compare_disjoint(&key, state.get(), len);
        }
    }
}

fn compare_disjoint(key: &SecretBytes, state: &Aes256Gcm, len: usize) {
    use aes_gcm::{Aes256Gcm as Reference, KeyInit, aead::inout::InOutBuf};
    let nonce = rng::array::<12>().unwrap();
    let message = rng::secret(len).unwrap();
    let aad = rng::secret(85).unwrap();
    let mut actual = SecretBytes::zeroed(len).unwrap();
    let mut expected = SecretBytes::from_slice(message.expose()).unwrap();
    let reference = Reference::new_from_slice(key.expose()).unwrap();
    let expected_tag = reference
        .encrypt_inout_detached(&nonce.into(), aad.expose(), expected.expose_mut().into())
        .unwrap();
    locked(state);
    locked(actual.expose());
    let tag = state
        .encrypt_inout_detached(
            &nonce.into(),
            aad.expose(),
            InOutBuf::new(message.expose(), actual.expose_mut()).unwrap(),
        )
        .unwrap();
    let equal = actual.expose() == expected.expose() && tag == expected_tag;
    assert!(equal);
    check_decryption(state, nonce, &aad, &actual, &message, &tag);
}

fn check_decryption(
    state: &Aes256Gcm,
    nonce: [u8; 12],
    aad: &SecretBytes,
    actual: &SecretBytes,
    message: &SecretBytes,
    tag: &aes_gcm::aead::Tag<Aes256Gcm>,
) {
    use aes_gcm::aead::inout::InOutBuf;
    let len = message.len();
    let mut bad_tag = *tag;
    bad_tag[0] ^= 1;
    let mut output = SecretBytes::zeroed(len + 6).unwrap();
    output.expose_mut().fill(0xa5);
    assert!(
        state
            .decrypt_inout_detached(
                &nonce.into(),
                aad.expose(),
                InOutBuf::new(actual.expose(), &mut output.expose_mut()[3..len + 3]).unwrap(),
                &bad_tag,
            )
            .is_err()
    );
    assert!(output.expose().iter().all(|byte| *byte == 0xa5));
    state
        .decrypt_inout_detached(
            &nonce.into(),
            aad.expose(),
            InOutBuf::new(actual.expose(), &mut output.expose_mut()[3..len + 3]).unwrap(),
            tag,
        )
        .unwrap();
    let equal = output.expose()[3..len + 3] == *message.expose();
    assert!(equal);
    assert!(output.expose()[..3].iter().all(|byte| *byte == 0xa5));
    assert!(output.expose()[len + 3..].iter().all(|byte| *byte == 0xa5));
}
