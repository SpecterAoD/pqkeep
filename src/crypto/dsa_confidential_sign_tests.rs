//! DE: Vertrauliche Kodierung gegen ursprüngliches Signieren und echte Fehler prüfen.
//! EN: Compare confidential encoding with original signing and actual failures.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    crypto::{rng, seed_state},
    hardening::memlock,
    locked_owner_test_support::locked,
};
use ml_dsa::signature::Keypair;
use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
use std::{cell::Cell, io};

struct Replay<'a> {
    bytes: &'a SecretBytes,
    require_locked: bool,
    fail: bool,
    calls: &'a Cell<usize>,
}

impl TryRng for Replay<'_> {
    type Error = io::Error;
    fn try_next_u32(&mut self) -> io::Result<u32> {
        Err(io::Error::other("unused"))
    }
    fn try_next_u64(&mut self) -> io::Result<u64> {
        Err(io::Error::other("unused"))
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> io::Result<()> {
        self.calls.set(self.calls.get() + 1);
        if self.require_locked {
            assert!(memlock::is_locked(out.as_ptr().addr()));
            assert!(memlock::is_locked(out.as_ptr().addr() + out.len() - 1));
        }
        if self.fail {
            let half = out.len() / 2;
            out[..half].copy_from_slice(&self.bytes.expose()[..half]);
            return Err(io::Error::other("partial RNG failure"));
        }
        out.copy_from_slice(self.bytes.expose());
        Ok(())
    }
}
impl TryCryptoRng for Replay<'_> {}

fn compare<P: MlDsaParams>() {
    let empty = KeyState::<P>::prepare().unwrap();
    assert_hidden_key_locked(empty.get());
    drop(empty);
    let seed = rng::secret(super::super::SEED_LEN).unwrap();
    let key = KeyState::<P>::new(seed_state::view(&seed).unwrap()).unwrap();
    let key_rows = assert_hidden_key_locked(key.get());
    let legacy = ml_dsa::SigningKey::<P>::from_seed(seed_state::view(&seed).unwrap());
    let mut work = SecretState::new(SigningWorkspace::<P>::default()).unwrap();
    let mut out = SecretBytes::zeroed(size_of::<EncodedSignature<P>>()).unwrap();
    out.assert_metadata_locked();
    locked(out.expose());
    let address = out.expose().as_ptr();
    for (length, context_len) in [(0, 0), (193, 255), (65_537, 17)] {
        let message = rng::secret(length).unwrap();
        let context = rng::secret(context_len).unwrap();
        let random = rng::secret(32).unwrap();
        let calls = Cell::new(0);
        let mut replay = Replay {
            bytes: &random,
            require_locked: true,
            fail: false,
            calls: &calls,
        };
        let encoded: &mut EncodedSignature<P> = out.expose_mut().try_into().unwrap();
        key.get()
            .sign_randomized_encoded_with_workspace(
                message.expose(),
                context.expose(),
                &mut replay,
                work.get_mut(),
                encoded,
            )
            .unwrap();
        assert_eq!(calls.get(), 1);
        locked(work.get());
        out.assert_metadata_locked();
        assert!(std::ptr::eq(address, out.expose().as_ptr()));
        compare_original(&legacy, &message, &context, &random, &out);
        let owners_unchanged = assert_hidden_key_locked(key.get()) == key_rows;
        assert!(owners_unchanged);
    }
}

fn assert_hidden_key_locked<P: MlDsaParams>(
    key: &ml_dsa::ExpandedSigningKey<P>,
) -> Vec<(usize, usize)> {
    locked(key);
    let mut rows = Vec::new();
    assert!(key.visit_confidential_storage(|address, len| {
        assert!(memlock::is_locked(address));
        assert!(memlock::is_locked(address + len - 1));
        #[cfg(target_os = "linux")]
        assert!(crate::locked_owner_test_support::own_mapping_locked(
            address
        ));
        rows.push((address, len));
        true
    }));
    assert_eq!(rows.len(), key.confidential_storage_count());
    rows
}

fn compare_original<P: MlDsaParams>(
    legacy: &ml_dsa::SigningKey<P>,
    message: &SecretBytes,
    context: &SecretBytes,
    random: &SecretBytes,
    out: &SecretBytes,
) {
    // DE: Bewusster öffentlicher Referenzpfad ausschließlich im Test.
    // EN: Intentional public reference path in the test only.
    let calls = Cell::new(0);
    let expected = legacy
        .expanded_key()
        .sign_randomized(
            message.expose(),
            context.expose(),
            &mut Replay {
                bytes: random,
                require_locked: false,
                fail: false,
                calls: &calls,
            },
        )
        .unwrap();
    let equal = out.expose() == expected.encode().as_slice();
    assert!(equal);
    assert!(legacy.verifying_key().verify_with_context(
        message.expose(),
        context.expose(),
        &expected
    ));
}

#[test]
fn confidential_encoding_matches_original_for_every_parameter_set_and_reused_workspace() {
    compare::<MlDsa44>();
    compare::<MlDsa65>();
    compare::<MlDsa87>();
}

#[test]
fn randomized_dispatch_returns_locked_signatures_accepted_by_existing_verifier() {
    for algorithm in [
        DsaAlgorithm::MlDsa44,
        DsaAlgorithm::MlDsa65,
        DsaAlgorithm::MlDsa87,
    ] {
        let key = super::super::generate(algorithm).unwrap();
        let signature = sign(algorithm, key.seed().expose(), b"test message", b"context").unwrap();
        signature.assert_metadata_locked();
        assert!(super::super::verify(
            algorithm,
            &key.public_key,
            b"test message",
            b"context",
            signature.expose()
        ));
        assert!(!super::super::verify(
            algorithm,
            &key.public_key,
            b"changed",
            b"context",
            signature.expose()
        ));
    }
}

#[test]
fn partial_rng_failure_keeps_output_unchanged_and_long_context_never_calls_rng() {
    let seed = rng::secret(super::super::SEED_LEN).unwrap();
    let key = KeyState::<MlDsa44>::new(seed_state::view(&seed).unwrap()).unwrap();
    let mut work = SecretState::new(SigningWorkspace::<MlDsa44>::default()).unwrap();
    let mut out = SecretBytes::zeroed(size_of::<EncodedSignature<MlDsa44>>()).unwrap();
    out.expose_mut().fill(0x5a);
    let random = rng::secret(32).unwrap();
    for (context, expected_calls) in [(b"context".as_slice(), 1), (&[0; 256][..], 0)] {
        let calls = Cell::new(0);
        let encoded: &mut EncodedSignature<MlDsa44> = out.expose_mut().try_into().unwrap();
        let result = key.get().sign_randomized_encoded_with_workspace(
            b"message",
            context,
            &mut Replay {
                bytes: &random,
                require_locked: true,
                fail: true,
                calls: &calls,
            },
            work.get_mut(),
            encoded,
        );
        assert!(result.is_err());
        assert_eq!(calls.get(), expected_calls);
        assert!(out.expose().iter().all(|byte| *byte == 0x5a));
        locked(work.get());
    }
}
