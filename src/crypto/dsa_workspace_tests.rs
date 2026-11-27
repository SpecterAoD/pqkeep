//! DE: DSA-Owner und geliehene Operationen gegen den ursprünglichen Pfad prüfen.
//! EN: Compare DSA owners and borrowed operations against the original path.
#![allow(clippy::unwrap_used, deprecated)]

use super::super::*;
use super::KeyState;
use crate::crypto::secret_state::SecretState;
use crate::hardening::memlock;
use crate::locked_owner_test_support::locked;
use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
use ml_dsa::{SeedKeyInPlace, SigningKey};

#[cfg(target_os = "linux")]
#[path = "dsa_workspace_denial_tests.rs"]
mod denial;

// DE: Nur Test: identische frische OS-Bytes an beide Vergleichspfade liefern.
// EN: Test only: replay identical fresh OS bytes into both comparison paths.
struct Replay<'a> {
    bytes: &'a SecretBytes,
    fail: bool,
    require_locked: bool,
}
impl TryRng for Replay<'_> {
    type Error = std::io::Error;
    fn try_next_u32(&mut self) -> std::io::Result<u32> {
        Err(std::io::Error::other("unused"))
    }
    fn try_next_u64(&mut self) -> std::io::Result<u64> {
        Err(std::io::Error::other("unused"))
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> std::io::Result<()> {
        assert!(memlock::is_locked(self.bytes.expose().as_ptr().addr()));
        if self.require_locked {
            assert!(memlock::is_locked(out.as_ptr().addr()));
            assert!(memlock::is_locked(out.as_ptr().addr() + out.len() - 1));
        }
        if self.fail {
            let half = out.len() / 2;
            out[..half].copy_from_slice(&self.bytes.expose()[..half]);
            return Err(std::io::Error::other("partial random failure"));
        }
        if out.len() != self.bytes.len() {
            return Err(std::io::Error::other("test"));
        }
        out.copy_from_slice(self.bytes.expose());
        Ok(())
    }
}
impl TryCryptoRng for Replay<'_> {}

fn payloads<P: MlDsaParams>(key: &SigningKey<P>) -> [(usize, usize); 2] {
    let mut out = [(0, 0); 2];
    let mut count = 0;
    assert!(key.visit_private_storage(|addr, len| {
        assert!(memlock::is_locked(addr));
        assert!(memlock::is_locked(addr + len - 1));
        #[cfg(target_os = "linux")]
        assert!(crate::locked_owner_test_support::own_mapping_locked(addr));
        out[count] = (addr, len);
        count += 1;
        true
    }));
    assert_eq!(count, 2);
    out
}

fn check<P: MlDsaParams>() {
    let seed = rng::secret(SEED_LEN).unwrap();
    let mut key = KeyState::<P>::prepare().unwrap();
    locked(key.get());
    let ranges = payloads(key.get());
    let mut construction =
        SecretState::new(ml_dsa::KeyGenerationWorkspace::<P>::default()).unwrap();
    locked(construction.get());
    key.key
        .get_mut()
        .initialize_seed_with_workspace(seed_state::view(&seed).unwrap(), construction.get_mut());
    locked(construction.get());
    let equal = payloads(key.get()) == ranges;
    assert!(equal);
    assert_eq!(
        format!("{:?}", construction.get()),
        "KeyGenerationWorkspace { .. }"
    );
    let legacy = SigningKey::<P>::from_seed(seed_state::view(&seed).unwrap());
    let equal = key.get().verifying_key().encode() == legacy.verifying_key().encode();
    assert!(equal);
    let mut private = key.get().expanded_key().to_expanded();
    let mut expected = legacy.expanded_key().to_expanded();
    let equal = private == expected;
    assert!(equal);
    private.zeroize();
    expected.zeroize();
    for length in [0, 255] {
        compare_operation(key.get(), &legacy, length);
    }
    key.key.get_mut().zeroize();
    assert!(key.get().as_seed().iter().all(|b| *b == 0));
    let mut wiped = key.get().expanded_key().to_expanded();
    let mut empty = SigningKey::<P>::public_state().expanded_key().to_expanded();
    let equal = wiped == empty;
    assert!(equal);
    wiped.zeroize();
    empty.zeroize();
    let equal = payloads(key.get()) == ranges;
    assert!(equal);
}

#[test]
fn ml_dsa44_borrowed_workspaces_match_original() {
    check::<MlDsa44>();
}
#[test]
fn ml_dsa65_borrowed_workspaces_match_original() {
    check::<MlDsa65>();
}
#[test]
fn ml_dsa87_borrowed_workspaces_match_original() {
    check::<MlDsa87>();
}

struct Observed<'a> {
    inner: ml_dsa::SigningWorkspace<MlDsa44>,
    dropped_locked: &'a std::cell::Cell<bool>,
}
impl zeroize::ZeroizeOnDrop for Observed<'_> {}
impl Drop for Observed<'_> {
    fn drop(&mut self) {
        self.inner.zeroize();
        locked(&self.inner);
        self.dropped_locked.set(true);
    }
}

fn fail_with_populated_workspace(
    key: &SigningKey<MlDsa44>,
    random: &SecretBytes,
    unwind: bool,
    partial: bool,
    witness: &std::cell::Cell<bool>,
) -> Result<()> {
    let mut work = SecretState::new(Observed {
        inner: ml_dsa::SigningWorkspace::default(),
        dropped_locked: witness,
    })?;
    let result = key.expanded_key().sign_randomized_with_workspace(
        b"private message",
        b"private context",
        &mut Replay {
            bytes: random,
            fail: partial,
            require_locked: true,
        },
        &mut work.get_mut().inner,
    );
    assert_eq!(result.is_err(), partial);
    if unwind {
        std::panic::resume_unwind(Box::new(()));
    }
    Err(Error::Crypto)
}

#[test]
fn private_signing_workspace_wipes_under_lock_on_error_partial_rng_and_unwind() {
    crate::locked_owner_test_support::isolated_test(
        "crypto::dsa::key_state::tests::signing_cleanup_child",
        "PQKEEP_DSA_CLEANUP_CHILD",
    );
}

#[test]
#[ignore = "DE/EN: Exakte Zähler nur im eigenen Kind / exact counters only in own child."]
fn signing_cleanup_child() {
    assert_eq!(std::env::var("PQKEEP_DSA_CLEANUP_CHILD").unwrap(), "1");
    let seed = rng::secret(SEED_LEN).unwrap();
    let random = rng::secret(32).unwrap();
    let key = KeyState::<MlDsa44>::new(seed_state::view(&seed).unwrap()).unwrap();
    let baseline = memlock::stats().locked_pages;
    for (unwind, partial) in [(false, false), (true, false), (false, true), (true, true)] {
        let witness = std::cell::Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fail_with_populated_workspace(key.get(), &random, unwind, partial, &witness)
        }));
        assert_eq!(result.is_err(), unwind);
        assert!(witness.get());
        assert_eq!(memlock::stats().locked_pages, baseline);
    }
}

fn compare_operation<P: MlDsaParams>(key: &SigningKey<P>, legacy: &SigningKey<P>, length: usize) {
    let mut work = SecretState::new(ml_dsa::SigningWorkspace::<P>::default()).unwrap();
    let mut verify = SecretState::new(ml_dsa::VerificationWorkspace::<P>::default()).unwrap();
    let message = rng::secret(193).unwrap();
    let context = rng::secret(length).unwrap();
    let random = rng::secret(32).unwrap();
    locked(work.get());
    locked(verify.get());
    let a = key
        .expanded_key()
        .sign_randomized_with_workspace(
            message.expose(),
            context.expose(),
            &mut Replay {
                bytes: &random,
                fail: false,
                require_locked: true,
            },
            work.get_mut(),
        )
        .unwrap();
    let b = legacy_signature(legacy, message.expose(), context.expose(), &random);
    let equal = a.encode() == b.encode();
    assert!(equal);
    assert!(key.verifying_key().verify_with_workspace(
        message.expose(),
        context.expose(),
        &a,
        verify.get_mut()
    ));
    assert!(
        legacy
            .verifying_key()
            .verify_with_context(message.expose(), context.expose(), &a)
    );
    assert!(!key.verifying_key().verify_with_workspace(
        b"changed",
        context.expose(),
        &a,
        verify.get_mut()
    ));
    locked(work.get());
    locked(verify.get());
    work.get_mut().zeroize();
    verify.get_mut().zeroize();
}

fn legacy_signature<P: MlDsaParams>(
    legacy: &SigningKey<P>,
    message: &[u8],
    context: &[u8],
    random: &SecretBytes,
) -> Signature<P> {
    legacy
        .expanded_key()
        .sign_randomized(
            message,
            context,
            &mut Replay {
                bytes: random,
                fail: false,
                require_locked: false,
            },
        )
        .unwrap()
}
