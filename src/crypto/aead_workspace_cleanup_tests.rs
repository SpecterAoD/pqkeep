//! DE: Tatsächliche private GCM-Zustände bis nach Wipe gesperrt halten.
//! EN: Keep actual private GCM states locked through wiping.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;

#[cfg(target_os = "linux")]
#[path = "aead_workspace_denial_tests.rs"]
mod denial;

struct Observed<'a> {
    inner: Aes256Gcm,
    witness: &'a std::cell::Cell<bool>,
}
impl ZeroizeOnDrop for Observed<'_> {}
impl Drop for Observed<'_> {
    fn drop(&mut self) {
        self.inner.zeroize();
        locked(&self.inner);
        self.witness.set(true);
    }
}

fn fail_after_private_operation(
    key: &SecretBytes,
    unwind: bool,
    witness: &std::cell::Cell<bool>,
) -> Result<()> {
    let mut state = SecretState::new(Observed {
        inner: Aes256Gcm::default(),
        witness,
    })?;
    locked(state.get());
    state
        .get_mut()
        .inner
        .initialize(key.expose().try_into().unwrap())
        .unwrap();
    let message = rng::secret(193)?;
    let aad = rng::secret(65)?;
    seal_locked(&state.get().inner, [0; 12], message.expose(), aad.expose())?;
    if unwind {
        std::panic::resume_unwind(Box::new(()));
    }
    Err(Error::Crypto)
}

#[test]
fn private_gcm_workspace_is_wiped_under_lock_on_error_and_unwind() {
    crate::locked_owner_test_support::isolated_test(
        "crypto::aead::workspace_tests::cleanup::gcm_cleanup_child",
        "PQKEEP_GCM_CLEANUP_CHILD",
    );
}

#[test]
#[ignore = "DE/EN: Exakte Zähler nur im eigenen Kind / exact counters only in own child."]
fn gcm_cleanup_child() {
    assert_eq!(std::env::var("PQKEEP_GCM_CLEANUP_CHILD").unwrap(), "1");
    let key = rng::secret(32).unwrap();
    let baseline = memlock::stats().locked_pages;
    for unwind in [false, true] {
        let witness = std::cell::Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fail_after_private_operation(&key, unwind, &witness)
        }));
        assert_eq!(result.is_err(), unwind);
        assert!(witness.get());
        assert_eq!(memlock::stats().locked_pages, baseline);
    }
}
