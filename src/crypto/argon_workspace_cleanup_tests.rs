//! DE: Tatsächliche Hash-/Workerflächen bei Error/Unwind unter Sperre löschen.
//! EN: Wipe actual hash/worker storage under lock on errors and unwind.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;
use zeroize::ZeroizeOnDrop;

#[cfg(target_os = "linux")]
#[path = "argon_workspace_denial_tests.rs"]
mod denial;

struct ObservedWork<'a> {
    inner: OperationWorkspace,
    witness: &'a std::cell::Cell<bool>,
}
impl ZeroizeOnDrop for ObservedWork<'_> {}
impl Drop for ObservedWork<'_> {
    fn drop(&mut self) {
        self.inner.zeroize();
        locked(&self.inner);
        self.witness.set(true);
    }
}

struct ObservedWorkers<'a> {
    inner: [WorkerWorkspace; 4],
    witness: &'a std::cell::Cell<bool>,
}
impl ZeroizeOnDrop for ObservedWorkers<'_> {}
impl Drop for ObservedWorkers<'_> {
    fn drop(&mut self) {
        for worker in &mut self.inner {
            worker.zeroize();
            locked(worker);
            assert_eq!(worker.completed_segments(), Some(0));
        }
        self.witness.set(true);
    }
}

fn fail_after_private_operation(
    password: &SecretBytes,
    salt: &SecretBytes,
    out: &mut SecretBytes,
    unwind: bool,
    witnesses: (&std::cell::Cell<bool>, &std::cell::Cell<bool>),
) -> Result<()> {
    let params = argon2::Params::new(32, 3, 4, Some(32)).unwrap();
    let mut memory = SecretWorkspace::<Block>::zeroed(params.block_count())?;
    let mut work = SecretState::new(ObservedWork {
        inner: OperationWorkspace::default(),
        witness: witnesses.0,
    })?;
    let mut workers = SecretState::new(ObservedWorkers {
        inner: std::array::from_fn(|_| WorkerWorkspace::default()),
        witness: witnesses.1,
    })?;
    let argon = Argon2::new_with_secret(
        password.expose(),
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    )
    .unwrap();
    argon
        .hash_password_into_with_workspace(
            WorkspaceInputs {
                password: password.expose(),
                salt: salt.expose(),
                associated_data: salt.expose(),
            },
            out.expose_mut(),
            memory.expose_mut(),
            &mut work.get_mut().inner,
            &mut workers.get_mut().inner,
        )
        .unwrap();
    if unwind {
        std::panic::resume_unwind(Box::new(()));
    }
    Err(Error::Crypto)
}

#[test]
fn populated_argon_hash_and_worker_storage_is_wiped_under_lock_on_error_and_unwind() {
    crate::locked_owner_test_support::isolated_test(
        "crypto::kdf::operation_workspace_tests::cleanup::argon_cleanup_child",
        "PQKEEP_ARGON_CLEANUP_CHILD",
    );
}

#[test]
#[ignore = "DE/EN: Exakte Zähler nur im eigenen Kind / exact counters only in own child."]
fn argon_cleanup_child() {
    assert_eq!(std::env::var("PQKEEP_ARGON_CLEANUP_CHILD").unwrap(), "1");
    let password = crate::crypto::rng::secret(32).unwrap();
    let salt = crate::crypto::rng::secret(16).unwrap();
    let mut out = SecretBytes::zeroed(32).unwrap();
    let baseline = memlock::stats().locked_pages;
    for unwind in [false, true] {
        let work_witness = std::cell::Cell::new(false);
        let workers_witness = std::cell::Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fail_after_private_operation(
                &password,
                &salt,
                &mut out,
                unwind,
                (&work_witness, &workers_witness),
            )
        }));
        assert_eq!(result.is_err(), unwind);
        assert!(work_witness.get() && workers_witness.get());
        assert_eq!(memlock::stats().locked_pages, baseline);
    }
}
