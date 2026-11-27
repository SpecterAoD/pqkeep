//! DE: Instrumentierter Payload bleibt bis nach Wipe/Unlock lesbar und lebend.
//! EN: Instrumented payload remains live and readable through wiping and unlocking.
#![allow(clippy::unwrap_used)]

use super::*;
use std::cell::RefCell;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[derive(Default)]
struct Witness {
    mode: usize,
    entered: AtomicBool,
    wipes: AtomicUsize,
    released_before_free: AtomicBool,
    workspace_dropped_locked: AtomicBool,
}

thread_local! {
    static CURRENT: RefCell<Option<Arc<Witness>>> = const { RefCell::new(None) };
}

struct Probe {
    bytes: Box<[u8]>,
    witness: Arc<Witness>,
}

struct ProbeWorkspace(ml_kem::KeyGenerationWorkspace<ml_kem::MlKem512>);

impl Default for ProbeWorkspace {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        if CURRENT.with(|current| current.borrow().as_ref().unwrap().mode == 5) {
            // DE: Nur im ausdrücklich gestarteten eigenen Denial-Testkind.
            // EN: Only in the explicitly launched own denial-test child.
            assert_eq!(std::env::var("PQKEEP_NESTED_KEM_DENIAL").unwrap(), "5");
            rustix::process::setrlimit(
                rustix::process::Resource::Memlock,
                rustix::process::Rlimit {
                    current: Some(0),
                    maximum: Some(0),
                },
            )
            .unwrap();
        }
        Self(ml_kem::KeyGenerationWorkspace::default())
    }
}

impl ZeroizeOnDrop for ProbeWorkspace {}

impl Drop for ProbeWorkspace {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            let current = current.borrow();
            let witness = current.as_ref().unwrap();
            if witness.entered.load(Ordering::SeqCst) {
                crate::locked_owner_test_support::locked(self);
                crate::locked_owner_test_support::locked(&self.0);
                witness
                    .workspace_dropped_locked
                    .store(true, Ordering::SeqCst);
            }
        });
    }
}

impl Zeroize for Probe {
    fn zeroize(&mut self) {
        if self.bytes.iter().any(|byte| *byte != 0) {
            assert!(memlock::is_locked(self.bytes.as_ptr().addr() + 32768));
            self.bytes.zeroize();
            self.witness.wipes.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl ZeroizeOnDrop for Probe {}

impl Drop for Probe {
    fn drop(&mut self) {
        assert!(self.bytes.iter().all(|byte| *byte == 0));
        assert!(!memlock::is_locked(self.bytes.as_ptr().addr() + 8192));
        assert!(!memlock::is_locked(self.bytes.as_ptr().addr() + 32768));
        self.witness
            .released_before_free
            .store(true, Ordering::SeqCst);
    }
}

impl SeedKeyInPlace for Probe {
    type Workspace = ProbeWorkspace;
    fn public_state() -> Self {
        Self {
            bytes: vec![0; 65536].into_boxed_slice(),
            witness: CURRENT.with(|current| current.borrow().as_ref().unwrap().clone()),
        }
    }

    fn visit_private_storage(&self, mut visit: impl FnMut(usize, usize) -> bool) -> bool {
        let base = self.bytes.as_ptr().addr();
        let first = visit(base, 16384);
        #[cfg(target_os = "linux")]
        if self.witness.mode == 4 {
            // DE: Ausschließlich isoliertes Testkind, nachdem die erste Payload gesperrt ist.
            // EN: Isolated test child only, after the first payload has been locked.
            assert!(first);
            rustix::process::setrlimit(
                rustix::process::Resource::Memlock,
                rustix::process::Rlimit {
                    current: Some(0),
                    maximum: Some(0),
                },
            )
            .unwrap();
        }
        first && visit(base + 16384, 32768) && visit(base + 49152, 16384)
    }

    fn initialize_seed_with_workspace(
        &mut self,
        seed: &Seed,
        workspace: &mut Self::Workspace,
    ) -> std::result::Result<(), ml_kem::kem::InvalidKey> {
        crate::locked_owner_test_support::locked(workspace);
        crate::locked_owner_test_support::locked(&workspace.0);
        assert!(memlock::is_locked(self.bytes.as_ptr().addr() + 32768));
        self.witness.entered.store(true, Ordering::SeqCst);
        self.bytes[32768..32832].copy_from_slice(seed);
        self.bytes[32768] |= 1;
        if self.witness.mode == 1 {
            return Err(ml_kem::kem::InvalidKey);
        }
        if self.witness.mode == 3 {
            std::panic::resume_unwind(Box::new(()));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[path = "kem_key_state_denial_tests.rs"]
mod denial;

#[test]
fn nested_payload_is_wiped_then_unlocked_before_free_on_success_error_and_unwind() {
    for mode in 0..4 {
        let witness = Arc::new(Witness {
            mode,
            ..Witness::default()
        });
        CURRENT.with(|current| *current.borrow_mut() = Some(witness.clone()));
        let seed = rng::secret(64).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let state = KeyState::<Probe>::new(seed_state::view(&seed).unwrap());
            if mode == 1 {
                assert!(matches!(state, Err(Error::Crypto)));
            } else {
                let _state = state.unwrap();
                if mode == 2 {
                    std::panic::resume_unwind(Box::new(()));
                }
            }
        }));
        assert_eq!(result.is_err(), mode == 2 || mode == 3);
        assert!(witness.entered.load(Ordering::SeqCst));
        assert_eq!(witness.wipes.load(Ordering::SeqCst), 1);
        assert!(witness.released_before_free.load(Ordering::SeqCst));
        assert!(witness.workspace_dropped_locked.load(Ordering::SeqCst));
        CURRENT.with(|current| *current.borrow_mut() = None);
    }
}
