#![allow(clippy::unwrap_used)]

use super::SecretState;
use crate::hardening::memlock;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::ZeroizeOnDrop;

static DROPPED_LOCKED: AtomicBool = AtomicBool::new(false);

struct Probe {
    secret: bool,
}

impl ZeroizeOnDrop for Probe {}

impl Drop for Probe {
    fn drop(&mut self) {
        if self.secret {
            assert!(memlock::is_locked(std::ptr::from_ref(self).addr()));
            self.secret = false;
            DROPPED_LOCKED.store(true, Ordering::SeqCst);
        }
    }
}

fn public() -> Probe {
    Probe { secret: false }
}

#[test]
fn provider_destructor_runs_in_place_before_unlock_and_deallocation() {
    DROPPED_LOCKED.store(false, Ordering::SeqCst);
    let mut state = SecretState::new(public(), public).unwrap();
    state.get_mut().secret = true;
    let address = std::ptr::from_ref(state.get()).addr();
    assert!(memlock::is_locked(address));
    drop(state);
    assert!(DROPPED_LOCKED.load(Ordering::SeqCst));
}
