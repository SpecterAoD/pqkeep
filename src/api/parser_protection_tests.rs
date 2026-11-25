//! DE: Echte gesperrte Parser-Schutzrecords und verweigerte Sperren.
//! EN: Actual locked parser protection records and denied locks.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::locked_owner_test_support::locked;

#[test]
fn scratch_range_metadata_is_locked_before_acquisition_and_stable_after_moves() {
    let mut state = SecretState::new(LockedRange::empty()).unwrap();
    locked(state.get());
    let address = std::ptr::from_ref(state.get());
    let bytes = vec![17u8; 4 * region::page::size()];
    assert!(state.get_mut().acquire(bytes.as_ptr().addr(), bytes.len()));
    locked(state.get());
    let moved = Box::new(ScratchLock { range: state });
    assert!(std::ptr::eq(std::ptr::from_ref(moved.range.get()), address));
    assert!(
        moved
            .range
            .get()
            .complete(bytes.as_ptr().addr(), bytes.len())
    );
    locked(moved.range.get());
    drop(moved);
}

struct ObservedProtection {
    inner: ScratchLock,
    wiped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl serde_json::de::ScratchProtection for ObservedProtection {
    fn wipe(&mut self, scratch: &mut Vec<u8>) {
        locked(self.inner.range.get());
        assert!(scratch.iter().any(|byte| *byte != 0));
        self.inner.wipe(scratch);
        assert_eq!(scratch.len(), scratch.capacity());
        assert!(scratch.iter().all(|byte| *byte == 0));
        assert!(memlock::is_locked(scratch.as_ptr().addr()));
        locked(self.inner.range.get());
        self.wiped.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

struct Unwind;
impl<'de> serde::Deserialize<'de> for Unwind {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let _secret = crate::api::secret_input::SecretInput::deserialize(de)?;
        std::panic::resume_unwind(Box::new(()))
    }
}

#[test]
fn parser_destructor_wipes_live_scratch_and_locked_record_during_unwind() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let bytes = SecretBytes::from_slice(br#""syn\u0074hetic""#).unwrap();
    let scratch = Vec::<u8>::with_capacity(bytes.expose().len() + 128);
    let wiped = Arc::new(AtomicBool::new(false));
    let protection = ObservedProtection {
        inner: ScratchLock::new(scratch.as_ptr().addr(), scratch.capacity()).unwrap(),
        wiped: Arc::clone(&wiped),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = serde_json::de::from_slice_with_protection::<Unwind>(
            bytes.expose(),
            scratch,
            Box::new(protection),
        );
    }));
    assert!(result.is_err());
    assert!(wiped.load(Ordering::SeqCst));
}

#[cfg(target_os = "linux")]
#[path = "parser_protection_denial_tests.rs"]
mod denial;
