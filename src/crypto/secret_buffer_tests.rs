//! DE: Sperr-/Löschreihenfolge ohne Lesen freigegebenen Speichers.
//! EN: Lock/wipe ordering without reading freed memory.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::hardening::memlock;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroize;

struct Probe(Arc<AtomicBool>);
impl Zeroize for Probe {
    fn zeroize(&mut self) {
        let locked = memlock::is_locked(std::ptr::from_ref(self).addr());
        self.0.store(locked, Ordering::SeqCst);
    }
}

#[test]
fn typed_buffers_are_wiped_while_still_locked() {
    let checked = Arc::new(AtomicBool::new(false));
    {
        let buffer =
            super::secret_buffer::SecretBuffer::new(vec![Probe(Arc::clone(&checked))]).unwrap();
        assert!(memlock::is_locked(buffer.expose().as_ptr().addr()));
    }
    assert!(checked.load(Ordering::SeqCst));
}

#[test]
fn byte_buffer_truncation_keeps_fixed_locked_storage() {
    let mut buffer = super::SecretBytes::zeroed(32).unwrap();
    let addr = buffer.expose().as_ptr().addr();
    buffer.truncate(4);
    assert_eq!(buffer.expose().as_ptr().addr(), addr);
    assert!(buffer.is_locked() && buffer.len() == 4);
    assert!(super::SecretBytes::zeroed(0).unwrap().is_locked());
}

#[test]
fn typed_buffers_wipe_while_locked_during_unwinding() {
    let checked = Arc::new(AtomicBool::new(false));
    let result = std::panic::catch_unwind({
        let checked = Arc::clone(&checked);
        move || {
            let _buffer = super::secret_buffer::SecretBuffer::new(vec![Probe(checked)]).unwrap();
            // DE: Synthetisches Unwind ohne Secret im Panic-Hook; kein Abort-Nachweis.
            // EN: Synthetic unwind without secrets in panic hooks; not an abort claim.
            std::panic::resume_unwind(Box::new(()));
        }
    });
    assert!(result.is_err());
    assert!(checked.load(Ordering::SeqCst));
}

#[test]
fn typed_preallocated_push_refuses_growth_and_keeps_existing_storage() {
    use super::secret_buffer::SecretBuffer;
    let mut buffer = SecretBuffer::new(Vec::<u64>::with_capacity(1)).unwrap();
    let address = buffer.expose().as_ptr().addr();
    buffer.push_preallocated(17).unwrap();
    assert!(matches!(
        buffer.push_preallocated(23),
        Err(crate::Error::MemoryLock)
    ));
    assert_eq!(buffer.expose(), &[17]);
    assert_eq!(buffer.expose().as_ptr().addr(), address);
    assert!(memlock::is_locked(address));
    buffer.zeroize();
    assert_eq!(buffer.expose(), &[] as &[u64]);
    assert!(memlock::is_locked(address));
    buffer.push_preallocated(29).unwrap();
    assert_eq!(buffer.expose(), &[29]);
    assert_eq!(buffer.expose().as_ptr().addr(), address);
}
