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
