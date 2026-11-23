//! DE: Destruktor-/Sperrreihenfolge an lebendem Speicher, auch beim Unwind.
//! EN: Observe destruction/lock ordering in live storage, including unwinding.
#![allow(clippy::unwrap_used)]

use super::SecretState;
use crate::hardening::memlock;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Default)]
struct Observation {
    address: AtomicUsize,
    drops: AtomicUsize,
}

#[repr(C, align(64))]
struct Probe {
    observation: Arc<Observation>,
    payload: [u8; 16 * 1024],
    active: bool,
}

impl ZeroizeOnDrop for Probe {}

impl Drop for Probe {
    fn drop(&mut self) {
        if self.active {
            let address = std::ptr::from_ref(self).addr();
            assert_eq!(address, self.observation.address.load(Ordering::SeqCst));
            assert!(memlock::is_locked(address));
            assert!(memlock::is_locked(address + size_of::<Self>() - 1));
            assert_eq!(self.payload[0], 17);
            assert_eq!(self.payload[self.payload.len() - 1], 23);
            self.payload.zeroize();
            self.observation.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn public_probe(observation: &Arc<Observation>) -> Probe {
    Probe {
        observation: Arc::clone(observation),
        payload: [0; 16 * 1024],
        active: false,
    }
}

fn activate(probe: &mut Probe) {
    let address = std::ptr::from_ref(probe).addr();
    probe.observation.address.store(address, Ordering::SeqCst);
    probe.payload[0] = 17;
    let last = probe.payload.len() - 1;
    probe.payload[last] = 23;
    probe.active = true;
}

fn state(observation: &Arc<Observation>) -> SecretState<Probe> {
    let mut state = SecretState::new(public_probe(observation)).unwrap();
    activate(state.get_mut());
    state
}

#[test]
fn provider_destructor_runs_once_in_place_before_unlock_and_deallocation() {
    let observation = Arc::new(Observation::default());
    let provider = state(&observation);
    assert_eq!(Arc::strong_count(&observation), 2);
    drop(provider);
    assert_eq!(observation.drops.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&observation), 1);
}

#[test]
fn full_former_allocation_is_available_for_wiping_before_unlock() {
    let observation = Arc::new(Observation::default());
    let mut provider = state(&observation);
    let address = provider.inner.as_ptr().addr();
    let capacity = provider.inner.capacity();
    provider.wipe();
    assert_eq!(observation.drops.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&observation), 1);
    assert_eq!(provider.inner.len(), 0);
    assert_eq!(provider.inner.spare_capacity_mut().len(), capacity);
    assert_eq!(provider.inner.as_ptr().addr(), address);
    assert!(memlock::is_locked(address));
    assert!(memlock::is_locked(
        address + capacity * size_of::<Probe>() - 1
    ));
    drop(provider);
    assert_eq!(observation.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn provider_destructor_stays_locked_during_unwinding() {
    let observation = Arc::new(Observation::default());
    let result = std::panic::catch_unwind({
        let observation = Arc::clone(&observation);
        move || {
            let _provider = state(&observation);
            // DE: Kein Secret im Panic-Hook, kein Abort-Nachweis.
            // EN: No secret in a panic hook; this does not prove abort cleanup.
            std::panic::resume_unwind(Box::new(()));
        }
    });
    assert!(result.is_err());
    assert_eq!(observation.drops.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&observation), 1);
}

struct PanickingProbe {
    probe: Probe,
    active: bool,
}

impl ZeroizeOnDrop for PanickingProbe {}

impl Drop for PanickingProbe {
    fn drop(&mut self) {
        if self.active {
            std::panic::resume_unwind(Box::new(()));
        }
    }
}

fn panicking_state(observation: &Arc<Observation>) -> SecretState<PanickingProbe> {
    let mut provider = SecretState::new(PanickingProbe {
        probe: public_probe(observation),
        active: false,
    })
    .unwrap();
    activate(&mut provider.get_mut().probe);
    provider.get_mut().active = true;
    provider
}

#[test]
fn destructor_panic_releases_owned_resources_and_completes_guard_cleanup() {
    let observation = Arc::new(Observation::default());
    let result = std::panic::catch_unwind({
        let observation = Arc::clone(&observation);
        move || drop(panicking_state(&observation))
    });
    assert!(result.is_err());
    assert_eq!(observation.drops.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&observation), 1);
}

#[test]
fn destructor_panic_leaves_full_live_allocation_available_to_wipe_guard() {
    let observation = Arc::new(Observation::default());
    let mut provider = panicking_state(&observation);
    let address = provider.inner.as_ptr().addr();
    let capacity = provider.inner.capacity();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| provider.wipe()));
    assert!(result.is_err());
    assert_eq!(observation.drops.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&observation), 1);
    assert!(provider.inner.is_empty());
    assert_eq!(provider.inner.spare_capacity_mut().len(), capacity);
    assert!(memlock::is_locked(address));
    drop(provider);
    assert_eq!(observation.drops.load(Ordering::SeqCst), 1);
}
