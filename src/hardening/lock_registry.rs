//! DE: Gemeinsame Sperrbuchhaltung vor Adress-/Referenz-Eintritt selbst sperren.
//! EN: Lock shared bookkeeping before address/reference ingress, without recursion.

#[cfg(test)]
use super::lock_registry_storage::Node;
use super::lock_registry_storage::{ALIGNMENT, Storage};
use region::LockGuard;
use std::sync::{
    Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroize;

const BUCKETS: usize = 2048;

#[cfg_attr(windows, repr(align(4096)))]
#[cfg_attr(not(windows), repr(align(65536)))]
struct Control(Mutex<Registry>);

#[cfg(windows)]
const _: () = assert!(align_of::<Control>() <= 4096);

static CONTROL: Control = Control(Mutex::new(Registry::new()));
static POISONED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
#[path = "lock_registry_tests.rs"]
mod tests;

pub(super) fn registry() -> MutexGuard<'static, Registry> {
    match CONTROL.0.lock() {
        Ok(guard) => guard,
        Err(error) => {
            // DE: Nur bestehendes Eigentum bereinigen, keine neuen Secrets annehmen.
            // EN: Allow cleanup of existing ownership, never accept new secrets.
            POISONED.store(true, Ordering::Relaxed);
            error.into_inner()
        }
    }
}

pub(super) struct Registry {
    storage: Storage,
    buckets: [usize; BUCKETS],
    control: LockGuard,
    len: usize,
    broken: bool,
}

impl Registry {
    const fn new() -> Self {
        Self {
            storage: Storage::new(),
            buckets: [0; BUCKETS],
            control: LockGuard::empty(),
            len: 0,
            broken: false,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(super) fn prepare(&mut self, extra: usize) -> bool {
        if self.broken || !self.storage.healthy() || POISONED.load(Ordering::Relaxed) {
            return false;
        }
        let page = region::page::size();
        if page > ALIGNMENT || !ALIGNMENT.is_multiple_of(page) {
            return false;
        }
        let budget = self
            .len
            .checked_mul(page)
            .and_then(|n| n.checked_add(extra))
            .and_then(|n| n.checked_add(size_of::<Control>()))
            .and_then(|n| n.checked_add(self.storage.budget_for(extra / page)?));
        if budget.is_none_or(|n| region::prepare_lock_capacity(n).is_err()) {
            return false;
        }
        self.control.is_active()
            || self
                .control
                .acquire(std::ptr::from_ref(&CONTROL), size_of::<Control>())
                .is_ok()
    }

    fn bucket(page: usize) -> usize {
        (page / region::page::size()) % BUCKETS
    }

    fn find(&self, page: usize) -> Result<(usize, usize), ()> {
        let (mut index, mut previous) = (self.buckets[Self::bucket(page)], 0);
        for _ in 0..self.len {
            if index == 0 {
                return Ok((0, previous));
            }
            let node = self.storage.node(index).ok_or(())?;
            if node.users == 0 || !node.guard.is_active() {
                return Err(());
            }
            if node.address == page {
                return Ok((index, previous));
            }
            previous = index;
            index = node.next;
        }
        if index == 0 {
            Ok((0, previous))
        } else {
            Err(())
        }
    }

    pub(super) fn contains_key(&self, page: usize) -> bool {
        self.find(page).is_ok_and(|(index, _)| index != 0)
    }

    pub(super) fn metadata_contains(&self, address: usize) -> bool {
        let base = std::ptr::from_ref(&CONTROL).addr();
        (self.control.is_active() && (base..base + size_of::<Control>()).contains(&address))
            || self.storage.contains(address)
    }

    #[cfg(test)]
    pub(super) fn get(&self, page: usize) -> Option<&Node> {
        self.storage.node(self.find(page).ok()?.0)
    }

    #[cfg(test)]
    pub(super) fn get_mut(&mut self, page: usize) -> Option<&mut Node> {
        let index = self.find(page).ok()?.0;
        self.storage.node_mut(index)
    }

    pub(super) fn acquire_page(&mut self, page: usize, size: usize) -> bool {
        let Ok((index, _)) = self.find(page) else {
            self.broken = true;
            return false;
        };
        if index != 0 {
            let Some(node) = self.storage.node_mut(index) else {
                self.broken = true;
                return false;
            };
            let Some(count) = node.users.checked_add(1) else {
                return false;
            };
            node.users = count;
            return true;
        }
        let budget = self
            .len
            .checked_add(1)
            .and_then(|n| n.checked_mul(size))
            .and_then(|n| n.checked_add(size_of::<Control>()));
        if budget.is_none_or(|n| !self.storage.extend(n)) {
            return false;
        }
        let index = self.storage.free;
        let Some(node) = self.storage.node_mut(index) else {
            self.broken = true;
            return false;
        };
        if node
            .guard
            .acquire(std::ptr::without_provenance::<u8>(page), size)
            .is_err()
        {
            return false;
        }
        self.storage.free = node.next;
        let Some(node) = self.storage.node_mut(index) else {
            self.broken = true;
            return false;
        };
        node.address = page;
        node.users = 1;
        node.next = self.buckets[Self::bucket(page)];
        self.buckets[Self::bucket(page)] = index;
        self.len += 1;
        true
    }

    pub(super) fn release_page(&mut self, page: usize) -> bool {
        let Ok((index, previous)) = self.find(page) else {
            self.broken = true;
            return false;
        };
        let Some(node) = self.storage.node_mut(index) else {
            self.broken = true;
            return false;
        };
        if node.users > 1 {
            node.users -= 1;
            return true;
        }
        let next = node.next;
        if previous == 0 {
            self.buckets[Self::bucket(page)] = next;
        } else if let Some(node) = self.storage.node_mut(previous) {
            node.next = next;
        } else {
            self.broken = true;
            return false;
        }
        let free = self.storage.free;
        let Some(node) = self.storage.node_mut(index) else {
            self.broken = true;
            return false;
        };
        node.address.zeroize();
        node.users.zeroize();
        node.next.zeroize();
        let success = node.guard.release().is_ok();
        node.next = free;
        self.storage.free = index;
        self.len -= 1;
        self.broken |= !success;
        success
    }

    pub(super) fn finish_release(&mut self) -> bool {
        if self.len != 0 || !self.control.is_active() {
            return true;
        }
        if !self.storage.clear() {
            self.broken = true;
            return false;
        }
        self.buckets.zeroize();
        self.len.zeroize();
        let success = self.control.release().is_ok();
        self.broken |= !success;
        success
    }
}
