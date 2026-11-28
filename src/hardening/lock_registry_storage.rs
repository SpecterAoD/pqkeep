//! DE: Vor Befüllung gesperrte, fallibel wachsende Registerarena ohne Rekursion.
//! EN: Prelocked fallibly growing registry arena without recursive memory locking.

use region::LockGuard;
use zeroize::Zeroize;

pub(super) const ALIGNMENT: usize = 65536;
const NODES: usize = 256;

pub(super) struct Node {
    pub(super) address: usize,
    pub(super) users: usize,
    pub(super) next: usize,
    pub(super) guard: LockGuard,
}

impl Node {
    const fn empty() -> Self {
        Self {
            address: 0,
            users: 0,
            next: 0,
            guard: LockGuard::empty(),
        }
    }

    fn transfer_to(&mut self, target: &mut Self) {
        target.address = self.address;
        self.address.zeroize();
        target.users = self.users;
        self.users.zeroize();
        target.next = self.next;
        self.next.zeroize();
        self.guard.swap(&mut target.guard);
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.address.zeroize();
        self.users.zeroize();
        self.next.zeroize();
    }
}

#[repr(align(65536))]
struct Chunk([Node; NODES]);

impl Chunk {
    const EMPTY: Self = Self([const { Node::empty() }; NODES]);
    fn empty() -> Self {
        Self::EMPTY
    }
}

pub(super) struct Storage {
    chunks: Vec<Chunk>,
    pending: Vec<Chunk>,
    guard: LockGuard,
    pending_guard: LockGuard,
    pub(super) free: usize,
    broken: bool,
}

impl Storage {
    pub(super) const fn new() -> Self {
        Self {
            chunks: Vec::new(),
            pending: Vec::new(),
            guard: LockGuard::empty(),
            pending_guard: LockGuard::empty(),
            free: 0,
            broken: false,
        }
    }

    pub(super) fn node(&self, index: usize) -> Option<&Node> {
        let index = index.checked_sub(1)?;
        self.chunks.get(index / NODES)?.0.get(index % NODES)
    }

    pub(super) fn node_mut(&mut self, index: usize) -> Option<&mut Node> {
        let index = index.checked_sub(1)?;
        self.chunks.get_mut(index / NODES)?.0.get_mut(index % NODES)
    }

    pub(super) fn budget_for(&self, extra_pages: usize) -> Option<usize> {
        let extra_chunks = extra_pages.checked_add(NODES - 1)? / NODES;
        self.chunks
            .capacity()
            .checked_add(extra_chunks)?
            .checked_next_power_of_two()?
            .checked_mul(2)?
            .checked_mul(size_of::<Chunk>())
    }

    pub(super) fn locked_bytes(&self) -> usize {
        if self.guard.is_active() {
            self.chunks.capacity() * size_of::<Chunk>()
        } else {
            0
        }
    }

    pub(super) fn healthy(&self) -> bool {
        !self.broken
    }

    #[cfg(test)]
    pub(super) fn visit_storage(&self, mut check: impl FnMut(usize, usize) -> bool) -> bool {
        (!self.guard.is_active() || check(self.chunks.as_ptr().addr(), self.locked_bytes()))
            && self.chunks.iter().flat_map(|chunk| &chunk.0).all(|node| {
                if node.users == 0 {
                    node.address == 0 && !node.guard.is_active()
                } else {
                    node.guard.is_active()
                }
            })
    }

    pub(super) fn contains(&self, address: usize) -> bool {
        let base = self.chunks.as_ptr().addr();
        self.guard.is_active() && (base..base + self.locked_bytes()).contains(&address)
    }

    pub(super) fn extend(&mut self, data_and_control_bytes: usize) -> bool {
        if self.broken {
            return false;
        }
        if self.free != 0 {
            return true;
        }
        let old = self.chunks.len();
        let Some(goal) = (if old == 0 {
            Some(1)
        } else {
            old.checked_mul(2)
        }) else {
            return false;
        };
        let Some(base) = old.checked_mul(NODES) else {
            return false;
        };
        let Some(last) = goal.checked_mul(NODES) else {
            return false;
        };
        if !self.prepare_growth(goal, data_and_control_bytes) {
            return false;
        }
        for (source, target) in self.chunks.iter_mut().zip(&mut self.pending) {
            for (source, target) in source.0.iter_mut().zip(&mut target.0) {
                source.transfer_to(target);
            }
        }
        // DE: Alte Felder und Padding unter ihrer noch gehaltenen Sperre löschen.
        // EN: Wipe old fields and padding while their lock is still owned.
        self.chunks.clear();
        self.chunks.spare_capacity_mut().zeroize();
        let released = self.guard.release().is_ok();
        self.chunks = Vec::new();
        std::mem::swap(&mut self.chunks, &mut self.pending);
        self.guard.swap(&mut self.pending_guard);
        self.broken |= !released;
        for index in base + 1..=last {
            if let Some(node) = self.node_mut(index) {
                node.next = if index == last { 0 } else { index + 1 };
            } else {
                self.broken = true;
                return false;
            }
        }
        self.free = base + 1;
        released
    }

    fn prepare_growth(&mut self, goal: usize, data_and_control_bytes: usize) -> bool {
        let Some(extra) = goal.checked_sub(self.pending.len()) else {
            return false;
        };
        if self.pending.try_reserve_exact(extra).is_err() {
            return false;
        }
        while self.pending.len() < goal {
            self.pending.push(Chunk::empty());
        }
        let Some(bytes) = self.pending.capacity().checked_mul(size_of::<Chunk>()) else {
            return false;
        };
        let budget = data_and_control_bytes
            .checked_add(self.locked_bytes())
            .and_then(|n| n.checked_add(bytes));
        if budget.is_none_or(|n| region::prepare_lock_capacity(n).is_err()) {
            return false;
        }
        self.pending_guard
            .acquire(self.pending.as_ptr(), bytes)
            .is_ok()
    }

    pub(super) fn clear(&mut self) -> bool {
        // DE: Invariantenfehler dürfen keine noch lebende fremde Sperre aufheben.
        // EN: Invariant failures must not release another still-live lock.
        if self
            .chunks
            .iter()
            .chain(&self.pending)
            .flat_map(|chunk| &chunk.0)
            .any(|node| node.users != 0 || node.guard.is_active())
        {
            return false;
        }
        self.chunks.clear();
        self.chunks.spare_capacity_mut().zeroize();
        self.pending.clear();
        self.pending.spare_capacity_mut().zeroize();
        let released = self.guard.release().is_ok();
        let pending_released = self.pending_guard.release().is_ok();
        self.chunks = Vec::new();
        self.pending = Vec::new();
        self.free.zeroize();
        self.broken |= !released || !pending_released;
        released && pending_released
    }
}
