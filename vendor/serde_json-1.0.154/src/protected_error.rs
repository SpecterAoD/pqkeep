//! DE: Nur synchroner Schutz vor privaten Fehler-Strings; keine globale Policy.
//! EN: Synchronous private-error scope, without changing the global parsing policy.

use core::{cell::Cell, marker::PhantomData};

std::thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn active() -> bool {
    ACTIVE.with(Cell::get)
}

pub(super) struct Guard {
    previous: bool,
    // DE: Scope darf den Thread nie wechseln. EN: Scope must never change threads.
    _thread_bound: PhantomData<*mut ()>,
}

impl Guard {
    pub(super) fn enter() -> Self {
        Self {
            previous: ACTIVE.with(|active| active.replace(true)),
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(self.previous));
    }
}
