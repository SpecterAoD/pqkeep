//! DE: Quellrecords, Permutation und Geometrie vor privatem Eintritt sperren.
//! EN: Prelock source records, permutation and geometry before private ingress.

use super::{paths::MAX_ENTRIES, source_entry::SourceEntry};
use crate::{
    Error, Result,
    crypto::{secret_state::SecretState, secret_workspace::SecretWorkspace},
};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Default)]
struct Sort {
    start: usize,
    end: usize,
    root: usize,
    child: usize,
}
impl Zeroize for Sort {
    fn zeroize(&mut self) {
        self.start.zeroize();
        self.end.zeroize();
        self.root.zeroize();
        self.child.zeroize();
    }
}

struct State {
    records: SecretWorkspace<SourceEntry>,
    order: SecretWorkspace<usize>,
    used: usize,
    scan: usize,
    sort: Sort,
}
impl Zeroize for State {
    fn zeroize(&mut self) {
        self.records.zeroize();
        self.order.zeroize();
        self.used.zeroize();
        self.scan.zeroize();
        self.sort.zeroize();
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for State {}
impl ZeroizeOnDrop for crate::crypto::secret_buffer::SecretBuffer<SourceEntry> {}

pub(crate) struct SourceEntries(SecretState<State>);

#[path = "source_entries_iter.rs"]
mod iteration;
#[path = "source_entries_sort.rs"]
mod sorting;

impl SourceEntries {
    pub(super) fn prepare() -> Result<Self> {
        Ok(Self(SecretState::new(State {
            records: SecretWorkspace::zeroed(0)?,
            order: SecretWorkspace::zeroed(0)?,
            used: 0,
            scan: 0,
            sort: Sort::default(),
        })?))
    }

    pub(super) fn len(&self) -> usize {
        self.0.get().used
    }

    pub(super) fn push(
        &mut self,
        rel: &str,
        abs: &Path,
        directory: bool,
        bytes: u64,
    ) -> Result<()> {
        let state = self.0.get_mut();
        state.reserve()?;
        let slot = &mut state.records.expose_mut()[state.used];
        if let Err(error) = slot.fill(rel, abs, directory, bytes) {
            slot.zeroize();
            return Err(error);
        }
        state.order.expose_mut()[state.used] = state.used;
        state.used += 1;
        Ok(())
    }

    pub(super) fn get(&self, position: usize) -> Result<&SourceEntry> {
        self.0.get().entry(position)
    }

    pub(super) fn prepend_all(&mut self, root: &str) -> Result<()> {
        let state = self.0.get_mut();
        state.scan = 0;
        while state.scan < state.used {
            state.records.expose_mut()[state.scan].prepend(root)?;
            state.scan += 1;
        }
        state.scan = 0;
        Ok(())
    }
}

impl State {
    fn entry(&self, position: usize) -> Result<&SourceEntry> {
        if position >= self.used {
            return Err(Error::Crypto);
        }
        let index = *self.order.expose().get(position).ok_or(Error::Crypto)?;
        if index >= self.used {
            return Err(Error::Crypto);
        }
        let entry = self.records.expose().get(index).ok_or(Error::Crypto)?;
        if entry.rel.is_none() || entry.abs.is_none() {
            return Err(Error::Crypto);
        }
        Ok(entry)
    }

    fn reserve(&mut self) -> Result<()> {
        let limit = usize::try_from(MAX_ENTRIES).map_err(|_| Error::MemoryLock)?;
        if self.used >= limit {
            return Err(Error::InvalidInput { field: "entries" });
        }
        if self.used < self.records.expose().len() {
            return Ok(());
        }
        let capacity = self
            .used
            .checked_mul(2)
            .ok_or(Error::MemoryLock)?
            .max(16)
            .min(limit);
        let mut records = SecretWorkspace::<SourceEntry>::zeroed(capacity)?;
        let mut order = SecretWorkspace::<usize>::zeroed(capacity)?;
        self.scan = 0;
        // DE: Nur Feldkopien zwischen gesperrten Zielen; alte Sammlung bleibt bei Fehler gültig.
        // EN: Copy fields only between protected targets; failure preserves the old collection.
        while self.scan < self.used {
            records.expose_mut()[self.scan].copy_from(&self.records.expose()[self.scan])?;
            order.expose_mut()[self.scan] = self.order.expose()[self.scan];
            self.scan += 1;
        }
        self.records = records;
        self.order = order;
        self.scan = 0;
        Ok(())
    }
}

#[cfg(test)]
#[path = "source_entry_tests.rs"]
mod tests;
