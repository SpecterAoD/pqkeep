//! DE: Nur gesperrte skalare Indizes tauschen; keine Record- oder Sortier-Scratchkopie.
//! EN: Swap locked scalar indices only; no record or sorting scratch copy.
use super::{Result, SourceEntries, State};
use std::cmp::Ordering;

impl SourceEntries {
    pub(crate) fn sort(&mut self) -> Result<()> {
        let state = self.0.get_mut();
        state.sort.start = state.used / 2;
        state.sort.end = state.used;
        while state.sort.start > 0 {
            state.sort.start -= 1;
            state.sort.root = state.sort.start;
            state.sift()?;
        }
        while state.sort.end > 1 {
            state.sort.end -= 1;
            state.order.expose_mut().swap(0, state.sort.end);
            state.sort.root = 0;
            state.sift()?;
        }
        state.sort.zeroize();
        Ok(())
    }
}

use zeroize::Zeroize;
impl State {
    fn compare(&self, a: usize, b: usize) -> Result<Ordering> {
        // DE: Originalindex erhält auch bei gleichen Pfaden die bisherige stabile Reihenfolge.
        // EN: Original indices retain the previous stable order even for equal paths.
        Ok(self
            .entry(a)?
            .path_bytes()
            .cmp(self.entry(b)?.path_bytes())
            .then(self.order.expose()[a].cmp(&self.order.expose()[b])))
    }

    fn sift(&mut self) -> Result<()> {
        loop {
            self.sort.child = self
                .sort
                .root
                .checked_mul(2)
                .and_then(|n| n.checked_add(1))
                .ok_or(crate::Error::MemoryLock)?;
            if self.sort.child >= self.sort.end {
                return Ok(());
            }
            if self.sort.child + 1 < self.sort.end
                && self.compare(self.sort.child, self.sort.child + 1)? == Ordering::Less
            {
                self.sort.child += 1;
            }
            if self.compare(self.sort.root, self.sort.child)? != Ordering::Less {
                return Ok(());
            }
            self.order
                .expose_mut()
                .swap(self.sort.root, self.sort.child);
            self.sort.root = self.sort.child;
        }
    }
}
