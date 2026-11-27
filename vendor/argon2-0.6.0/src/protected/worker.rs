//! DE: Exklusive vorab gesperrte Worker-Leihe je Lane, ohne Lane-Serialisierung.
//! EN: Exclusive prelocked worker borrow per lane, without serializing lanes.

use super::{WorkerState, WorkerWorkspace};
use zeroize::{Zeroize, ZeroizeOnDrop};

impl WorkerWorkspace {
    /// DE: Öffentliche Fortschrittszahl für vollständige Lane-Abdeckung.
    /// EN: Public progress count for complete lane coverage.
    #[must_use]
    pub fn completed_segments(&self) -> Option<usize> {
        self.state
            .try_lock()
            .ok()
            .map(|state| state.completed_segments)
    }
}

impl Zeroize for WorkerState {
    fn zeroize(&mut self) {
        self.address.zeroize();
        self.input.zeroize();
        self.zero.zeroize();
        self.r.zeroize();
        self.result.zeroize();
        self.completed_segments.zeroize();
    }
}
impl Zeroize for WorkerWorkspace {
    fn zeroize(&mut self) {
        // DE: Giftzustand ausschließlich löschen, niemals zur Berechnung wiederverwenden.
        // EN: Access poisoned state only to wipe, never recover it for computation.
        let state = match self.state.get_mut() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.zeroize();
    }
}
impl Drop for WorkerWorkspace {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for WorkerWorkspace {}
