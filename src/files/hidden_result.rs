//! DE: Geteilten Trailer-Ergebniszustand vor Identitätseintritt sperren.
//! EN: Lock shared trailer result state before identity ingress.

use super::SignedBy;
use crate::{Result, crypto::secret_state::SecretState};
use std::{cell::RefCell, rc::Rc};
use zeroize::ZeroizeOnDrop;

struct State(RefCell<Option<SignedBy>>);

impl Drop for State {
    fn drop(&mut self) {
        self.0.get_mut().take();
    }
}
impl ZeroizeOnDrop for State {}

// DE: Rc enthält nur gemeinsame Ownership; der befüllte Slot bleibt stabil gesperrt.
// EN: Rc holds shared ownership only; the populated slot stays stably locked.
#[derive(Clone)]
pub(super) struct HiddenResult(Rc<SecretState<State>>);

impl HiddenResult {
    pub(super) fn new() -> Result<Self> {
        Ok(Self(Rc::new(SecretState::new(State(RefCell::new(None)))?)))
    }

    pub(super) fn store(&self, signer: SignedBy) {
        *self.0.get().0.borrow_mut() = Some(signer);
    }

    pub(super) fn take(&self) -> Option<SignedBy> {
        self.0.get().0.borrow_mut().take()
    }
}

#[cfg(test)]
#[path = "hidden_result_tests.rs"]
mod tests;
