//! DE: Typisierte Pufferdescriptoren vor privater Geometrie stabil sperren.
//! EN: Stably lock typed buffer descriptors before private geometry is stored.

use super::{secret_buffer::SecretBuffer, secret_state::SecretState};
use crate::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) struct SecretWorkspace<T: Zeroize>
where
    SecretBuffer<T>: ZeroizeOnDrop,
{
    inner: SecretState<SecretBuffer<T>>,
}

impl<T: Zeroize> SecretWorkspace<T>
where
    SecretBuffer<T>: ZeroizeOnDrop,
{
    fn prepare() -> Result<Self> {
        Ok(Self {
            inner: SecretBuffer::prepare_state()?,
        })
    }

    pub(crate) fn with_capacity(capacity: usize) -> Result<Self> {
        let mut out = Self::prepare()?;
        out.inner.get_mut().reserve_empty(capacity)?;
        Ok(out)
    }

    // DE: Bewusste Caller-Übernahme; bei frühem Ownerfehler Quelle vollständig löschen.
    // EN: Explicit caller transfer; fully wipe the source on early owner failure.
    pub(crate) fn new(mut source: Vec<T>) -> Result<Self> {
        let mut inner = SecretBuffer::prepare_state_or_wipe(&mut source)?;
        inner.get_mut().adopt_locked(source)?;
        Ok(Self { inner })
    }

    pub(crate) fn expose(&self) -> &[T] {
        self.inner.get().expose()
    }

    pub(crate) fn expose_mut(&mut self) -> &mut [T] {
        self.inner.get_mut().expose_mut()
    }

    pub(crate) fn push_preallocated(&mut self, value: T) -> Result<()> {
        self.inner.get_mut().push_preallocated(value)
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.inner.get_mut().truncate(len);
    }
}

impl<T: Zeroize + Default> SecretWorkspace<T>
where
    SecretBuffer<T>: ZeroizeOnDrop,
{
    pub(crate) fn zeroed(len: usize) -> Result<Self> {
        let mut out = Self::prepare()?;
        out.inner.get_mut().initialize_defaults(len)?;
        Ok(out)
    }
}

impl<T: Zeroize> Zeroize for SecretWorkspace<T>
where
    SecretBuffer<T>: ZeroizeOnDrop,
{
    fn zeroize(&mut self) {
        self.inner.get_mut().zeroize();
    }
}

#[cfg(test)]
#[path = "secret_workspace_tests.rs"]
mod tests;
