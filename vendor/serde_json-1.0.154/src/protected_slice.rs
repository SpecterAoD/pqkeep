//! DE: Öffentlich leeren SliceRead-Parser vor privater Bindung vorbereiten.
//! EN: Prepare a public-empty SliceRead parser before binding private input.

use super::{protected_error, Deserializer, ScratchProtection, SliceRead};
use crate::error::{Error, Result};
use alloc::boxed::Box;
use serde::de::Deserialize;

/// DE: Vorbereitung fehlgeschlagen, ohne private Quelle zu binden.
/// EN: Preparation failed without binding private input.
#[derive(Debug)]
pub enum ProtectedScratchError<E> {
    /// DE/EN: Zustand, Kapazität oder Modus ungeeignet / unsupported state or mode.
    Unsupported,
    /// DE/EN: Reservierung fehlgeschlagen / allocation failed.
    Allocation,
    /// DE/EN: Host hat Schutz verweigert / host denied protection.
    Protection(E),
}

impl<'a> Deserializer<SliceRead<'a>> {
    fn protected_mode_supported(&self) -> bool {
        if cfg!(any(
            feature = "float_roundtrip",
            feature = "arbitrary_precision"
        )) || self.remaining_depth != 128
        {
            return false;
        }
        #[cfg(feature = "unbounded_depth")]
        if self.disable_recursion_limit {
            return false;
        }
        true
    }

    /// DE: Host sperrt den leeren Parser zuerst, dann dessen ganze Scratch-Kapazität.
    /// EN: The host must prelock this public-empty parser, then protect the entire
    /// scratch allocation through its wipe callback. No mutable scratch escapes.
    /// Allocation and callback occur in place, before private source binding.
    pub fn prepare_protected_scratch<E, F>(
        &mut self,
        capacity: usize,
        protect: F,
    ) -> core::result::Result<(), ProtectedScratchError<E>>
    where
        F: FnOnce(usize, usize) -> core::result::Result<Box<dyn ScratchProtection>, E>,
    {
        if !self.protected_mode_supported()
            || self.protected_bound
            || !self.read.protected_empty()
            || self.scratch.capacity() != 0
            || self.scratch_protection.is_some()
            || capacity < 128
        {
            return Err(ProtectedScratchError::Unsupported);
        }
        tri!(self
            .scratch
            .try_reserve_exact(capacity)
            .map_err(|_| ProtectedScratchError::Allocation));
        self.scratch_protection = Some(tri!(protect(
            self.scratch.as_ptr() as usize,
            self.scratch.capacity(),
        )
        .map_err(ProtectedScratchError::Protection)));
        Ok(())
    }

    /// DE: Einmalig Quelle in bereits geschützten Parser binden und synchron parsen.
    /// EN: Bind input in place once, then parse synchronously with private errors.
    /// The host retains parser and source protection until their final use. Returned
    /// values and compiler/scalar transit are outside this ownership contract.
    pub fn deserialize_protected_slice<T: Deserialize<'a>>(
        &mut self,
        input: &'a [u8],
    ) -> Result<T> {
        let required = input.len().checked_add(128);
        if !self.protected_mode_supported()
            || self.protected_bound
            || !self.read.protected_empty()
            || !self.scratch.is_empty()
            || self.scratch_protection.is_none()
            || required.map_or(true, |n| self.scratch.capacity() < n)
        {
            return Err(Error::io(crate::io::Error::new(
                crate::io::ErrorKind::InvalidInput,
                "unsupported protected parser state, capacity or mode",
            )));
        }
        let _scope = protected_error::Guard::enter();
        self.protected_bound = true;
        self.read.bind_protected(input);
        let value = tri!(T::deserialize(&mut *self));
        tri!(self.end());
        Ok(value)
    }
}
