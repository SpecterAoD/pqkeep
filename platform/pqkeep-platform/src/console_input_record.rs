//! DE: FFI schreibt ausschließlich im Callerbereich. EN: FFI writes in caller storage.

use std::io;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::sync::atomic::{Ordering, compiler_fence};
use windows_sys::Win32::System::Console::INPUT_RECORD;

/// DE: Platz für einen ausgerichteten Record in beliebig ausgerichteten Bytes.
/// EN: Space for an aligned record within arbitrarily aligned caller bytes.
pub const CONSOLE_INPUT_STORAGE: usize = size_of::<INPUT_RECORD>() + align_of::<INPUT_RECORD>() - 1;

pub(super) struct Record<'a> {
    start: *mut u8,
    len: usize,
    native: *mut INPUT_RECORD,
    _borrow: PhantomData<&'a mut [u8]>,
}

impl<'a> Record<'a> {
    pub(super) fn new(storage: &'a mut [u8]) -> io::Result<Self> {
        let start = storage.as_mut_ptr();
        let len = storage.len();
        // SAFETY: MaybeUninit<INPUT_RECORD> permits every initial byte pattern and
        // uninitialized padding. align_to_mut selects only fully in-bounds aligned
        // elements within this exclusive live storage, without assuming u8 alignment.
        let (_, aligned, _) = unsafe { storage.align_to_mut::<MaybeUninit<INPUT_RECORD>>() };
        let native = aligned
            .first_mut()
            .ok_or(io::ErrorKind::InvalidInput)?
            .as_mut_ptr();
        Ok(Self {
            start,
            len,
            native,
            _borrow: PhantomData,
        })
    }

    pub(super) fn pointer(&self) -> *mut INPUT_RECORD {
        self.native
    }
}

impl Drop for Record<'_> {
    fn drop(&mut self) {
        // DE: Auch potenziell uninitialisiertes FFI-Padding nur SCHREIBEN, nie lesen.
        // EN: Only WRITE possibly uninitialized FFI padding; never inspect it as bytes.
        for offset in 0..self.len {
            // SAFETY: Exclusive borrowed allocation remains live; every byte is in bounds.
            // Raw volatile initialization is valid even for uninitialized padding. No
            // typed/safe byte access occurs until this guard has initialized all bytes.
            unsafe { self.start.add(offset).write_volatile(0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}
