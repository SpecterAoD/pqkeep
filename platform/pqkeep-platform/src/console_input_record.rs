//! DE: FFI schreibt ausschließlich im Callerbereich. EN: FFI writes in caller storage.

use std::io;
use std::marker::PhantomData;
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
        let len = storage.len();
        // DE: Nur geprüfte Bytegeometrie, keine Referenz auf native/uninitialisierte Daten.
        // EN: Checked byte geometry only; no reference to native/uninitialized data.
        let offset = storage.as_ptr().align_offset(align_of::<INPUT_RECORD>());
        let end = offset
            .checked_add(size_of::<INPUT_RECORD>())
            .ok_or(io::ErrorKind::InvalidInput)?;
        if storage.get(offset..end).is_none() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // DE: Beide Zeiger erst nach Bounds-Prüfung aus derselben exklusiven Herkunft.
        // EN: Derive both pointers from the same exclusive origin after bounds checks.
        let start = storage.as_mut_ptr();
        #[expect(
            clippy::cast_ptr_alignment,
            reason = "align_offset and checked bounds establish alignment; verified again below"
        )]
        let native = start.wrapping_add(offset).cast::<INPUT_RECORD>();
        if !native.is_aligned() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            start,
            len,
            native,
            _borrow: PhantomData,
        })
    }

    pub(super) fn pointer(&mut self) -> *mut INPUT_RECORD {
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
