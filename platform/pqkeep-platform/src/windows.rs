//! DE: Einzige produktive FFI-Grenze, keine Allokation oder Secret-Kopie.
//! EN: Single production FFI boundary, without allocation or secret copying.

use std::io;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use windows_sys::Win32::System::Console::WriteConsoleW;

/// DE: Geliehene UTF-16-Einheiten synchron ausgeben; Caller schützt deren Speicher.
/// EN: Synchronously write borrowed UTF-16 units; caller protects their storage.
/// # Errors
/// DE/EN: Win32-Fehler, ungültige Länge oder keine Fortschritte / Win32 errors,
/// invalid lengths or no progress. No redirected-handle fallback.
pub fn write_console(handle: BorrowedHandle<'_>, text: &[u16]) -> io::Result<usize> {
    if text.is_empty() {
        return Ok(0);
    }
    let count = u32::try_from(text.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let mut written = 0;
    // SAFETY: BorrowedHandle is live for this synchronous call; the initialized slice
    // covers count UTF-16 units, written is exclusive, reserved must be null. Win32
    // does not retain either pointer. Failure cannot expose an uninitialized value.
    let result = unsafe {
        WriteConsoleW(
            handle.as_raw_handle(),
            text.as_ptr(),
            count,
            &mut written,
            std::ptr::null(),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    if written == 0 {
        return Err(io::ErrorKind::WriteZero.into());
    }
    if written > count {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(written as usize)
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
