//! DE: Einzige produktive FFI-Grenze, keine Allokation oder Secret-Kopie.
//! EN: Single production FFI boundary, without allocation or secret copying.

use std::io;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use windows_sys::Win32::System::Console::{GetConsoleMode, WriteConsoleW};
use windows_sys::Win32::System::ErrorReporting::{WerGetFlags, WerSetFlags};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

fn wer_flags(handle: windows_sys::Win32::Foundation::HANDLE) -> io::Result<u32> {
    let mut flags = 0;
    // DE: Initialisierte Ausgabe; Win32 prüft das Prozesshandle, keine Zeigerspeicherung.
    // SAFETY: Exclusive initialized output; Win32 validates the process handle and
    // does not retain the pointer. Invalid handles produce an HRESULT failure.
    let result = unsafe { WerGetFlags(handle, &raw mut flags) };
    hresult(result)?;
    Ok(flags)
}

fn hresult(result: i32) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::other("WER operation failed"))
    }
}

/// DE: WER-Flags des eigenen Prozesses lesen, keine Policy ändern.
/// EN: Read this process's WER flags without changing policy.
/// # Errors
/// DE/EN: Nicht erfolgreiche WER-Abfrage / unsuccessful WER query.
pub fn current_wer_flags() -> io::Result<u32> {
    // DE: Pseudohandle, nicht schließen. EN: Pseudo-handle, must not be closed.
    // SAFETY: No arguments or pointers; returns the current process pseudo-handle.
    wer_flags(unsafe { GetCurrentProcess() })
}

/// DE: Nur WER-Heapberichte des eigenen Prozesses mindern und nachprüfen.
/// Bestehende Flags erhalten; keine vollständige Dumpsperre. Beim Prozessstart aufrufen.
/// EN: Mitigate and verify current-process WER heap reporting only, preserving flags.
/// Not a complete dump barrier. Invoke during startup before concurrent host policy changes.
/// # Errors
/// DE/EN: Read-/Set-/Read-back-Fehler; keine Erfolgsannahme / no assumed success.
pub fn suppress_wer_heap_reporting() -> io::Result<()> {
    static POLICY: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = POLICY
        .lock()
        .map_err(|_| io::Error::other("WER policy unavailable"))?;
    crate::wer::ensure_noheap(current_wer_flags, |flags| {
        // DE: Ausschließlich eigener Prozess; keine fremden Handles/Registry-Eingriffe.
        // SAFETY: Scalar documented flags, no pointers; affects the current process only.
        hresult(unsafe { WerSetFlags(flags) })
    })
}

/// DE: Nur echte Konsolen erkennen; MSYS-/Cygwin-PTY-Pipes bleiben Byte-Streams.
/// EN: Detect real consoles only; MSYS/Cygwin PTY pipes remain byte streams.
#[must_use]
pub fn is_console(handle: BorrowedHandle<'_>) -> bool {
    let mut mode = 0;
    // DE: Geliehenes gültiges Handle und initialisierter exklusiver Ausgabewert.
    // SAFETY: Live borrowed handle and initialized exclusive output pointer;
    // the synchronous API does not retain the pointer.
    unsafe { GetConsoleMode(handle.as_raw_handle(), &raw mut mode) != 0 }
}

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
            &raw mut written,
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

#[cfg(test)]
#[path = "windows_wer_tests.rs"]
mod wer_tests;
