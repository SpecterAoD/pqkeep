//! DE: Nur eigenen Eingabemodus halten. EN: Guard only the caller's console mode.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle};
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
    FlushConsoleInputBuffer, GetConsoleMode, GetNumberOfConsoleInputEvents, SetConsoleMode,
};

/// DE: Kontrolliert restaurierbarer Konsolenmodus; Handle bleibt geliehen.
/// EN: Explicitly restorable console input mode with a borrowed live handle.
pub struct ConsoleInputMode<'a> {
    handle: BorrowedHandle<'a>,
    original: u32,
    active: bool,
    cleanup: File,
}

pub(super) fn get(handle: BorrowedHandle<'_>) -> io::Result<u32> {
    let mut mode = 0;
    // SAFETY: Live borrowed handle, initialized exclusive scalar output, synchronous API.
    if unsafe { GetConsoleMode(handle.as_raw_handle(), &raw mut mode) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(mode)
}

fn set(handle: BorrowedHandle<'_>, mode: u32) -> io::Result<()> {
    // SAFETY: Live borrowed own-console handle, scalar flags, no retained pointers.
    if unsafe { SetConsoleMode(handle.as_raw_handle(), mode) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if get(handle)? != mode {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

impl<'a> ConsoleInputMode<'a> {
    /// DE: Verdeckte Ereigniseingabe aktivieren; andere Flags erhalten.
    /// EN: Enable hidden event input, preserving unrelated mode flags.
    /// # Errors
    /// DE/EN: Get-/Set-/Read-back-Fehler / failed mode operations.
    pub fn new(handle: BorrowedHandle<'a>) -> io::Result<Self> {
        let original = get(handle)?;
        // DE: Ausgabekonsolen können dieselben Mode-Bits haben; echte Eingabe prüfen.
        // EN: Output consoles may share mode bits; verify genuine input capability.
        let _ = queued(handle)?;
        // DE: Eigenes vorhandenes CONIN$, keine ACL-/Tokenänderung. Schreibzugriff ist
        // für dokumentiertes Flush erforderlich; keine spätere Rechteannahme.
        // EN: Own existing CONIN$, no ACL/token changes. Documented flush requires
        // write access; acquire it before private input rather than assume it later.
        let cleanup = OpenOptions::new().read(true).write(true).open("CONIN$")?;
        if get(cleanup.as_handle())? != original {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let guard = Self {
            handle,
            original,
            active: true,
            cleanup,
        };
        set(
            handle,
            original
                & !(ENABLE_ECHO_INPUT
                    | ENABLE_LINE_INPUT
                    | ENABLE_PROCESSED_INPUT
                    | ENABLE_VIRTUAL_TERMINAL_INPUT),
        )?;
        Ok(guard)
    }

    /// DE: Ursprünglichen Modus setzen und nachprüfen.
    /// EN: Restore and verify the original mode.
    /// # Errors
    /// DE/EN: Nicht bestätigte Wiederherstellung / restoration not confirmed.
    pub fn restore(self) -> io::Result<()> {
        self.finish(false)
    }

    /// DE: Wartende private Eingaben verwerfen, dann ursprünglichen Modus nachprüfen.
    /// EN: Discard queued private input, then verify original mode restoration.
    /// # Errors
    /// DE/EN: Flush-/Restore-Fehler; kein stiller Echo-Fallback / no silent echo fallback.
    pub fn restore_after_error(self) -> io::Result<()> {
        self.finish(true)
    }

    fn finish(mut self, discard: bool) -> io::Result<()> {
        if discard {
            flush(&self.cleanup)?;
        }
        set(self.handle, self.original)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ConsoleInputMode<'_> {
    fn drop(&mut self) {
        if self.active {
            // DE: Nur Unwind-/Fehlersicherung; normale Rückwege prüfen restore.
            // EN: Unwind/error cleanup only; normal returns check restore explicitly.
            if flush(&self.cleanup).is_ok() {
                let _ = set(self.handle, self.original);
            }
        }
    }
}

fn flush(file: &File) -> io::Result<()> {
    // SAFETY: Live owned input handle opened with read/write access before any private
    // input, referring to this process's console. No pointers retained or data copied.
    if unsafe { FlushConsoleInputBuffer(file.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn queued(handle: BorrowedHandle<'_>) -> io::Result<u32> {
    let mut count = 0;
    // SAFETY: Live borrowed input handle and initialized exclusive scalar output.
    // No private event data is read or removed; output/file handles fail closed.
    if unsafe { GetNumberOfConsoleInputEvents(handle.as_raw_handle(), &raw mut count) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(count)
}
