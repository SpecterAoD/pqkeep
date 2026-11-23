//! DE: Native Konsole prüfen, nicht aus Pipe-Erfolg ableiten.
//! EN: Verify native console behavior rather than inferring it from pipes.
#![allow(clippy::unwrap_used)]

use super::*;
use std::os::windows::io::{AsHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{
    AllocConsole, CONSOLE_TEXTMODE_BUFFER, COORD, CreateConsoleScreenBuffer,
    ReadConsoleOutputCharacterW,
};

fn screen_buffer() -> OwnedHandle {
    // DE: Nur die Testprozess-Konsole anlegen, vorhandene Konsole unverändert lassen.
    // SAFETY: No pointers. Only allocates this test process's console when absent;
    // already-attached consoles may return failure and are left unchanged.
    let _ = unsafe { AllocConsole() };
    // SAFETY: Documented constant flags; null security pointer prevents inheritance,
    // reserved pointer is null. The returned handle is checked before taking ownership.
    let raw = unsafe {
        CreateConsoleScreenBuffer(
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            CONSOLE_TEXTMODE_BUFFER,
            std::ptr::null(),
        )
    };
    assert_ne!(raw, INVALID_HANDLE_VALUE);
    assert!(!raw.is_null());
    // SAFETY: Successful CreateConsoleScreenBuffer returns a unique owned handle.
    unsafe { OwnedHandle::from_raw_handle(raw) }
}

#[test]
fn native_console_roundtrips_unicode_and_rejects_file_handles() {
    let buffer = screen_buffer();
    let raw = buffer.as_raw_handle();
    let text: Vec<u16> = "α中".encode_utf16().collect();
    assert_eq!(
        write_console(buffer.as_handle(), &text).unwrap(),
        text.len()
    );
    let mut actual = [0u16; 2];
    let mut read = 0;
    // SAFETY: Live owned screen-buffer handle; initialized exclusive output array
    // covers the exact count. The OS does not retain output pointers.
    let result = unsafe {
        ReadConsoleOutputCharacterW(
            raw,
            actual.as_mut_ptr(),
            2,
            COORD { X: 0, Y: 0 },
            &raw mut read,
        )
    };
    assert_ne!(result, 0);
    assert_eq!(read, 2);
    assert_eq!(actual.as_slice(), text);
    let file = std::env::current_exe()
        .and_then(std::fs::File::open)
        .unwrap();
    assert!(write_console(file.as_handle(), &text).is_err());
}
