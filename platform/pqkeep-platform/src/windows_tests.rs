//! DE: Native Konsole prüfen, nicht aus Pipe-Erfolg ableiten.
//! EN: Verify native console behavior rather than inferring it from pipes.
#![allow(clippy::unwrap_used)]

use super::*;
use std::os::windows::io::{AsHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{
    AllocConsole, CONSOLE_TEXTMODE_BUFFER, COORD, CreateConsoleScreenBuffer,
    ReadConsoleOutputCharacterW, SetConsoleCursorPosition,
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
    // DE: Bildschirmzellen können doppelte Breite haben, auch bei griechischen Zeichen.
    // EN: Screen cells may have double width, including for Greek characters.
    for character in "α中".chars() {
        // SAFETY: Live owned screen buffer and an in-bounds origin; no pointer arguments.
        let positioned = unsafe { SetConsoleCursorPosition(raw, COORD { X: 0, Y: 0 }) };
        assert_ne!(positioned, 0);
        let text = [u16::try_from(u32::from(character)).unwrap()];
        assert_eq!(write_console(buffer.as_handle(), &text).unwrap(), 1);
        assert_eq!(first_cell(&buffer), text[0]);
    }
    let file = std::env::current_exe()
        .and_then(std::fs::File::open)
        .unwrap();
    assert!(write_console(file.as_handle(), &[0x61]).is_err());
}

fn first_cell(buffer: &OwnedHandle) -> u16 {
    let mut actual = 0u16;
    let mut read = 0;
    // SAFETY: Live owned screen buffer; initialized exclusive outputs cover one unit.
    // The OS does not retain pointers. Read a cell, not a presumed string offset.
    let result = unsafe {
        ReadConsoleOutputCharacterW(
            buffer.as_raw_handle(),
            &raw mut actual,
            1,
            COORD { X: 0, Y: 0 },
            &raw mut read,
        )
    };
    assert_ne!(result, 0);
    assert_eq!(read, 1);
    actual
}
