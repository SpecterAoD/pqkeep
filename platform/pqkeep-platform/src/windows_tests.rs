//! DE: Native Konsole prüfen, nicht aus Pipe-Erfolg ableiten.
//! EN: Verify native console behavior rather than inferring it from pipes.
#![allow(clippy::unwrap_used)]

use super::*;
use std::os::windows::io::{AsHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{
    AllocConsole, CONSOLE_SCREEN_BUFFER_INFO, CONSOLE_TEXTMODE_BUFFER, COORD,
    CreateConsoleScreenBuffer, GetConsoleScreenBufferInfo, ReadConsoleOutputCharacterW,
    SetConsoleCursorPosition, SetConsoleScreenBufferSize,
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
    let buffer = unsafe { OwnedHandle::from_raw_handle(raw) };
    configure_buffer(&buffer);
    buffer
}

fn configure_buffer(buffer: &OwnedHandle) {
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    // SAFETY: Live owned buffer; initialized exclusive output pointer is not retained.
    let read = unsafe { GetConsoleScreenBufferInfo(buffer.as_raw_handle(), &raw mut info) };
    assert_ne!(read, 0);
    eprintln!(
        "Native fixture geometry: {}x{}",
        info.dwSize.X, info.dwSize.Y
    );
    // DE: Eigener versteckter Testpuffer muss Platz für breite Unicode-Zeichen haben.
    // EN: Own hidden test buffer must have room for wide Unicode characters.
    let size = COORD {
        X: info.dwSize.X.max(128),
        Y: info.dwSize.Y.max(32),
    };
    // SAFETY: Live own test buffer, dimensions never shrink below its existing window.
    let changed = unsafe { SetConsoleScreenBufferSize(buffer.as_raw_handle(), size) };
    assert_ne!(changed, 0);
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
    let mut actual = [0u16; 4];
    let mut read = 0;
    // DE: Genug Zellen für ein breites Zeichen lesen, keine abgeschnittene Hälfte.
    // EN: Read enough cells for a wide character, not a clipped half.
    // SAFETY: Live owned screen buffer; initialized exclusive outputs cover four units.
    // The OS does not retain pointers. Read a glyph, not a presumed string offset.
    let result = unsafe {
        ReadConsoleOutputCharacterW(
            buffer.as_raw_handle(),
            actual.as_mut_ptr(),
            4,
            COORD { X: 0, Y: 0 },
            &raw mut read,
        )
    };
    assert_ne!(result, 0);
    assert_eq!(read, 4);
    actual[0]
}
