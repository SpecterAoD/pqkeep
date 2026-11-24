//! DE: Ereignisse ohne private Record-Kopie. EN: Events without private record copies.

use crate::console_input_record::Record;
use std::io;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use windows_sys::Win32::System::Console::{KEY_EVENT, ReadConsoleInputW};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_BACK, VK_ESCAPE, VK_RETURN};

/// DE: Nur öffentliche Aktionen/Längen zurückgeben; Text bleibt im Callerpuffer.
/// EN: Public action/length metadata only; text remains in caller storage.
#[derive(Debug, PartialEq, Eq)]
pub enum ConsoleInputEvent {
    /// DE/EN: UTF8-Bytes und Wiederholungen / UTF8 bytes and repetition count.
    Text {
        /// DE/EN: Initialisierte Bytezahl / initialized byte count.
        len: usize,
        /// DE/EN: Wiederholungen / repetitions.
        repeat: u16,
    },
    /// DE/EN: Ganze Zeichen entfernen / remove complete characters.
    Backspace(u16),
    /// DE/EN: Zeile abgeschlossen / line complete.
    Finish,
    /// DE/EN: Abbruch / cancel.
    Cancel,
    /// DE/EN: Ignoriertes Ereignis oder ausstehendes Surrogat / ignored or pending event.
    Ignore,
}

/// DE: Caller sperrt Record, vier Zustandsbytes und vier UTF8-Bytes vor Aufruf.
/// Kein privater Record per Wert; Padding vor jeder Rückgabe vollständig initialisieren.
/// EN: Caller must lock record storage, four state bytes and four UTF8 bytes first.
/// No private record by value; fully initialize padding before every return/unwind.
/// # Errors
/// DE/EN: Win32-/Längen-/UTF16-Fehler, nur Statuscodes / status-only errors.
pub fn read_console_input(
    handle: BorrowedHandle<'_>,
    storage: &mut [u8],
    pending: &mut [u8],
    text: &mut [u8],
) -> io::Result<ConsoleInputEvent> {
    if pending.len() != 4 || text.len() != 4 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let result = (|| {
        let record = Record::new(storage)?;
        read_record(handle, &record)?;
        key_event(&record, pending, text)
    })();
    if result.is_err()
        || matches!(
            &result,
            Ok(ConsoleInputEvent::Cancel | ConsoleInputEvent::Finish)
        )
    {
        pending.fill(0);
    }
    result
}

fn read_record(handle: BorrowedHandle<'_>, record: &Record<'_>) -> io::Result<()> {
    let mut count = 0;
    // SAFETY: Record guard owns exclusive aligned full native output storage and wipes
    // all bytes before safe access resumes, including partial failure/unwind. The live
    // handle and initialized public count remain borrowed for this synchronous call.
    if unsafe { ReadConsoleInputW(handle.as_raw_handle(), record.pointer(), 1, &raw mut count) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    if count != 1 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

fn key_event(
    record: &Record<'_>,
    pending: &mut [u8],
    text: &mut [u8],
) -> io::Result<ConsoleInputEvent> {
    // SAFETY: Success with exactly one event initializes EventType. No full record load.
    if u32::from(unsafe { (*record.pointer()).EventType }) != KEY_EVENT {
        return Ok(ConsoleInputEvent::Ignore);
    }
    // SAFETY: KEY_EVENT discriminant establishes initialized KEY_EVENT_RECORD fields.
    // Take only a raw address, never a whole record/reference or private by-value copy.
    let key = unsafe { &raw const (*record.pointer()).Event.KeyEvent };
    // SAFETY: The checked native key variant initializes these scalar fields.
    if unsafe { (*key).bKeyDown } == 0 {
        return Ok(ConsoleInputEvent::Ignore);
    }
    // SAFETY: Checked key variant, documented Unicode W API, initialized scalar fields.
    let repeat = unsafe { (*key).wRepeatCount };
    if repeat == 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // SAFETY: Checked initialized W key event; only a scalar private character is
    // loaded. Compiler/register/scalar copies remain an explicitly open boundary.
    let unit = unsafe { (*key).uChar.UnicodeChar };
    if unit == 0 {
        // SAFETY: Checked initialized key event. No aggregate native record load.
        let event = match unsafe { (*key).wVirtualKeyCode } {
            VK_BACK => ConsoleInputEvent::Backspace(repeat),
            VK_RETURN => ConsoleInputEvent::Finish,
            VK_ESCAPE => ConsoleInputEvent::Cancel,
            _ => ConsoleInputEvent::Ignore,
        };
        if load(pending) != 0
            && matches!(
                event,
                ConsoleInputEvent::Finish | ConsoleInputEvent::Backspace(_)
            )
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok(event);
    }
    decode(unit, repeat, pending, text)
}

fn load(bytes: &[u8]) -> u16 {
    u16::from(bytes[0]) | (u16::from(bytes[1]) << 8)
}

fn save(bytes: &mut [u8], value: u16) {
    bytes[0] = (value & 255) as u8;
    bytes[1] = (value >> 8) as u8;
}

fn decode(
    unit: u16,
    repeat: u16,
    pending: &mut [u8],
    text: &mut [u8],
) -> io::Result<ConsoleInputEvent> {
    use ConsoleInputEvent::{Backspace, Cancel, Finish, Ignore, Text};
    if unit == 3 || unit == 27 {
        return Ok(Cancel);
    }
    if (0xd800..=0xdbff).contains(&unit) {
        if load(pending) != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        save(pending, unit);
        save(&mut pending[2..], repeat);
        return Ok(Ignore);
    }
    let scalar = if load(pending) != 0 {
        if !(0xdc00..=0xdfff).contains(&unit) || load(&pending[2..]) != repeat {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let value =
            0x10000 + ((u32::from(load(pending)) - 0xd800) << 10) + u32::from(unit) - 0xdc00;
        pending.fill(0);
        value
    } else {
        u32::from(unit)
    };
    match scalar {
        0 => return Ok(Ignore),
        8 | 127 => return Ok(Backspace(repeat)),
        10 | 13 => return Ok(Finish),
        _ => {}
    }
    let ch = char::from_u32(scalar).ok_or(io::ErrorKind::InvalidData)?;
    if ch.is_control() {
        return Ok(Ignore);
    }
    Ok(Text {
        len: ch.encode_utf8(text).len(),
        repeat,
    })
}

#[cfg(test)]
#[path = "console_input_tests.rs"]
mod tests;
