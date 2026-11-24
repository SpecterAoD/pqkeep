//! DE: Nur Dev-Feature: feste öffentliche Ereignisse in alleiniger eigener Konsole.
//! EN: Development feature only: fixed public events in a sole own-process console.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Console::{
    FOCUS_EVENT, FlushConsoleInputBuffer, GetConsoleProcessList, GetStdHandle, INPUT_RECORD,
    INPUT_RECORD_0, KEY_EVENT, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0, STD_INPUT_HANDLE,
    SetStdHandle, WriteConsoleInputW,
};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

/// DE/EN: Ausschließlich öffentliche synthetische Fixtures / public synthetic fixtures only.
#[derive(Clone, Copy)]
pub enum Event {
    /// DE/EN: Griechisches Zeichen dreimal / Greek character three times.
    Alpha,
    /// DE/EN: Losgelassene Taste / released key.
    Release,
    /// DE/EN: Oberes Surrogat zweimal / high surrogate twice.
    High,
    /// DE/EN: Unteres Surrogat zweimal / low surrogate twice.
    Low,
    /// DE/EN: Backspace viermal / backspace four times.
    Backspace,
    /// DE/EN: Enter / enter.
    Enter,
    /// DE/EN: Control-C / control-C.
    CtrlC,
    /// DE/EN: Escape / escape.
    Escape,
    /// DE/EN: Ungültiges unteres Surrogat / invalid low surrogate.
    InvalidLow,
    /// DE/EN: Letztes unteres Surrogat / last low surrogate.
    LastLow,
    /// DE/EN: Ungültige Wiederholungszahl / invalid repeat count.
    ZeroRepeat,
    /// DE/EN: Virtuelles Enter ohne Unicode / virtual enter without Unicode.
    VirtualEnter,
    /// DE/EN: Nicht-Tastaturereignis / non-key event.
    NonKey,
}

/// DE: Testkonsole mit nachgewiesen alleiniger eigener Prozesszugehörigkeit.
/// EN: Test console verified to belong solely to this process.
pub struct Console {
    file: File,
    previous_stdin: HANDLE,
}

fn own_console() -> io::Result<()> {
    if std::env::var("PQKEEP_NATIVE_INPUT_CHILD").as_deref() != Ok("1") {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut processes = [0; 2];
    // SAFETY: Initialized public PID array of exactly two elements; synchronous API
    // reports total required size, so any additional attached process fails closed.
    let count = unsafe { GetConsoleProcessList(processes.as_mut_ptr(), 2) };
    // SAFETY: Scalar own-process query, no pointers or handle ownership transfer.
    if count != 1 || processes[0] != unsafe { GetCurrentProcessId() } {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

impl Console {
    /// DE: Nur eigene neue Konsole öffnen und Start-Ereignisse entfernen.
    /// EN: Open only the own new console and discard its startup events.
    /// # Errors
    /// DE/EN: Zugehörigkeits-, Handle- oder Win32-Fehler / ownership/handle/Win32 errors.
    pub fn new() -> io::Result<Self> {
        own_console()?;
        let file = OpenOptions::new().read(true).write(true).open("CONIN$")?;
        // SAFETY: Borrowed existing standard handle, retained only for restoration;
        // it is never closed or claimed as owned by this fixture.
        let previous_stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let fixture = Self {
            file,
            previous_stdin,
        };
        // SAFETY: Verified sole own console. No public fixtures/private inputs exist
        // yet. Only this console's startup events are discarded, no desktop injection.
        if unsafe { FlushConsoleInputBuffer(fixture.file.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Own child process only. File remains live until after restoration.
        if unsafe { SetStdHandle(STD_INPUT_HANDLE, fixture.file.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fixture)
    }

    /// DE/EN: Geliehenes eigenes Eingabehandle / borrowed own input handle.
    #[must_use]
    pub fn handle(&self) -> BorrowedHandle<'_> {
        self.file.as_handle()
    }

    /// DE/EN: Aktuelle eigene Flags prüfen / query current own flags.
    /// # Errors
    /// DE/EN: Win32-Fehler / Win32 failure.
    pub fn mode(&self) -> io::Result<u32> {
        crate::console_input_mode::get(self.handle())
    }

    /// DE/EN: Wartende Ereignisse der eigenen Fixture zählen / count own queued events.
    /// # Errors
    /// DE/EN: Win32-Fehler / Win32 failure.
    pub fn queued(&self) -> io::Result<u32> {
        crate::console_input_mode::queued(self.handle())
    }

    /// DE: Nur ein vordefiniertes öffentliches Ereignis schreiben, keine Secret-Parameter.
    /// EN: Write one predefined public event, accepting no private character parameters.
    /// # Errors
    /// DE/EN: Zugehörigkeits-/Win32-/Zählfehler / ownership/Win32/count failure.
    pub fn emit(&self, event: Event) -> io::Result<()> {
        own_console()?;
        let record = public_record(event)?;
        let mut written = 0;
        // SAFETY: Verified sole own console, one initialized public synthetic record
        // and initialized exclusive count. No pointers retained or user-desktop input.
        if unsafe {
            WriteConsoleInputW(
                self.file.as_raw_handle(),
                &raw const record,
                1,
                &raw mut written,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if written != 1 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        // SAFETY: Restore only this child's original borrowed standard handle before
        // the fixture file closes. No parent handle or console ownership is changed.
        let _ = unsafe { SetStdHandle(STD_INPUT_HANDLE, self.previous_stdin) };
    }
}

fn public_record(event: Event) -> io::Result<INPUT_RECORD> {
    use Event::{
        Alpha, Backspace, CtrlC, Enter, Escape, High, InvalidLow, LastLow, Low, NonKey, Release,
        VirtualEnter, ZeroRepeat,
    };
    let (unit, repeat, down, virtual_code) = match event {
        Alpha => (0x03b1, 3, 1, 0),
        Release => (0x03b1, 1, 0, 0),
        High => (0xd83d, 2, 1, 0),
        Low => (0xde80, 2, 1, 0),
        Backspace => (8, 4, 1, 8),
        Enter => (13, 1, 1, 13),
        CtrlC => (3, 1, 1, 0),
        Escape => (27, 1, 1, 27),
        InvalidLow => (0xdc00, 1, 1, 0),
        LastLow => (0xdfff, 1, 1, 0),
        ZeroRepeat => (0x03b1, 0, 1, 0),
        VirtualEnter => (0, 1, 1, 13),
        NonKey => (0, 1, 1, 0),
    };
    let kind = if matches!(event, NonKey) {
        FOCUS_EVENT
    } else {
        KEY_EVENT
    };
    Ok(INPUT_RECORD {
        EventType: u16::try_from(kind).map_err(|_| io::ErrorKind::InvalidData)?,
        Event: INPUT_RECORD_0 {
            KeyEvent: KEY_EVENT_RECORD {
                bKeyDown: down,
                wRepeatCount: repeat,
                wVirtualKeyCode: virtual_code,
                uChar: KEY_EVENT_RECORD_0 { UnicodeChar: unit },
                ..KEY_EVENT_RECORD::default()
            },
        },
    })
}
