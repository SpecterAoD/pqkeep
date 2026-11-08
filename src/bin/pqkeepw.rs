//! DE: `pqkeepw.exe` – Startprogramm für das Kontextmenü unter Windows. Es ist ein Programm der
//! Windows-Oberfläche (keine Konsole) und startet `pqkeep.exe context --dialog <Argumente>` aus
//! demselben Ordner ohne Konsolenfenster (`CREATE_NO_WINDOW`). Es verarbeitet keine Geheimnisse und
//! startet nichts anderes; der Dateipfad bleibt ein einzelnes Argument (keine Shell). Sind keine
//! Fenster möglich (Exit-Code 6), startet es den gewohnten Ablauf in einem neuen Konsolenfenster.
//! Unter anderen Systemen tut es nichts (Exit-Code 2).
//! EN: `pqkeepw.exe` – launcher for the context menu on Windows. It is a Windows GUI program (no
//! console) and starts `pqkeep.exe context --dialog <arguments>` from the same folder without a
//! console window (`CREATE_NO_WINDOW`). It handles no secrets and starts nothing else; the file path
//! stays a single argument (no shell). If no windows are possible (exit code 6) it starts the usual
//! flow in a new console window. On other systems it does nothing (exit code 2).

#![cfg_attr(windows, windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::process::ExitCode;

/// DE: Exit-Code von `pqkeep context --dialog`, wenn keine Fenster möglich sind (`code::NO_WINDOWS`).
/// EN: Exit code of `pqkeep context --dialog` when no windows are possible (`code::NO_WINDOWS`).
#[cfg(windows)]
const NO_WINDOWS: i32 = 6;

#[cfg(windows)]
fn main() -> ExitCode {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    /// DE/EN: `CREATE_NO_WINDOW`, `CREATE_NEW_CONSOLE` (Win32).
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    let Ok(exe) = std::env::current_exe() else {
        return ExitCode::from(1);
    };
    let pqkeep = exe.with_file_name("pqkeep.exe");
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    // DE: Standardkanäle werden geerbt – ein Fensterprogramm hat keine, daher erhält jeder
    //     Kindprozess die Kanäle seiner eigenen (verborgenen bzw. neuen) Konsole.
    // EN: Standard handles are inherited – a GUI program has none, so each child gets the
    //     handles of its own (hidden or new) console.
    let windows = Command::new(&pqkeep)
        .args(["context", "--dialog"])
        .args(&args)
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .ok()
        .and_then(|s| s.code());
    let code = if windows == Some(NO_WINDOWS) {
        // DE: Keine Fenster (z. B. eingeschränktes PowerShell): gewohnter Ablauf in einer Konsole.
        // EN: No windows (e.g. restricted PowerShell): usual flow in a console.
        Command::new(&pqkeep)
            .arg("context")
            .args(&args)
            .creation_flags(CREATE_NEW_CONSOLE)
            .status()
            .ok()
            .and_then(|s| s.code())
    } else {
        windows
    };
    ExitCode::from(code.and_then(|c| u8::try_from(c).ok()).unwrap_or(1))
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("pqkeepw: nur unter Windows / Windows only");
    ExitCode::from(2)
}
