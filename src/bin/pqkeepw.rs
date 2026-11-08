//! DE: `pqkeepw.exe` – Startprogramm für das Kontextmenü unter Windows. Es ist ein Programm der
//! Windows-Oberfläche (keine Konsole) und startet `pqkeep.exe context --dialog <Argumente>` aus
//! demselben Ordner ohne Konsolenfenster (`CREATE_NO_WINDOW`). Es verarbeitet keine Geheimnisse und
//! startet nichts anderes; der Dateipfad bleibt ein einzelnes Argument (keine Shell).
//! Unter anderen Systemen tut es nichts (Exit-Code 2).
//! EN: `pqkeepw.exe` – launcher for the context menu on Windows. It is a Windows GUI program (no
//! console) and starts `pqkeep.exe context --dialog <arguments>` from the same folder without a
//! console window (`CREATE_NO_WINDOW`). It handles no secrets and starts nothing else; the file path
//! stays a single argument (no shell). On other systems it does nothing (exit code 2).

#![cfg_attr(windows, windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::process::ExitCode;

#[cfg(windows)]
fn main() -> ExitCode {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    /// DE/EN: `CREATE_NO_WINDOW` (Win32).
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let Ok(exe) = std::env::current_exe() else {
        return ExitCode::from(1);
    };
    let status = Command::new(exe.with_file_name("pqkeep.exe"))
        .args(["context", "--dialog"])
        .args(std::env::args_os().skip(1))
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status.ok().and_then(|s| s.code()) {
        Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        None => ExitCode::from(1),
    }
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("pqkeepw: nur unter Windows / Windows only");
    ExitCode::from(2)
}
