//! DE: Bewusste vertrauliche Ausgabe ohne std-LineWriter-Zwischenspeicher.
//! EN: Intentional confidential output without std `LineWriter` staging.

use std::{fs::File, io};

#[cfg(any(windows, test))]
#[path = "output_unicode.rs"]
mod unicode;

#[cfg(windows)]
#[path = "output_windows.rs"]
mod windows;

/// DE: Eigenes stdout-Handle; Windows-Konsole nutzt gesperrtes UTF-16-Workspace.
/// EN: Own stdout handle; Windows console uses a locked UTF-16 workspace.
/// # Errors
/// DE/EN: Handle-/Sperrfehler / handle or memory-lock errors.
#[cfg(unix)]
pub fn stdout() -> io::Result<impl io::Write> {
    use std::os::fd::AsFd;
    Ok(File::from(std::io::stdout().as_fd().try_clone_to_owned()?))
}

/// DE: Wie unter Unix; native Unicode-Konsole, UTF-8 in umgeleiteten Handles.
/// EN: As on Unix; native Unicode console, UTF-8 on redirected handles.
/// # Errors
/// DE/EN: Handle-/Sperrfehler / handle or memory-lock errors.
#[cfg(windows)]
pub fn stdout() -> io::Result<impl io::Write> {
    use std::os::windows::io::AsHandle;
    windows::Output::new(File::from(
        std::io::stdout().as_handle().try_clone_to_owned()?,
    ))
}
