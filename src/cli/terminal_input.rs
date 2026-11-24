//! DE: Eingabe-Scratch vor erstem Read sperren. EN: Lock input scratch before reading.

use pqkeep::crypto::SecretBytes;
use std::io;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    Text { len: usize, repeat: u16 },
    Backspace(u16),
    Finish,
    Cancel,
    Ignore,
}

pub(super) struct Input {
    scratch: SecretBytes,
    #[cfg(windows)]
    record: SecretBytes,
    #[cfg(windows)]
    pending: SecretBytes,
}

impl Input {
    pub(super) fn new() -> pqkeep::Result<Self> {
        Ok(Self {
            scratch: SecretBytes::zeroed(4)?,
            #[cfg(windows)]
            record: SecretBytes::zeroed(pqkeep_platform::CONSOLE_INPUT_STORAGE)?,
            #[cfg(windows)]
            pending: SecretBytes::zeroed(4)?,
        })
    }

    pub(super) fn text(&self, len: usize) -> &[u8] {
        &self.scratch.expose()[..len]
    }

    pub(super) fn next(&mut self) -> io::Result<Action> {
        #[cfg(not(windows))]
        self.scratch.expose_mut().zeroize();
        #[cfg(target_os = "linux")]
        return super::terminal_input_linux::next(self.scratch.expose_mut());
        #[cfg(windows)]
        {
            use std::os::windows::io::AsHandle;
            self.windows(std::io::stdin().as_handle())
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            // DE: Bisherigen Provider auf anderen Plattformen erhalten; dort weiter OPEN.
            // EN: Preserve the existing provider elsewhere; its scratch remains OPEN.
            use dialoguer::console::{Key, Term};
            Ok(match Term::stderr().read_key_raw()? {
                Key::Enter => Action::Finish,
                Key::Escape | Key::CtrlC => Action::Cancel,
                Key::Backspace => Action::Backspace(1),
                Key::Char(ch) if !ch.is_control() => Action::Text {
                    len: ch.encode_utf8(self.scratch.expose_mut()).len(),
                    repeat: 1,
                },
                _ => Action::Ignore,
            })
        }
    }
    #[cfg(windows)]
    pub(super) fn windows(
        &mut self,
        handle: std::os::windows::io::BorrowedHandle<'_>,
    ) -> io::Result<Action> {
        use pqkeep_platform::ConsoleInputEvent as Event;
        self.scratch.expose_mut().zeroize();
        Ok(
            match pqkeep_platform::read_console_input(
                handle,
                self.record.expose_mut(),
                self.pending.expose_mut(),
                self.scratch.expose_mut(),
            )? {
                Event::Text { len, repeat } => Action::Text { len, repeat },
                Event::Backspace(repeat) => Action::Backspace(repeat),
                Event::Finish => Action::Finish,
                Event::Cancel => Action::Cancel,
                Event::Ignore => Action::Ignore,
            },
        )
    }
}

#[cfg(test)]
#[path = "terminal_input_tests.rs"]
mod tests;
