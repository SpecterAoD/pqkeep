//! DE: UTF-8 stückweise ohne ungesperrte Transcodierung zur nativen Konsole.
//! EN: Incremental UTF-8 to native console without unlocked transcoding.

use crate::crypto::{SecretBytes, secret_buffer::SecretBuffer};
use std::{
    fs::File,
    io::{self, IsTerminal, Write},
    os::windows::io::AsHandle,
};
use zeroize::Zeroize;

pub(super) struct Output {
    file: File,
    workspace: Option<SecretBuffer<u16>>,
    pending: SecretBytes,
    used: usize,
}

impl Output {
    pub(super) fn new(file: File) -> io::Result<Self> {
        let console = file.is_terminal();
        let workspace = console
            .then(|| SecretBuffer::new(vec![0u16; 1024]))
            .transpose()
            .map_err(io::Error::other)?;
        let pending = SecretBytes::zeroed(if console { 4 } else { 0 }).map_err(io::Error::other)?;
        Ok(Self {
            file,
            workspace,
            pending,
            used: 0,
        })
    }

    fn complete_pending(&mut self, input: &mut &[u8]) -> io::Result<bool> {
        let first = self.pending.expose()[0];
        let needed = if first < 0xe0 {
            2
        } else if first < 0xf0 {
            3
        } else {
            4
        };
        let count = (needed - self.used).min(input.len());
        self.pending.expose_mut()[self.used..self.used + count].copy_from_slice(&input[..count]);
        self.used += count;
        *input = &input[count..];
        if self.used < needed {
            return Ok(false);
        }
        let result = (|| {
            let text =
                std::str::from_utf8(&self.pending.expose()[..needed]).map_err(|_| invalid())?;
            let workspace = self.workspace.as_mut().ok_or_else(invalid)?;
            write_text(&self.file, workspace.expose_mut(), text)
        })();
        self.pending.expose_mut().zeroize();
        self.used = 0;
        result.map(|()| true)
    }
}

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

fn write_text(file: &File, words: &mut [u16], text: &str) -> io::Result<()> {
    super::unicode::write_text(words, text, |part| {
        pqkeep_platform::write_console(file.as_handle(), part)
    })
}

impl Write for Output {
    fn write(&mut self, mut input: &[u8]) -> io::Result<usize> {
        if self.workspace.is_none() {
            return self.file.write(input);
        }
        let total = input.len();
        if self.used > 0 && !self.complete_pending(&mut input)? {
            return Ok(total);
        }
        let workspace = self.workspace.as_mut().ok_or_else(invalid)?;
        match std::str::from_utf8(input) {
            Ok(text) => write_text(&self.file, workspace.expose_mut(), text)?,
            Err(error) if error.error_len().is_none() => {
                let valid = error.valid_up_to();
                let text = std::str::from_utf8(&input[..valid]).map_err(|_| invalid())?;
                write_text(&self.file, workspace.expose_mut(), text)?;
                self.used = input.len() - valid;
                self.pending.expose_mut()[..self.used].copy_from_slice(&input[valid..]);
            }
            Err(_) => return Err(invalid()),
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.used > 0 {
            return Err(invalid());
        }
        self.file.flush()
    }
}
