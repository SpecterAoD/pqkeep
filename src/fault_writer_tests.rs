//! DE: Test-Schreiber um echte Dateien; keine Pufferinhalte im Fehlerzustand.
//! EN: Test writer around real files; no buffer contents in fault state.
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use crate::fault_io_tests::{self as fault, Action, Point, Shared};

pub(crate) struct OutputFile {
    file: File,
    state: Option<Shared>,
    written: usize,
}

impl OutputFile {
    pub(crate) fn new(file: File, path: &Path) -> Self {
        Self {
            file,
            state: fault::capture(path),
            written: 0,
        }
    }

    pub(crate) fn set_len(&self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }

    pub(crate) fn sync_all(&self) -> io::Result<()> {
        if let Some(state) = &self.state {
            fault::check_state(state, Point::BeforeFileSync)?;
        }
        self.file.sync_all()
    }

    fn allowance(&self, length: usize) -> io::Result<usize> {
        let Some(state) = &self.state else {
            return Ok(length);
        };
        let Some(action) = fault::action(state, Point::Write) else {
            return Ok(length);
        };
        if let Action::Partial { after, failure } = action {
            if self.written < after {
                return Ok(length.min(after - self.written));
            }
            fault::consume(state);
            return Err(failure.error());
        }
        if let Action::PauseAfter(after) = action {
            if self.written < after {
                return Ok(length.min(after - self.written));
            }
            fault::consume(state);
            crate::crash_driver_tests::pause()?;
            return Ok(length);
        }
        fault::consume(state);
        match action {
            Action::Fail(failure) => Err(failure.error()),
            Action::Short(max) => Ok(length.min(max)),
            Action::Interrupt => Err(io::ErrorKind::Interrupted.into()),
            Action::Zero => Ok(0),
            Action::Pause => {
                crate::crash_driver_tests::pause()?;
                Ok(length)
            }
            Action::Partial { .. } | Action::PauseAfter(_) | Action::Run(_) => unreachable!(),
        }
    }
}

impl Write for OutputFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return self.file.write(buf);
        }
        let allowed = self.allowance(buf.len())?;
        let written = self.file.write(&buf[..allowed])?;
        self.written += written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(state) = &self.state {
            fault::check_state(state, Point::BeforeFlush)?;
        }
        self.file.flush()
    }
}
