//! DE: Unter Linux verdeckten Raw-Modus für eine ganze Eingabe halten.
//! EN: Hold hidden raw mode across an entire Linux input operation.

use rustix::termios::{OptionalActions, Termios, tcgetattr, tcsetattr};

pub(super) struct Mode {
    original: Option<Termios>,
}

impl Mode {
    pub(super) fn new() -> std::io::Result<Self> {
        let input = std::io::stdin();
        let original = tcgetattr(&input)?;
        let mut raw = original.clone();
        raw.make_raw();
        raw.output_modes = original.output_modes;
        tcsetattr(&input, OptionalActions::Now, &raw)?;
        Ok(Self {
            original: Some(original),
        })
    }

    pub(super) fn restore(mut self) -> std::io::Result<()> {
        if let Some(original) = &self.original {
            tcsetattr(std::io::stdin(), OptionalActions::Now, original)?;
            self.original = None;
        }
        Ok(())
    }
}

impl Drop for Mode {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            // DE: Nur Panic-/Fehler-Sicherung; normale Rückwege prüfen restore explizit.
            // EN: Panic/error cleanup only; normal return paths explicitly check restore.
            let _ = tcsetattr(std::io::stdin(), OptionalActions::Now, original);
        }
    }
}
