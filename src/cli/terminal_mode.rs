//! DE: Raw-Modus über Bestätigung/Retry halten. EN: Hold raw mode through confirmation/retry.

use rustix::termios::{OptionalActions, SpecialCodeIndex, Termios, tcgetattr, tcsetattr};

pub(super) struct Mode {
    original: Option<Termios>,
}

fn set(actions: OptionalActions, expected: &Termios) -> std::io::Result<()> {
    tcsetattr(std::io::stdin(), actions, expected)?;
    let actual = tcgetattr(std::io::stdin())?;
    // DE: Sicherheitsrelevante Flags/Read-Timing vor Prompt und nach Restore nachprüfen.
    // EN: Verify security-relevant flags/read timing before prompt and after restore.
    if actual.input_modes != expected.input_modes
        || actual.local_modes != expected.local_modes
        || actual.control_modes != expected.control_modes
        || actual.output_modes != expected.output_modes
        || actual.special_codes[SpecialCodeIndex::VMIN]
            != expected.special_codes[SpecialCodeIndex::VMIN]
        || actual.special_codes[SpecialCodeIndex::VTIME]
            != expected.special_codes[SpecialCodeIndex::VTIME]
    {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

impl Mode {
    pub(super) fn new() -> std::io::Result<Self> {
        let original = tcgetattr(std::io::stdin())?;
        let mut raw = original.clone();
        raw.make_raw();
        raw.output_modes = original.output_modes;
        let guard = Self {
            original: Some(original),
        };
        set(OptionalActions::Now, &raw)?;
        Ok(guard)
    }

    pub(super) fn restore(mut self, discard: bool) -> std::io::Result<()> {
        if let Some(original) = &self.original {
            let actions = if discard {
                OptionalActions::Flush
            } else {
                OptionalActions::Now
            };
            set(actions, original)?;
            self.original = None;
        }
        Ok(())
    }
}

impl Drop for Mode {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            // DE: Nur Fehler-/Unwind-Sicherung; wartende private Reste vor Echo verwerfen.
            // EN: Error/unwind cleanup only; discard queued private suffix before echo.
            let _ = set(OptionalActions::Flush, original);
        }
    }
}
