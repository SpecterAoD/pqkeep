//! DE: WER-Flags erhalten und tatsächliche Heap-Minderung nachprüfen.
//! EN: Preserve WER flags and verify actual heap reporting mitigation.

#[cfg(any(windows, test))]
use std::io;

/// DE: Abwesende Prozesskonfiguration ist kein erfundener Null-Flagsatz.
/// EN: Absent process configuration is distinct from an invented zero flag set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WerFlags {
    /// DE: WER meldet ausdrücklich kein Element. EN: WER explicitly reports no element.
    Absent,
    /// DE: Erfolgreich gelesene tatsächliche Flags. EN: Successfully read actual flags.
    Present(u32),
}

#[cfg(any(windows, test))]
pub(super) const NOHEAP: u32 = 1;

#[cfg(any(windows, test))]
pub(super) fn ensure_noheap(
    mut read: impl FnMut() -> io::Result<WerFlags>,
    mut set: impl FnMut(u32) -> io::Result<()>,
) -> io::Result<()> {
    let before = read()?;
    let desired = match before {
        WerFlags::Absent => NOHEAP,
        WerFlags::Present(flags) => flags | NOHEAP,
    };
    if before != WerFlags::Present(desired) {
        set(desired)?;
    }
    if !matches!(read()?, WerFlags::Present(flags) if flags & desired == desired) {
        return Err(io::Error::other("WER mitigation not confirmed"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "wer_tests.rs"]
mod tests;
