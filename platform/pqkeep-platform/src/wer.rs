//! DE: WER-Flags erhalten und tatsächliche Heap-Minderung nachprüfen.
//! EN: Preserve WER flags and verify actual heap reporting mitigation.

use std::io;

pub(super) const NOHEAP: u32 = 1;

pub(super) fn ensure_noheap(
    mut read: impl FnMut() -> io::Result<u32>,
    mut set: impl FnMut(u32) -> io::Result<()>,
) -> io::Result<()> {
    let before = read()?;
    let desired = before | NOHEAP;
    if desired != before {
        set(desired)?;
    }
    if read()? & desired != desired {
        return Err(io::Error::other("WER mitigation not confirmed"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "wer_tests.rs"]
mod tests;
